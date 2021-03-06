/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package consent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/go-resty/resty"
	"github.com/gorilla/sessions"
	"github.com/machinebox/graphql"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/go-convenience/mapx"
	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/go-convenience/stringsx"
	"github.com/ory/go-convenience/urlx"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	cookieAuthenticationName    = "oauth2_authentication_session"
	cookieAuthenticationSIDName = "sid"

	cookieAuthenticationCSRFName = "oauth2_authentication_csrf"
	cookieConsentCSRFName        = "oauth2_consent_csrf"
)

type DefaultStrategy struct {
	AuthenticationURL             string
	ConsentURL                    string
	DisableUserConsent            bool
	IssuerURL                     string
	OAuth2AuthURL                 string
	M                             Manager
	CookieStore                   sessions.Store
	ScopeStrategy                 fosite.ScopeStrategy
	RunsHTTPS                     bool
	RequestMaxAge                 time.Duration
	JWTStrategy                   jwt.JWTStrategy
	OpenIDConnectRequestValidator *openid.OpenIDConnectRequestValidator
	SubjectIdentifierAlgorithm    map[string]SubjectIdentifierAlgorithm
}

func NewStrategy(
	authenticationURL string,
	consentURL string,
	disableUserConsent bool,
	issuerURL string,
	oAuth2AuthURL string,
	m Manager,
	cookieStore sessions.Store,
	scopeStrategy fosite.ScopeStrategy,
	runsHTTPS bool,
	requestMaxAge time.Duration,
	jwtStrategy jwt.JWTStrategy,
	openIDConnectRequestValidator *openid.OpenIDConnectRequestValidator,
	subjectIdentifierAlgorithm map[string]SubjectIdentifierAlgorithm,
) *DefaultStrategy {
	return &DefaultStrategy{
		AuthenticationURL:             authenticationURL,
		ConsentURL:                    consentURL,
		DisableUserConsent:            disableUserConsent,
		IssuerURL:                     issuerURL,
		OAuth2AuthURL:                 oAuth2AuthURL,
		M:                             m,
		CookieStore:                   cookieStore,
		ScopeStrategy:                 scopeStrategy,
		RunsHTTPS:                     runsHTTPS,
		RequestMaxAge:                 requestMaxAge,
		JWTStrategy:                   jwtStrategy,
		OpenIDConnectRequestValidator: openIDConnectRequestValidator,
		SubjectIdentifierAlgorithm:    subjectIdentifierAlgorithm,
	}
}

var ErrAbortOAuth2Request = errors.New("The OAuth 2.0 Authorization request must be aborted")
var ErrNoPreviousConsentFound = errors.New("No previous OAuth 2.0 Consent could be found for this access request")

func (s *DefaultStrategy) requestAuthentication(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester) error {
	prompt := stringsx.Splitx(ar.GetRequestForm().Get("prompt"), " ")
	if stringslice.Has(prompt, "login") {
		return s.forwardAuthenticationRequest(w, r, ar, "", time.Time{}, nil)
	}

	// We try to open the session cookie. If it does not exist (indicated by the error), we must authenticate the user.
	cookie, err := s.CookieStore.Get(r, cookieAuthenticationName)
	if err != nil {
		//id.L.WithError(err).Debug("No OAuth2 authentication session was found, performing consent authentication flow")
		return s.forwardAuthenticationRequest(w, r, ar, "", time.Time{}, nil)
	}

	sessionID := mapx.GetStringDefault(cookie.Values, cookieAuthenticationSIDName, "")
	if sessionID == "" {
		return s.forwardAuthenticationRequest(w, r, ar, "", time.Time{}, nil)
	}

	session, err := s.M.GetAuthenticationSession(r.Context(), sessionID)
	if errors.Cause(err) == pkg.ErrNotFound {
		return s.forwardAuthenticationRequest(w, r, ar, "", time.Time{}, nil)
	} else if err != nil {
		return err
	}

	maxAge := int64(0)
	if ma := ar.GetRequestForm().Get("max_age"); len(ma) > 0 {
		var err error
		maxAge, err = strconv.ParseInt(ma, 10, 64)
		if err != nil {
			return err
		}
	}

	if maxAge > 0 && session.AuthenticatedAt.UTC().Add(time.Second*time.Duration(maxAge)).Before(time.Now().UTC()) {
		if stringslice.Has(prompt, "none") {
			return errors.WithStack(fosite.ErrLoginRequired.WithDebug("Request failed because prompt is set to \"none\" and authentication time reached max_age"))
		}
		return s.forwardAuthenticationRequest(w, r, ar, "", time.Time{}, nil)
	}

	idTokenHint := ar.GetRequestForm().Get("id_token_hint")
	if idTokenHint == "" {
		return s.forwardAuthenticationRequest(w, r, ar, session.Subject, session.AuthenticatedAt, session)
	}

	token, err := s.JWTStrategy.Decode(r.Context(), idTokenHint)
	if ve, ok := errors.Cause(err).(*jwtgo.ValidationError); err == nil || (ok && ve.Errors == jwtgo.ValidationErrorExpired) {
	} else {
		return err
	}

	var hintSub, obfuscatedUserID, forcedObfuscatedUserID string
	if hintClaims, ok := token.Claims.(jwtgo.MapClaims); !ok {
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Failed to validate OpenID Connect request as decoding id token from id_token_hint to *jwt.StandardClaims failed"))
	} else if hintSub, _ := hintClaims["sub"].(string); hintSub == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Failed to validate OpenID Connect request because provided id token from id_token_hint does not have a subject"))
	} else if obfuscatedUserID, err = s.obfuscateSubjectIdentifier(session.Subject, ar, ""); err != nil {
		return err
	}

	if s, err := s.M.GetForcedObfuscatedAuthenticationSession(r.Context(), ar.GetClient().GetID(), hintSub); errors.Cause(err) == pkg.ErrNotFound {
		// do nothing
	} else if err != nil {
		return err
	} else {
		forcedObfuscatedUserID = s.SubjectObfuscated
	}

	if hintSub != session.Subject && hintSub != obfuscatedUserID && hintSub != forcedObfuscatedUserID {
		return errors.WithStack(fosite.ErrLoginRequired.WithDebug("Request failed because subject claim from id_token_hint does not match subject from authentication session"))
	} else {
		return s.forwardAuthenticationRequest(w, r, ar, session.Subject, session.AuthenticatedAt, session)
	}
}

func (s *DefaultStrategy) forwardAuthenticationRequest(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, subject string, authenticatedAt time.Time, session *AuthenticationSession) error {
	if (subject != "" && authenticatedAt.IsZero()) || (subject == "" && !authenticatedAt.IsZero()) {
		return errors.WithStack(fosite.ErrServerError.WithDebug("Consent strategy returned a non-empty subject with an empty auth date, or an empty subject with a non-empty auth date"))
	}

	skip := false
	if subject != "" {
		skip = true
	}

	// Let'id validate that prompt is actually not "none" if we can't skip authentication
	prompt := stringsx.Splitx(ar.GetRequestForm().Get("prompt"), " ")
	if stringslice.Has(prompt, "none") && !skip {
		return errors.WithStack(fosite.ErrLoginRequired.WithDebug(`Prompt "none" was requested, but no existing login session was found`))
	}

	// Set up csrf/challenge/verifier values
	verifier := strings.Replace(uuid.New(), "-", "", -1)
	challenge := strings.Replace(uuid.New(), "-", "", -1)
	csrf := strings.Replace(uuid.New(), "-", "", -1)

	// Generate the request URL
	iu, err := url.Parse(s.IssuerURL)
	if err != nil {
		return errors.WithStack(err)
	}
	iu = urlx.AppendPaths(iu, s.OAuth2AuthURL)
	iu.RawQuery = r.URL.RawQuery

	var idTokenHintClaims jwtgo.MapClaims
	if idTokenHint := ar.GetRequestForm().Get("id_token_hint"); len(idTokenHint) > 0 {
		token, err := s.JWTStrategy.Decode(r.Context(), idTokenHint)
		if ve, ok := errors.Cause(err).(*jwtgo.ValidationError); err == nil || (ok && ve.Errors == jwtgo.ValidationErrorExpired) {
			if hintClaims, ok := token.Claims.(jwtgo.MapClaims); ok {
				idTokenHintClaims = hintClaims
			}
		}
	}

	sessionID := ""
	if session != nil {
		sessionID = session.ID
	}

	// Set the session
	if err := s.M.CreateAuthenticationRequest(
		r.Context(),
		&AuthenticationRequest{
			Challenge:       challenge,
			Verifier:        verifier,
			CSRF:            csrf,
			Skip:            skip,
			RequestedScope:  []string(ar.GetRequestedScopes()),
			Subject:         subject,
			Client:          sanitizeClientFromRequest(ar),
			RequestURL:      iu.String(),
			AuthenticatedAt: authenticatedAt,
			RequestedAt:     time.Now().UTC(),
			SessionID:       sessionID,
			OpenIDConnectContext: &OpenIDConnectContext{
				IDTokenHintClaims: idTokenHintClaims,
				ACRValues:         stringsx.Splitx(ar.GetRequestForm().Get("acr_values"), " "),
				UILocales:         stringsx.Splitx(ar.GetRequestForm().Get("ui_locales"), " "),
				Display:           ar.GetRequestForm().Get("display"),
				LoginHint:         ar.GetRequestForm().Get("login_hint"),
			},
		},
	); err != nil {
		return errors.WithStack(err)
	}

	if err := createCsrfSession(w, r, s.CookieStore, cookieAuthenticationCSRFName, csrf, s.RunsHTTPS); err != nil {
		return errors.WithStack(err)
	}

	au, err := url.Parse(s.AuthenticationURL)
	if err != nil {
		return errors.WithStack(err)
	}

	q := au.Query()
	q.Set("login_challenge", challenge)
	au.RawQuery = q.Encode()

	http.Redirect(w, r, au.String(), http.StatusFound)

	// generate the verifier
	return errors.WithStack(ErrAbortOAuth2Request)
}

func (s *DefaultStrategy) revokeAuthenticationSession(w http.ResponseWriter, r *http.Request) error {
	sid, err := revokeAuthenticationCookie(w, r, s.CookieStore)
	if err != nil {
		return err
	}

	if sid == "" {
		return nil
	}

	return s.M.DeleteAuthenticationSession(r.Context(), sid)
}

func revokeAuthenticationCookie(w http.ResponseWriter, r *http.Request, s sessions.Store) (string, error) {
	cookie, _ := s.Get(r, cookieAuthenticationName)
	sid, _ := mapx.GetString(cookie.Values, cookieAuthenticationSIDName)

	cookie.Options.MaxAge = -1
	cookie.Values[cookieAuthenticationSIDName] = ""

	if err := cookie.Save(r, w); err != nil {
		return "", errors.WithStack(err)
	}

	return sid, nil
}

func (s *DefaultStrategy) obfuscateSubjectIdentifier(subject string, req fosite.AuthorizeRequester, forcedIdentifier string) (string, error) {
	if c, ok := req.GetClient().(*client.Client); ok && c.SubjectType == "pairwise" {
		algorithm, ok := s.SubjectIdentifierAlgorithm[c.SubjectType]
		if !ok {
			return "", errors.WithStack(fosite.ErrInvalidRequest.WithHint(fmt.Sprintf(`Subject Identifier Algorithm "%s" was requested by OAuth 2.0 Client "%s", but is not configured.`, c.SubjectType, c.ClientID)))
		}

		if len(forcedIdentifier) > 0 {
			return forcedIdentifier, nil
		}

		return algorithm.Obfuscate(subject, c)
	} else if !ok {
		return "", errors.New("Unable to type assert OAuth 2.0 Client to *client.Client")
	}
	return subject, nil
}

func (s *DefaultStrategy) verifyAuthentication(w http.ResponseWriter, r *http.Request, req fosite.AuthorizeRequester, verifier string) (*HandledAuthenticationRequest, error) {
	ctx := r.Context()
	session, err := s.M.VerifyAndInvalidateAuthenticationRequest(ctx, verifier)
	if errors.Cause(err) == pkg.ErrNotFound {
		return nil, errors.WithStack(fosite.ErrAccessDenied.WithDebug("The login verifier has already been used, has not been granted, or is invalid."))
	} else if err != nil {
		return nil, err
	}

	if session.Error != nil {
		return nil, errors.WithStack(session.Error.toRFCError())
	}

	if session.RequestedAt.Add(s.RequestMaxAge).Before(time.Now()) {
		return nil, errors.WithStack(fosite.ErrRequestUnauthorized.WithDebug("The login request has expired, please try again."))
	}

	if err := validateCsrfSession(r, s.CookieStore, cookieAuthenticationCSRFName, session.AuthenticationRequest.CSRF); err != nil {
		return nil, err
	}

	if session.AuthenticationRequest.Skip && session.Remember {
		return nil, errors.WithStack(fosite.ErrServerError.WithDebug("The login request is marked as remember, but is also marked as skipped - only one of the values can be true."))
	}

	if session.AuthenticationRequest.Skip && session.Subject != session.AuthenticationRequest.Subject {
		// Revoke the session because there's clearly a mix up wrt the subject that's being authenticated
		if err := s.revokeAuthenticationSession(w, r); err != nil {
			return nil, err
		}

		return nil, errors.WithStack(fosite.ErrServerError.WithDebug("The login request is marked as remember, but the subject from the login confirmation does not match the original subject from the cookie."))
	}

	subjectIdentifier, err := s.obfuscateSubjectIdentifier(session.Subject, req, session.ForceSubjectIdentifier)
	if err != nil {
		return nil, err
	}

	if err := s.OpenIDConnectRequestValidator.ValidatePrompt(ctx, &fosite.AuthorizeRequest{
		ResponseTypes: req.GetResponseTypes(),
		RedirectURI:   req.GetRedirectURI(),
		State:         req.GetState(),
		//HandledResponseTypes, this can be safely ignored because it's not being used by validation
		Request: fosite.Request{
			ID:            req.GetID(),
			RequestedAt:   req.GetRequestedAt(),
			Client:        req.GetClient(),
			Scopes:        req.GetRequestedScopes(),
			GrantedScopes: req.GetGrantedScopes(),
			Form:          req.GetRequestForm(),
			Session: &openid.DefaultSession{
				Claims: &jwt.IDTokenClaims{
					Subject:     subjectIdentifier,
					IssuedAt:    time.Now().UTC(),                // doesn't matter
					ExpiresAt:   time.Now().Add(time.Hour).UTC(), // doesn't matter
					AuthTime:    session.AuthenticatedAt,
					RequestedAt: session.RequestedAt,
				},
				Headers: &jwt.Headers{},
				Subject: session.Subject,
			},
		},
	}); errors.Cause(err) == fosite.ErrLoginRequired {
		// This indicates that something went wrong with checking the subject id - let's destroy the session to be safe
		if err := s.revokeAuthenticationSession(w, r); err != nil {
			return nil, err
		}

		return nil, err
	} else if err != nil {
		return nil, err
	}

	if session.ForceSubjectIdentifier != "" {
		if err := s.M.CreateForcedObfuscatedAuthenticationSession(r.Context(), &ForcedObfuscatedAuthenticationSession{
			Subject:           session.Subject,
			ClientID:          req.GetClient().GetID(),
			SubjectObfuscated: session.ForceSubjectIdentifier,
		}); err != nil {
			return nil, err
		}
	}

	if !session.Remember {
		if !session.AuthenticationRequest.Skip {
			// If the session should not be remembered (and we're actually not skipping), than the user clearly don't
			// wants us to store a cookie. So let's bust the authentication session (if one exists).
			if err := s.revokeAuthenticationSession(w, r); err != nil {
				return nil, err
			}
		}

		return session, nil
	}

	cookie, _ := s.CookieStore.Get(r, cookieAuthenticationName)
	sid := uuid.New()

	if err := s.M.CreateAuthenticationSession(r.Context(), &AuthenticationSession{
		ID:              sid,
		Subject:         session.Subject,
		AuthenticatedAt: session.AuthenticatedAt,
	}); err != nil {
		return nil, err
	}

	cookie.Values[cookieAuthenticationSIDName] = sid
	if session.RememberFor >= 0 {
		cookie.Options.MaxAge = session.RememberFor
	}
	cookie.Options.HttpOnly = true

	if s.RunsHTTPS {
		cookie.Options.Secure = true
	}

	if err := cookie.Save(r, w); err != nil {
		return nil, errors.WithStack(err)
	}
	return session, nil
}

func (s *DefaultStrategy) requestConsent(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, authenticationSession *HandledAuthenticationRequest) error {
	prompt := stringsx.Splitx(ar.GetRequestForm().Get("prompt"), " ")
	if stringslice.Has(prompt, "consent") {
		return s.forwardConsentRequest(w, r, ar, authenticationSession, nil)
	}

	// https://tools.ietf.org/html/rfc6749
	//
	// As stated in Section 10.2 of OAuth 2.0 [RFC6749], the authorization
	// server SHOULD NOT process authorization requests automatically
	// without user consent or interaction, except when the identity of the
	// client can be assured.  This includes the case where the user has
	// previously approved an authorization request for a given client id --
	// unless the identity of the client can be proven, the request SHOULD
	// be processed as if no previous request had been approved.
	//
	// Measures such as claimed "https" scheme redirects MAY be accepted by
	// authorization servers as identity proof.  Some operating systems may
	// offer alternative platform-specific identity features that MAY be
	// accepted, as appropriate.
	if ar.GetClient().IsPublic() {
		// The OpenID Connect Test Tool fails if this returns `consent_required` when `prompt=none` is used.
		// According to the quote above, it should be ok to allow https to skip consent.
		//
		// This is tracked as issue: https://github.com/ory/hydra/issues/866
		// This is also tracked as upstream issue: https://github.com/openid-certification/oidctest/issues/97
		if ar.GetRedirectURI().Scheme != "https" {
			return s.forwardConsentRequest(w, r, ar, authenticationSession, nil)
		}
	}

	// This breaks OIDC Conformity Tests and is probably a bit paranoid.
	//
	// if ar.GetResponseTypes().Has("token") {
	//	 // We're probably requesting the implicit or hybrid flow in which case we MUST authenticate and authorize the request
	// 	 return s.forwardConsentRequest(w, r, ar, authenticationSession, nil)
	// }

	consentSessions, err := s.M.FindPreviouslyGrantedConsentRequests(r.Context(), ar.GetClient().GetID(), authenticationSession.Subject)
	if errors.Cause(err) == ErrNoPreviousConsentFound {
		return s.forwardConsentRequest(w, r, ar, authenticationSession, nil)
	} else if err != nil {
		return err
	}

	if found := matchScopes(s.ScopeStrategy, consentSessions, ar.GetRequestedScopes()); found != nil {
		return s.forwardConsentRequest(w, r, ar, authenticationSession, found)
	}

	return s.forwardConsentRequest(w, r, ar, authenticationSession, nil)
}

func (s *DefaultStrategy) forwardConsentRequest(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, as *HandledAuthenticationRequest, cs *HandledConsentRequest) error {
	skip := false
	if cs != nil {
		skip = true
	}

	prompt := stringsx.Splitx(ar.GetRequestForm().Get("prompt"), " ")
	if stringslice.Has(prompt, "none") && !skip {
		return errors.WithStack(fosite.ErrConsentRequired.WithDebug(`Prompt "none" was requested, but no previous consent was found`))
	}

	// Set up csrf/challenge/verifier values
	verifier := strings.Replace(uuid.New(), "-", "", -1)
	challenge := strings.Replace(uuid.New(), "-", "", -1)
	csrf := strings.Replace(uuid.New(), "-", "", -1)

	if err := s.M.CreateConsentRequest(
		r.Context(),
		&ConsentRequest{
			Challenge:              challenge,
			Verifier:               verifier,
			CSRF:                   csrf,
			Skip:                   skip,
			RequestedScope:         []string(ar.GetRequestedScopes()),
			Subject:                as.Subject,
			Client:                 sanitizeClientFromRequest(ar),
			RequestURL:             as.AuthenticationRequest.RequestURL,
			AuthenticatedAt:        as.AuthenticatedAt,
			RequestedAt:            as.RequestedAt,
			ForceSubjectIdentifier: as.ForceSubjectIdentifier,
			OpenIDConnectContext:   as.AuthenticationRequest.OpenIDConnectContext,
			LoginSessionID:         as.AuthenticationRequest.SessionID,
			LoginChallenge:         as.AuthenticationRequest.Challenge,
		},
	); err != nil {
		return errors.WithStack(err)
	}

	cu, err := url.Parse(s.ConsentURL)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := createCsrfSession(w, r, s.CookieStore, cookieConsentCSRFName, csrf, s.RunsHTTPS); err != nil {
		return errors.WithStack(err)
	}

	q := cu.Query()
	q.Set("consent_challenge", challenge)
	cu.RawQuery = q.Encode()

	http.Redirect(w, r, cu.String(), http.StatusFound)

	// generate the verifier
	return errors.WithStack(ErrAbortOAuth2Request)
}

func (s *DefaultStrategy) verifyConsent(w http.ResponseWriter, r *http.Request, req fosite.AuthorizeRequester, verifier string) (*HandledConsentRequest, error) {
	session, err := s.M.VerifyAndInvalidateConsentRequest(r.Context(), verifier)
	if errors.Cause(err) == pkg.ErrNotFound {
		return nil, errors.WithStack(fosite.ErrAccessDenied.WithDebug("The consent verifier has already been used, has not been granted, or is invalid."))
	} else if err != nil {
		return nil, err
	}

	if session.RequestedAt.Add(s.RequestMaxAge).Before(time.Now()) {
		return nil, errors.WithStack(fosite.ErrRequestUnauthorized.WithDebug("The consent request has expired, please try again."))
	}

	if session.Error != nil {
		return nil, errors.WithStack(session.Error.toRFCError())
	}

	if session.ConsentRequest.AuthenticatedAt.IsZero() {
		return nil, errors.WithStack(fosite.ErrServerError.WithDebug("The authenticatedAt value was not set."))
	}

	if !s.DisableUserConsent {
		if err := validateCsrfSession(r, s.CookieStore, cookieConsentCSRFName, session.ConsentRequest.CSRF); err != nil {
			return nil, err
		}
	}

	pw, err := s.obfuscateSubjectIdentifier(session.ConsentRequest.Subject, req, session.ConsentRequest.ForceSubjectIdentifier)
	if err != nil {
		return nil, err
	}

	if session.Session == nil {
		session.Session = newConsentRequestSessionData()
	}

	if session.Session.AccessToken == nil {
		session.Session.AccessToken = map[string]interface{}{}
	}

	if session.Session.IDToken == nil {
		session.Session.IDToken = map[string]interface{}{}
	}

	if s.DisableUserConsent {
		id, err := s.getIdBySubject(session.ConsentRequest.Subject)
		if err != nil {
			return nil, err
		}
		if id != "" {
			session.Session.IDToken["sub"] = id
			session.Session.IDToken["urn:104:v3:entity:pid"] = id
			list, err := s.getCompanyList(id)
			if err != nil {
				return nil, err
			}
			if len(list) == 0 || len(list) > 1 {
				session.Session.IDToken["urn:104:v3:entity:company_id"] = ""
				if len(list) == 0 {
					session.Session.IDToken["urn:104:v3:entity:company_list"] = []string{}
				} else {
					session.Session.IDToken["urn:104:v3:entity:company_list"] = list
				}
			} else {
				session.Session.IDToken["urn:104:v3:entity:company_id"] = list[0]
				session.Session.IDToken["urn:104:v3:entity:company_list"] = list
			}
		}
		session.Session.IDToken["azp"] = req.GetClient().GetID()
	}

	session.ConsentRequest.SubjectIdentifier = pw
	session.AuthenticatedAt = session.ConsentRequest.AuthenticatedAt
	return session, nil
}

func (s *DefaultStrategy) HandleOAuth2AuthorizationRequest(w http.ResponseWriter, r *http.Request, req fosite.AuthorizeRequester) (*HandledConsentRequest, error) {
	authenticationVerifier := strings.TrimSpace(req.GetRequestForm().Get("login_verifier"))
	consentVerifier := strings.TrimSpace(req.GetRequestForm().Get("consent_verifier"))
	if authenticationVerifier == "" && consentVerifier == "" {
		// ok, we need to process this request and redirect to auth endpoint
		return nil, s.requestAuthentication(w, r, req)
	} else if authenticationVerifier != "" {
		authSession, err := s.verifyAuthentication(w, r, req, authenticationVerifier)
		if err != nil {
			return nil, err
		}

		if s.DisableUserConsent {
			// 建立 consent request
			challenge, verifier, err := s.createConsentRequest(w, r, req, authSession)
			if err != nil {
				return nil, err
			}

			// 不 redirect 出去，直接處理掉
			err = s.handleConsentRequest(w, r, req, challenge)
			if err != nil {
				return nil, err
			}

			// 重設原本預計從 query string 拿取的 consent_verifier
			consentVerifier = verifier
		} else {
			// ok, we need to process this request and redirect to auth endpoint
			return nil, s.requestConsent(w, r, req, authSession)
		}
	}

	consentSession, err := s.verifyConsent(w, r, req, consentVerifier)
	if err != nil {
		return nil, err
	}

	return consentSession, nil
}

func (s *DefaultStrategy) createConsentRequest(w http.ResponseWriter, r *http.Request, req fosite.AuthorizeRequester, authSession *HandledAuthenticationRequest) (challenge string, verifier string, err error) {

	prompt := stringsx.Splitx(req.GetRequestForm().Get("prompt"), " ")
	if stringslice.Has(prompt, "consent") {
		return "", "", errors.WithStack(fosite.ErrConsentRequired.WithDebug(`Prompt "consent" was not supported`))
	}

	consentSessions, err := s.M.FindPreviouslyGrantedConsentRequests(r.Context(), req.GetClient().GetID(), authSession.Subject)
	if err != nil && errors.Cause(err) != ErrNoPreviousConsentFound {
		return "", "", err
	}

	skip := false
	found := matchScopes(s.ScopeStrategy, consentSessions, req.GetRequestedScopes())
	if found != nil {
		skip = true
	}

	if stringslice.Has(prompt, "none") && !skip {
		return "", "", errors.WithStack(fosite.ErrConsentRequired.WithDebug(`Prompt "none" was requested, but no previous consent was found`))
	}

	// Set up csrf/challenge/verifier values
	v := strings.Replace(uuid.New(), "-", "", -1)
	c := strings.Replace(uuid.New(), "-", "", -1)
	csrf := strings.Replace(uuid.New(), "-", "", -1)

	if err := s.M.CreateConsentRequest(
		r.Context(),
		&ConsentRequest{
			Challenge:              c,
			Verifier:               v,
			CSRF:                   csrf,
			Skip:                   false,
			RequestedScope:         []string(req.GetRequestedScopes()),
			Subject:                authSession.Subject,
			Client:                 sanitizeClientFromRequest(req),
			RequestURL:             authSession.AuthenticationRequest.RequestURL,
			AuthenticatedAt:        authSession.AuthenticatedAt,
			RequestedAt:            authSession.RequestedAt,
			ForceSubjectIdentifier: authSession.ForceSubjectIdentifier,
			OpenIDConnectContext:   authSession.AuthenticationRequest.OpenIDConnectContext,
			LoginSessionID:         authSession.AuthenticationRequest.SessionID,
			LoginChallenge:         authSession.AuthenticationRequest.Challenge,
		},
	); err != nil {
		return "", "", err
	}

	return c, v, nil
}

func (s *DefaultStrategy) handleConsentRequest(w http.ResponseWriter, r *http.Request, req fosite.AuthorizeRequester, challenge string) (err error) {
	var p HandledConsentRequest

	cr, err := s.M.GetConsentRequest(r.Context(), challenge)
	if err != nil {
		return err
	}

	p.Challenge = challenge
	p.RequestedAt = cr.RequestedAt
	p.GrantedScope = []string(req.GetRequestedScopes())

	hr, err := s.M.HandleConsentRequest(r.Context(), challenge, &p)
	if err != nil {
		return err
	} else if hr.Skip && p.Remember {
		return err
	}

	return nil
}

func (s *DefaultStrategy) getIdBySubject(subject string) (string, error) {

	apiBaseUrl := viper.GetString("CORP_INTERNAL_API_URL")
	if apiBaseUrl == "" {
		return "", errors.WithStack(errors.New("No corp internal api url"))
	}

	resp, err := resty.R().Get(apiBaseUrl + "/ac/getIdByMail/" + base64.URLEncoding.EncodeToString([]byte(subject)))
	if err != nil {
		return "", err
	}

	responseMap := make(map[string]interface{})
	if err := json.Unmarshal(resp.Body(), &responseMap); err != nil {
		return "", err
	}

	if responseMap["error"].(string) == "" {
		dataMap := responseMap["data"].(map[string]interface{})
		if dataMap["id"].(string) != "" {
			return dataMap["id"].(string), nil
		}
	}

	return "", errors.New(responseMap["error"].(string))
}

func (s *DefaultStrategy) getCompanyList(id string) ([]string, error) {

	apiUrl := viper.GetString("GRAPHQL_API_URL")
	if apiUrl == "" {
		return []string{""}, errors.WithStack(errors.New("No graphql api url"))
	}

	gqlClient := graphql.NewClient(apiUrl)
	// make a request
	req := graphql.NewRequest(`
query CompanyList($userID: ID!) {
  user(id: $userID) {
    companies {
      id
    }
  }
}
	`)
	// set any variables
	req.Var("userID", id)

	// set header fields
	req.Header.Set("Cache-Control", "no-cache")

	// define a Context for the request
	ctx := context.Background()

	// run it and capture the response
	responseMap := make(map[string]interface{})
	if err := gqlClient.Run(ctx, req, &responseMap); err != nil {
		return []string{""}, err
	}
	userMap := responseMap["user"].(map[string]interface{})
	companiesMap := userMap["companies"].([]interface{})

	var result []string
	for _, v := range companiesMap {
		c := v.(map[string]interface{})
		result = append(result, c["id"].(string))
	}

	return result, nil
}
