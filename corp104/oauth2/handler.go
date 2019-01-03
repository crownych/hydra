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
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package oauth2

import (
	"encoding/json"
	"fmt"
	"github.com/ory/hydra/corp104/resource"
	"net/http"
	"reflect"
	"strings"
	"time"

	jwt2 "github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/corp104/consent"
	"github.com/ory/hydra/pkg"
	"github.com/pkg/errors"
)

const (
	OpenIDConnectKeyName       = "openid.id-token"
	OAuth2JWTKeyName           = "jwt.access-token"
	idTokenSignatureSessionKey = "id_token_signature"

	DefaultConsentPath = "/oauth2/fallbacks/consent"
	DefaultLogoutPath  = "/logout"
	DefaultErrorPath   = "/oauth2/fallbacks/error"
	TokenPath          = "/token"
	AuthPath           = "/authorize"

	UserinfoPath  = "/userinfo"
	WellKnownPath = "/.well-known/oauth-authorization-server"
	JWKPath       = "/jwks.json"

	// IntrospectPath points to the OAuth2 introspection endpoint.
	IntrospectPath = "/oauth2/introspect"
	RevocationPath = "/revoke"
	FlushPath      = "/oauth2/flush"

	ServiceDocURL    = "https://github.com/104corp/vip3-auth"
	CheckSessionPath = "/check-session"

	EndSessionPath = "/oauth2/auth/sessions/login/revoke"
)

type SignedMetadata struct {
	Token string `json:"signed_metadata"`
}

// swagger:model wellKnown
type WellKnown struct {
	// URL using the https scheme with no query or fragment component that the OP asserts as its IssuerURL Identifier.
	// If IssuerURL discovery is supported , this value MUST be identical to the issuer value returned
	// by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this IssuerURL.
	//
	// required: true
	Issuer string `json:"issuer"`

	// URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate
	// signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs
	// to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use)
	// parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
	// Although some algorithms allow the same key to be used for both signatures and encryption, doing so is
	// NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of
	// keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
	//
	// required: true
	JWKsURI string `json:"jwks_uri"`

	// Auth service documentation URL
	ServiceDocumentation string `json:"service_documentation"`

	// URL of the OP's OAuth 2.0 Authorization Endpoint.
	//
	// required: true
	AuthURL string `json:"authorization_endpoint"`

	// URL of the OP's OAuth 2.0 Token Endpoint
	//
	// required: true
	TokenURL string `json:"token_endpoint"`

	// URL of the OP's Dynamic Client Registration Endpoint.
	RegistrationEndpoint string `json:"registration_endpoint"`

	// Revocation endpoint
	RevocationEndpoint string `json:"revocation_endpoint"`

	// Check Session IFrame Endpoint
	CheckSessionIFrame string `json:"check_session_iframe"`

	// End Session Endpoint
	EndSessionEndpoint string `json:"end_session_endpoint"`

	// Resources Endpoint
	ResourcesEndpoint string `json:"resources_endpoint"`

	// JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST
	// support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used
	ScopesSupported []string `json:"scopes_supported"`

	// JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID
	// Providers MUST support the code, id_token, and the token id_token Response Type values.
	//
	// required: true
	ResponseTypes []string `json:"response_types_supported"`

	// JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
	GrantTypesSupported []string `json:"grant_types_supported"`

	// JSON array containing a list of Client Authentication methods supported by this Token Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the auth service for the Token
	// to encode the Claims in a JWT.
	//
	// required: true
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`

	// JSON array containing a list of auth methods supported by the revocation endpoint
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the auth service for the Token
	// revocation to encode the Claims in a JWT.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token
	// to encode the Claims in a JWT.
	//
	// required: true
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// 	Boolean value specifying whether the auth service supports use of the request parameter, with true indicating support.
	RequestParameterSupported bool `json:"request_parameter_supported"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the auth service for the
	// request object to encode the Claims in a JWT.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`
}

func (w *WellKnown) ToMap() map[string]interface{} {
	m := make(map[string]interface{})
	m["issuer"] = w.Issuer
	m["jwks_uri"] = w.JWKsURI
	m["service_documentation"] = w.ServiceDocumentation
	m["authorization_endpoint"] = w.AuthURL
	m["token_endpoint"] = w.TokenURL
	m["registration_endpoint"] = w.RegistrationEndpoint
	m["revocation_endpoint"] = w.RevocationEndpoint
	m["check_session_iframe"] = w.CheckSessionIFrame
	m["end_session_endpoint"] = w.EndSessionEndpoint
	m["resources_endpoint"] = w.ResourcesEndpoint
	m["scopes_supported"] = w.ScopesSupported
	m["response_types_supported"] = w.ResponseTypes
	m["grant_types_supported"] = w.GrantTypesSupported
	m["token_endpoint_auth_methods_supported"] = w.TokenEndpointAuthMethodsSupported
	m["token_endpoint_auth_signing_alg_values_supported"] = w.TokenEndpointAuthSigningAlgValuesSupported
	m["revocation_endpoint_auth_methods_supported"] = w.RevocationEndpointAuthMethodsSupported
	m["revocation_endpoint_auth_signing_alg_values_supported"] = w.RevocationEndpointAuthSigningAlgValuesSupported
	m["id_token_signing_alg_values_supported"] = w.IDTokenSigningAlgValuesSupported
	m["request_parameter_supported"] = w.RequestParameterSupported
	m["request_object_signing_alg_values_supported"] = w.RevocationEndpointAuthSigningAlgValuesSupported
	return m
}

func (w *WellKnown) ToMapClaims() jwt2.MapClaims {
	return w.ToMap()
}

// swagger:model flushInactiveOAuth2TokensRequest
type FlushInactiveOAuth2TokensRequest struct {
	// NotAfter sets after which point tokens should not be flushed. This is useful when you want to keep a history
	// of recently issued tokens for auditing.
	NotAfter time.Time `json:"notAfter"`
}

func (h *Handler) SetRoutes(frontend, backend *httprouter.Router, corsMiddleware func(http.Handler) http.Handler) {
	frontend.Handler("OPTIONS", TokenPath, corsMiddleware(http.HandlerFunc(h.handleOptions)))
	frontend.Handler("POST", TokenPath, corsMiddleware(http.HandlerFunc(h.TokenHandler)))
	frontend.GET(AuthPath, h.AuthHandler)
	frontend.POST(AuthPath, h.AuthHandler)
	frontend.GET(DefaultConsentPath, h.DefaultConsentHandler)
	frontend.GET(DefaultErrorPath, h.DefaultErrorHandler)
	frontend.GET(DefaultLogoutPath, h.DefaultLogoutHandler)
	frontend.Handler("OPTIONS", RevocationPath, corsMiddleware(http.HandlerFunc(h.handleOptions)))
	frontend.Handler("POST", RevocationPath, corsMiddleware(http.HandlerFunc(h.RevocationHandler)))
	frontend.Handler("OPTIONS", WellKnownPath, corsMiddleware(http.HandlerFunc(h.handleOptions)))
	frontend.Handler("GET", WellKnownPath, corsMiddleware(http.HandlerFunc(h.WellKnownHandler)))
	frontend.Handler("OPTIONS", UserinfoPath, corsMiddleware(http.HandlerFunc(h.handleOptions)))
	frontend.Handler("GET", UserinfoPath, corsMiddleware(http.HandlerFunc(h.UserinfoHandler)))
	frontend.Handler("POST", UserinfoPath, corsMiddleware(http.HandlerFunc(h.UserinfoHandler)))

	backend.POST(IntrospectPath, h.IntrospectHandler)
	backend.POST(FlushPath, h.FlushHandler)
}

// swagger:route GET /.well-known/openid-configuration oAuth2 getWellKnown
//
// Server well known configuration
//
// The well known endpoint an be used to retrieve information for OpenID Connect clients. We encourage you to not roll
// your own OpenID Connect client but to use an OpenID Connect client library instead. You can learn more on this
// flow at https://openid.net/specs/openid-connect-discovery-1_0.html
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: wellKnown
//       401: genericError
//       500: genericError
func (h *Handler) WellKnownHandler(w http.ResponseWriter, r *http.Request) {
	claimsSupported := []string{"sub"}
	if h.ClaimsSupported != "" {
		claimsSupported = append(claimsSupported, strings.Split(h.ClaimsSupported, ",")...)
	}

	scopesSupported := []string{"openid"}
	if h.ScopesSupported != "" {
		scopesSupported = append(scopesSupported, strings.Split(h.ScopesSupported, ",")...)
	}
	resourceScopes, _ := h.ResourceManager.GetAllScopeNames()
	fmt.Println("resourceScopes: ", resourceScopes)
	scopesSupported = append(scopesSupported, resourceScopes...)

	claims := (&WellKnown{
		Issuer:                            strings.TrimRight(h.IssuerURL, "/") + "/",
		JWKsURI:                           strings.TrimRight(h.IssuerURL, "/") + JWKPath,
		ServiceDocumentation:              ServiceDocURL,
		AuthURL:                           strings.TrimRight(h.IssuerURL, "/") + AuthPath,
		TokenURL:                          strings.TrimRight(h.IssuerURL, "/") + TokenPath,
		RegistrationEndpoint:              strings.TrimRight(h.IssuerURL, "/") + client.ClientsHandlerPath,
		RevocationEndpoint:                strings.TrimRight(h.IssuerURL, "/") + RevocationPath,
		CheckSessionIFrame:                strings.TrimRight(h.IssuerURL, "/") + CheckSessionPath,
		EndSessionEndpoint:                strings.TrimRight(h.IssuerURL, "/") + EndSessionPath,
		ResourcesEndpoint:                 strings.TrimRight(h.IssuerURL, "/") + resource.ResourcesHandlerPath,
		ScopesSupported:                   scopesSupported,
		ResponseTypes:                     []string{"id_token", "token"},
		GrantTypesSupported:               []string{"client_credentials", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt", "private_key_jwt+session"},
		TokenEndpointAuthSigningAlgValuesSupported:      []string{"ES256"},
		RevocationEndpointAuthMethodsSupported:          []string{"private_key_jwt"},
		RevocationEndpointAuthSigningAlgValuesSupported: []string{"ES256"},
		IDTokenSigningAlgValuesSupported:                []string{"ES256"},
		RequestParameterSupported:                       true,
		RequestObjectSigningAlgValuesSupported:          []string{"ES256"},
	}).ToMapClaims()

	metaStrategy := h.OAuthServerMetadataStrategy
	extraHeaders := make(map[string]interface{})
	pubKeyId, _ := metaStrategy.GetPublicKeyID(r.Context())
	extraHeaders["kid"] = pubKeyId
	token, _, _ := metaStrategy.Generate(r.Context(), claims, &jwt.Headers{Extra: extraHeaders})

	h.H.Write(w, r, &SignedMetadata{token})
}

// swagger:route POST /userinfo oAuth2 userinfo
//
// OpenID Connect Userinfo
//
// This endpoint returns the payload of the ID Token, including the idTokenExtra values, of the provided OAuth 2.0 access token.
// The endpoint implements http://openid.net/specs/openid-connect-core-1_0.html#UserInfo .
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oauth2:
//
//     Responses:
//       200: userinfoResponse
//       401: genericError
//       500: genericError
func (h *Handler) UserinfoHandler(w http.ResponseWriter, r *http.Request) {
	session := NewSession("")
	tokenType, ar, err := h.OAuth2.IntrospectToken(r.Context(), fosite.AccessTokenFromRequest(r), fosite.AccessToken, session)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if tokenType != fosite.AccessToken {
		h.H.WriteErrorCode(w, r, http.StatusUnauthorized, errors.New("Only access tokens are allowed in the authorization header"))
		return
	}

	c, ok := ar.GetClient().(*client.Client)
	if !ok {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrServerError.WithHint("Unable to type assert to *client.Client")))
		return
	}

	if c.UserinfoSignedResponseAlg == "ES256" {
		interim := ar.GetSession().(*Session).IDTokenClaims().ToMap()

		delete(interim, "nonce")
		delete(interim, "at_hash")
		delete(interim, "c_hash")
		delete(interim, "auth_time")
		delete(interim, "iat")
		delete(interim, "rat")
		delete(interim, "exp")
		delete(interim, "jti")

		keyID, err := h.OpenIDJWTStrategy.GetPublicKeyID(r.Context())
		if err != nil {
			h.H.WriteError(w, r, err)
			return
		}

		token, _, err := h.OpenIDJWTStrategy.Generate(r.Context(), jwt2.MapClaims(interim), &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": keyID,
			},
		})
		if err != nil {
			h.H.WriteError(w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(token))
	} else if c.UserinfoSignedResponseAlg == "" || c.UserinfoSignedResponseAlg == "none" {
		interim := ar.GetSession().(*Session).IDTokenClaims().ToMap()
		delete(interim, "aud")
		delete(interim, "iss")
		delete(interim, "nonce")
		delete(interim, "at_hash")
		delete(interim, "c_hash")
		delete(interim, "auth_time")
		delete(interim, "iat")
		delete(interim, "rat")
		delete(interim, "exp")
		delete(interim, "jti")

		h.H.Write(w, r, interim)
	} else {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrServerError.WithHint(fmt.Sprintf("Unsupported userinfo signing algorithm \"%s\"", c.UserinfoSignedResponseAlg))))
		return
	}
}

// swagger:route POST /revoke oAuth2 revokeOAuth2Token
//
// Revoke OAuth2 tokens
//
// Revoking a token (both access and refresh) means that the tokens will be invalid. A revoked access token can no
// longer be used to make access requests, and a revoked refresh token can no longer be used to refresh an access token.
// Revoking a refresh token also invalidates the access token that was created with it.
//
//     Consumes:
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Security:
//       basic:
//       oauth2:
//
//     Responses:
//       200: emptyResponse
//       401: genericError
//       500: genericError
func (h *Handler) RevocationHandler(w http.ResponseWriter, r *http.Request) {
	var ctx = r.Context()

	err := h.OAuth2.NewRevocationRequest(ctx, r)
	if err != nil {
		pkg.LogError(err, h.L)
	}

	h.OAuth2.WriteRevocationResponse(w, err)
}

// swagger:route POST /oauth2/introspect oAuth2 introspectOAuth2Token
//
// Introspect OAuth2 tokens
//
// The introspection endpoint allows to check if a token (both refresh and access) is active or not. An active token
// is neither expired nor revoked. If a token is active, additional information on the token will be included. You can
// set additional data for a token by setting `accessTokenExtra` during the consent flow.
//
//     Consumes:
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       basic:
//       oauth2:
//
//     Responses:
//       200: oAuth2TokenIntrospection
//       401: genericError
//       500: genericError
func (h *Handler) IntrospectHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var session = NewSession("")
	var ctx = r.Context()

	if r.Method != "POST" {
		err := errors.WithStack(fosite.ErrInvalidRequest.WithHintf("HTTP method is \"%s\", expected \"POST\".", r.Method))
		pkg.LogError(err, h.L)
		h.OAuth2.WriteIntrospectionError(w, err)
		return
	} else if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		err := errors.WithStack(fosite.ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithDebug(err.Error()))
		pkg.LogError(err, h.L)
		h.OAuth2.WriteIntrospectionError(w, err)
		return
	} else if len(r.PostForm) == 0 {
		err := errors.WithStack(fosite.ErrInvalidRequest.WithHint("The POST body can not be empty."))
		pkg.LogError(err, h.L)
		h.OAuth2.WriteIntrospectionError(w, err)
		return
	}

	token := r.PostForm.Get("token")
	tokenType := r.PostForm.Get("token_type_hint")
	scope := r.PostForm.Get("scope")

	tt, ar, err := h.OAuth2.IntrospectToken(ctx, token, fosite.TokenType(tokenType), session, strings.Split(scope, " ")...)
	if err != nil {
		err := errors.WithStack(fosite.ErrInactiveToken.WithHint("An introspection strategy indicated that the token is inactive.").WithDebug(err.Error()))
		pkg.LogError(err, h.L)
		h.OAuth2.WriteIntrospectionError(w, err)
		return
	}

	resp := &fosite.IntrospectionResponse{
		Active:          true,
		AccessRequester: ar,
		TokenType:       tt,
	}

	exp := resp.GetAccessRequester().GetSession().GetExpiresAt(fosite.AccessToken)
	if exp.IsZero() {
		exp = resp.GetAccessRequester().GetRequestedAt().Add(h.AccessTokenLifespan)
	}

	session, ok := resp.GetAccessRequester().GetSession().(*Session)
	if !ok {
		err := errors.WithStack(fosite.ErrServerError.WithHint("Expected session to be of type *Session, but got another type.").WithDebug(fmt.Sprintf("Got type %s", reflect.TypeOf(resp.GetAccessRequester().GetSession()))))
		pkg.LogError(err, h.L)
		h.OAuth2.WriteIntrospectionError(w, err)
		return
	}

	var obfuscated string
	if len(session.Claims.Subject) > 0 && session.Claims.Subject != session.Subject {
		obfuscated = session.Claims.Subject
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	if err = json.NewEncoder(w).Encode(&Introspection{
		Active:            resp.IsActive(),
		ClientID:          resp.GetAccessRequester().GetClient().GetID(),
		Scope:             strings.Join(resp.GetAccessRequester().GetGrantedScopes(), " "),
		ExpiresAt:         exp.Unix(),
		IssuedAt:          resp.GetAccessRequester().GetRequestedAt().Unix(),
		Subject:           session.GetSubject(),
		Username:          session.GetUsername(),
		Extra:             session.Extra,
		Audience:          session.Audience,
		Issuer:            strings.TrimRight(h.IssuerURL, "/") + "/",
		ObfuscatedSubject: obfuscated,
		TokenType:         string(resp.GetTokenType()),
	}); err != nil {
		pkg.LogError(errors.WithStack(err), h.L)
	}
}

// swagger:route POST /oauth2/flush oAuth2 flushInactiveOAuth2Tokens
//
// Flush Expired OAuth2 Access Tokens
//
// This endpoint flushes expired OAuth2 access tokens from the database. You can set a time after which no tokens will be
// not be touched, in case you want to keep recent tokens for auditing. Refresh tokens can not be flushed as they are deleted
// automatically when performing the refresh flow.
//
//     Consumes:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       204: emptyResponse
//       401: genericError
//       500: genericError
func (h *Handler) FlushHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var fr FlushInactiveOAuth2TokensRequest
	if err := json.NewDecoder(r.Body).Decode(&fr); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if fr.NotAfter.IsZero() {
		fr.NotAfter = time.Now()
	}

	if err := h.Storage.FlushInactiveAccessTokens(r.Context(), fr.NotAfter); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route POST /token oAuth2 oauthToken
//
// The OAuth 2.0 token endpoint
//
// This endpoint is not documented here because you should never use your own implementation to perform OAuth2 flows.
// OAuth2 is a very popular protocol and a library for your programming language will exists.
//
// To learn more about this flow please refer to the specification: https://tools.ietf.org/html/rfc6749
//
//     Consumes:
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       basic:
//       oauth2:
//
//     Responses:
//       200: oauthTokenResponse
//       401: genericError
//       500: genericError
func (h *Handler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	var session = NewSession("")
	var ctx = r.Context()

	accessRequest, err := h.OAuth2.NewAccessRequest(ctx, r, session)
	if err != nil {
		pkg.LogError(err, h.L)
		h.OAuth2.WriteAccessError(w, accessRequest, err)
		return
	}

	// TODO 應該放在 AccessTokenStrategy 中處理
	if h.AccessTokenStrategy == "jwt" {
		accessTokenKeyID, err := h.AccessTokenJWTStrategy.GetPublicKeyID(r.Context())
		if err != nil {
			pkg.LogError(err, h.L)
			h.OAuth2.WriteAccessError(w, accessRequest, err)
			return
		}
		claims := session.GetJWTClaims()
		if sub, ok := claims.Extra["sub"].(string); ok {
			session.Subject = sub
		}
		if aud, ok := claims.Extra["aud"].(string); ok {
			session.Audience = []string{aud}
		} else if auds, ok := claims.Extra["aud"].([]string); ok {
			session.Audience = auds
		}
		session.ClientID = accessRequest.GetClient().GetID()
		session.KID = accessTokenKeyID
		session.DefaultSession.Claims.Issuer = strings.TrimRight(h.IssuerURL, "/") + "/"
		session.DefaultSession.Claims.IssuedAt = time.Now().UTC()
		session.GetJWTHeader().Add("cty", "resource-access-token+jwt")
	}
	// TODO: ScopeStrategy 暫時忽略

	accessResponse, err := h.OAuth2.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		pkg.LogError(err, h.L)
		h.OAuth2.WriteAccessError(w, accessRequest, err)
		return
	}

	h.OAuth2.WriteAccessResponse(w, accessRequest, accessResponse)
}

// swagger:route GET /oauth2/auth oAuth2 oauthAuth
//
// The OAuth 2.0 authorize endpoint
//
// This endpoint is not documented here because you should never use your own implementation to perform OAuth2 flows.
// OAuth2 is a very popular protocol and a library for your programming language will exists.
//
// To learn more about this flow please refer to the specification: https://tools.ietf.org/html/rfc6749
//
//     Consumes:
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       302: emptyResponse
//       401: genericError
//       500: genericError
func (h *Handler) AuthHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var ctx = r.Context()

	authorizeRequest, err := h.OAuth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		pkg.LogError(err, h.L)
		h.writeAuthorizeError(w, authorizeRequest, err)
		return
	}

	session, err := h.Consent.HandleOAuth2AuthorizationRequest(w, r, authorizeRequest)
	if errors.Cause(err) == consent.ErrAbortOAuth2Request {
		// do nothing
		return
	} else if err != nil {
		pkg.LogError(err, h.L)
		h.writeAuthorizeError(w, authorizeRequest, err)
		return
	}

	for _, scope := range session.GrantedScope {
		authorizeRequest.GrantScope(scope)
	}

	openIDKeyID, err := h.OpenIDJWTStrategy.GetPublicKeyID(r.Context())
	if err != nil {
		pkg.LogError(err, h.L)
		h.writeAuthorizeError(w, authorizeRequest, err)
		return
	}

	var accessTokenKeyID string
	if h.AccessTokenStrategy == "jwt" {
		accessTokenKeyID, err = h.AccessTokenJWTStrategy.GetPublicKeyID(r.Context())
		if err != nil {
			pkg.LogError(err, h.L)
			h.writeAuthorizeError(w, authorizeRequest, err)
			return
		}
	}

	authorizeRequest.SetID(session.Challenge)

	// done
	response, err := h.OAuth2.NewAuthorizeResponse(ctx, authorizeRequest, &Session{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				// We do not need to pass the audience because it's included directly by ORY Fosite
				Audience: []string{authorizeRequest.GetClient().GetID(), h.IssuerURL},
				Subject:  session.ConsentRequest.SubjectIdentifier,
				Issuer:   strings.TrimRight(h.IssuerURL, "/") + "/",
				IssuedAt: time.Now().UTC(),
				// This is set by the fosite strategy
				//ExpiresAt:   time.Now().Add(h.IDTokenLifespan).UTC(),
				AuthTime:    session.AuthenticatedAt,
				RequestedAt: session.RequestedAt,
				Extra:       session.Session.IDToken,
			},
			// required for lookup on jwk endpoint
			Headers: &jwt.Headers{Extra: map[string]interface{}{"kid": openIDKeyID}},
			Subject: session.ConsentRequest.Subject,
		},
		Extra: session.Session.AccessToken,
		// Here, we do not include the client because it's typically not the audience.
		Audience: []string{},
		KID:      accessTokenKeyID,
		ClientID: authorizeRequest.GetClient().GetID(),
	})
	if err != nil {
		pkg.LogError(err, h.L)
		h.writeAuthorizeError(w, authorizeRequest, err)
		return
	}

	idToken := response.GetFragment().Get("id_token")
	if idToken != "" {
		parts := strings.Split(idToken, ".")
		if len(parts) == 3 && parts[2] != "" {
			pkg.SaveSessionValue(r, idTokenSignatureSessionKey, parts[2])
		}
	}

	h.OAuth2.WriteAuthorizeResponse(w, authorizeRequest, response)
}

func (h *Handler) writeAuthorizeError(w http.ResponseWriter, ar fosite.AuthorizeRequester, err error) {
	if !ar.IsRedirectURIValid() {
		var rfcerr = fosite.ErrorToRFC6749Error(err)

		redirectURI := h.ErrorURL
		query := redirectURI.Query()
		query.Add("error", rfcerr.Name)
		query.Add("error_description", rfcerr.Description)
		query.Add("error_hint", rfcerr.Hint)

		if h.ShareOAuth2Debug {
			query.Add("error_debug", rfcerr.Debug)
		}

		redirectURI.RawQuery = query.Encode()
		w.Header().Add("Location", redirectURI.String())
		w.WriteHeader(http.StatusFound)
		return
	}

	h.OAuth2.WriteAuthorizeError(w, ar, err)
}

// This function will not be called, OPTIONS request will be handled by cors
// this is just a placeholder.
func (h *Handler) handleOptions(w http.ResponseWriter, r *http.Request) {}
