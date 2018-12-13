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
	"encoding/base64"
	"encoding/json"
	"github.com/go-resty/resty"
	"github.com/ory/hydra/pkg"
	"github.com/spf13/viper"
	"net/http"
	"net/url"
	"time"

	nSession "github.com/goincremental/negroni-sessions"
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/go-convenience/urlx"
	"github.com/ory/herodot"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/pagination"
	"github.com/pkg/errors"
)

type Handler struct {
	H                 herodot.Writer
	M                 Manager
	LogoutRedirectURL string
	RequestMaxAge     time.Duration
	CookieStore       sessions.Store
	KeyManager        jwk.Manager
}

const (
	LoginPath    = "/oauth2/auth/requests/login"
	ConsentPath  = "/oauth2/auth/requests/consent"
	SessionsPath = "/oauth2/auth/sessions"
	IdpPath      = "/idp"
	ForgotPasswordPath = "/forgot-password"
	ResetPasswordPath  = "/reset-password"

	ClientsMetadataSessionKey = "client_metadata"
)

func NewHandler(
	h herodot.Writer,
	m Manager,
	c sessions.Store,
	u string,
	k jwk.Manager,
) *Handler {
	return &Handler{
		H:                 h,
		M:                 m,
		LogoutRedirectURL: u,
		CookieStore:       c,
		KeyManager:        k,
	}
}

func (h *Handler) SetRoutes(frontend, backend *httprouter.Router) {
	backend.GET(LoginPath+"/:challenge", h.GetLoginRequest)
	backend.PUT(LoginPath+"/:challenge/accept", h.AcceptLoginRequest)
	backend.PUT(LoginPath+"/:challenge/reject", h.RejectLoginRequest)

	backend.GET(ConsentPath+"/:challenge", h.GetConsentRequest)
	backend.PUT(ConsentPath+"/:challenge/accept", h.AcceptConsentRequest)
	backend.PUT(ConsentPath+"/:challenge/reject", h.RejectConsentRequest)

	backend.DELETE(SessionsPath+"/login/:user", h.DeleteLoginSession)
	backend.GET(SessionsPath+"/consent/:user", h.GetConsentSessions)
	backend.DELETE(SessionsPath+"/consent/:user", h.DeleteUserConsentSession)
	backend.DELETE(SessionsPath+"/consent/:user/:client", h.DeleteUserClientConsentSession)

	frontend.GET(SessionsPath+"/login/revoke", h.LogoutUser)

	frontend.POST(IdpPath, h.AuthUser)
	frontend.POST(ForgotPasswordPath, h.ForgotPassword)
	frontend.POST(ResetPasswordPath, h.ResetPassword)
}

// swagger:route DELETE /oauth2/auth/sessions/consent/{user} oAuth2 revokeAllUserConsentSessions
//
// Revokes all previous consent sessions of a user
//
// This endpoint revokes a user's granted consent sessions and invalidates all associated OAuth 2.0 Access Tokens.
//
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       204: emptyResponse
//       404: genericError
//       500: genericError
func (h *Handler) DeleteUserConsentSession(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := ps.ByName("user")
	if err := h.M.RevokeUserConsentSession(r.Context(), user); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route DELETE /oauth2/auth/sessions/consent/{user}/{client} oAuth2 revokeUserClientConsentSessions
//
// Revokes consent sessions of a user for a specific OAuth 2.0 Client
//
// This endpoint revokes a user's granted consent sessions for a specific OAuth 2.0 Client and invalidates all
// associated OAuth 2.0 Access Tokens.
//
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       204: emptyResponse
//       404: genericError
//       500: genericError
func (h *Handler) DeleteUserClientConsentSession(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	client := ps.ByName("client")
	user := ps.ByName("user")
	if client == "" {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Parameter client is not defined")))
		return
	}

	if err := h.M.RevokeUserClientConsentSession(r.Context(), user, client); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route GET /oauth2/auth/sessions/consent/{user} oAuth2 listUserConsentSessions
//
// Lists all consent sessions of a user
//
// This endpoint lists all user's granted consent sessions, including client and granted scope
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: handledConsentRequestList
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) GetConsentSessions(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := ps.ByName("user")
	if user == "" {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Parameter user is not defined")))
		return
	}
	limit, offset := pagination.Parse(r, 100, 0, 500)

	sessions, err := h.M.FindPreviouslyGrantedConsentRequestsByUser(r.Context(), user, limit, offset)
	if errors.Cause(err) == ErrNoPreviousConsentFound {
		h.H.Write(w, r, []PreviousConsentSession{})
		return
	} else if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	var a []PreviousConsentSession

	for _, session := range sessions {
		session.ConsentRequest.Client = sanitizeClient(session.ConsentRequest.Client)
		a = append(a, PreviousConsentSession(session))
	}

	if len(a) == 0 {
		a = []PreviousConsentSession{}
	}

	h.H.Write(w, r, a)
}

// swagger:route DELETE /oauth2/auth/sessions/login/{user} oAuth2 revokeAuthenticationSession
//
// Invalidates a user's authentication session
//
// This endpoint invalidates a user's authentication session. After revoking the authentication session, the user
// has to re-authenticate at ORY Hydra. This endpoint does not invalidate any tokens.
//
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       204: emptyResponse
//       404: genericError
//       500: genericError
func (h *Handler) DeleteLoginSession(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := ps.ByName("user")

	if err := h.M.RevokeUserAuthenticationSession(r.Context(), user); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route GET /oauth2/auth/requests/login/{challenge} oAuth2 getLoginRequest
//
// Get an login request
//
// When an authorization code, hybrid, or implicit OAuth 2.0 Flow is initiated, ORY Hydra asks the login provider
// (sometimes called "identity provider") to authenticate the user and then tell ORY Hydra now about it. The login
// provider is an web-app you write and host, and it must be able to authenticate ("show the user a login screen")
// a user (in OAuth2 the proper name for user is "resource owner").
//
// The authentication challenge is appended to the login provider URL to which the user's user-agent (browser) is redirected to. The login
// provider uses that challenge to fetch information on the OAuth2 request and then accept or reject the requested authentication process.
//
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: loginRequest
//       401: genericError
//       500: genericError
func (h *Handler) GetLoginRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	request, err := h.M.GetAuthenticationRequest(r.Context(), ps.ByName("challenge"))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	request.Client = sanitizeClient(request.Client)

	h.H.Write(w, r, request)
}

// swagger:route PUT /oauth2/auth/requests/login/{challenge}/accept oAuth2 acceptLoginRequest
//
// Accept an login request
//
// When an authorization code, hybrid, or implicit OAuth 2.0 Flow is initiated, ORY Hydra asks the login provider
// (sometimes called "identity provider") to authenticate the user and then tell ORY Hydra now about it. The login
// provider is an web-app you write and host, and it must be able to authenticate ("show the user a login screen")
// a user (in OAuth2 the proper name for user is "resource owner").
//
// The authentication challenge is appended to the login provider URL to which the user's user-agent (browser) is redirected to. The login
// provider uses that challenge to fetch information on the OAuth2 request and then accept or reject the requested authentication process.
//
// This endpoint tells ORY Hydra that the user has successfully authenticated and includes additional information such as
// the user's ID and if ORY Hydra should remember the user's user agent for future authentication attempts by setting
// a cookie.
//
// The response contains a redirect URL which the login provider should redirect the user-agent to.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: completedRequest
//       401: genericError
//       500: genericError
func (h *Handler) AcceptLoginRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p HandledAuthenticationRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		h.H.WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	p.Challenge = ps.ByName("challenge")
	ar, err := h.M.GetAuthenticationRequest(r.Context(), ps.ByName("challenge"))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	} else if ar.Subject != "" && p.Subject != ar.Subject {
		h.H.WriteErrorCode(w, r, http.StatusBadRequest, errors.New("Subject from payload does not match subject from previous authentication"))
		return
	} else if ar.Skip && p.Remember {
		h.H.WriteErrorCode(w, r, http.StatusBadRequest, errors.New("Can not remember authentication because no user interaction was required"))
		return
	}

	if !ar.Skip {
		p.AuthenticatedAt = time.Now().UTC()
	} else {
		p.AuthenticatedAt = ar.AuthenticatedAt
	}
	p.RequestedAt = ar.RequestedAt

	request, err := h.M.HandleAuthenticationRequest(r.Context(), ps.ByName("challenge"), &p)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	ru, err := url.Parse(request.RequestURL)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.Write(w, r, &RequestHandlerResponse{
		RedirectTo: urlx.SetQuery(ru, url.Values{"login_verifier": {request.Verifier}}).String(),
	})
}

// swagger:route PUT /oauth2/auth/requests/login/{challenge}/reject oAuth2 rejectLoginRequest
//
// Reject a login request
//
// When an authorization code, hybrid, or implicit OAuth 2.0 Flow is initiated, ORY Hydra asks the login provider
// (sometimes called "identity provider") to authenticate the user and then tell ORY Hydra now about it. The login
// provider is an web-app you write and host, and it must be able to authenticate ("show the user a login screen")
// a user (in OAuth2 the proper name for user is "resource owner").
//
// The authentication challenge is appended to the login provider URL to which the user's user-agent (browser) is redirected to. The login
// provider uses that challenge to fetch information on the OAuth2 request and then accept or reject the requested authentication process.
//
// This endpoint tells ORY Hydra that the user has not authenticated and includes a reason why the authentication
// was be denied.
//
// The response contains a redirect URL which the login provider should redirect the user-agent to.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: completedRequest
//       401: genericError
//       500: genericError
func (h *Handler) RejectLoginRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p RequestDeniedError
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		h.H.WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	ar, err := h.M.GetAuthenticationRequest(r.Context(), ps.ByName("challenge"))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	request, err := h.M.HandleAuthenticationRequest(r.Context(), ps.ByName("challenge"), &HandledAuthenticationRequest{
		Error:       &p,
		Challenge:   ps.ByName("challenge"),
		RequestedAt: ar.RequestedAt,
	})
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	ru, err := url.Parse(request.RequestURL)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.Write(w, r, &RequestHandlerResponse{
		RedirectTo: urlx.SetQuery(ru, url.Values{"login_verifier": {request.Verifier}}).String(),
	})
}

// swagger:route GET /oauth2/auth/requests/consent/{challenge} oAuth2 getConsentRequest
//
// Get consent request information
//
// When an authorization code, hybrid, or implicit OAuth 2.0 Flow is initiated, ORY Hydra asks the login provider
// to authenticate the user and then tell ORY Hydra now about it. If the user authenticated, he/she must now be asked if
// the OAuth 2.0 Client which initiated the flow should be allowed to access the resources on the user's behalf.
//
// The consent provider which handles this request and is a web app implemented and hosted by you. It shows a user interface which asks the user to
// grant or deny the client access to the requested scope ("Application my-dropbox-app wants write access to all your private files").
//
// The consent challenge is appended to the consent provider's URL to which the user's user-agent (browser) is redirected to. The consent
// provider uses that challenge to fetch information on the OAuth2 request and then tells ORY Hydra if the user accepted
// or rejected the request.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: consentRequest
//       401: genericError
//       500: genericError
func (h *Handler) GetConsentRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	request, err := h.M.GetConsentRequest(r.Context(), ps.ByName("challenge"))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	request.Client = sanitizeClient(request.Client)

	h.H.Write(w, r, request)
}

// swagger:route PUT /oauth2/auth/requests/consent/{challenge}/accept oAuth2 acceptConsentRequest
//
// Accept an consent request
//
// When an authorization code, hybrid, or implicit OAuth 2.0 Flow is initiated, ORY Hydra asks the login provider
// to authenticate the user and then tell ORY Hydra now about it. If the user authenticated, he/she must now be asked if
// the OAuth 2.0 Client which initiated the flow should be allowed to access the resources on the user's behalf.
//
// The consent provider which handles this request and is a web app implemented and hosted by you. It shows a user interface which asks the user to
// grant or deny the client access to the requested scope ("Application my-dropbox-app wants write access to all your private files").
//
// The consent challenge is appended to the consent provider's URL to which the user's user-agent (browser) is redirected to. The consent
// provider uses that challenge to fetch information on the OAuth2 request and then tells ORY Hydra if the user accepted
// or rejected the request.
//
// This endpoint tells ORY Hydra that the user has authorized the OAuth 2.0 client to access resources on his/her behalf.
// The consent provider includes additional information, such as session data for access and ID tokens, and if the
// consent request should be used as basis for future requests.
//
// The response contains a redirect URL which the consent provider should redirect the user-agent to.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: completedRequest
//       401: genericError
//       500: genericError
func (h *Handler) AcceptConsentRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p HandledConsentRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		h.H.WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	cr, err := h.M.GetConsentRequest(r.Context(), ps.ByName("challenge"))
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	p.Challenge = ps.ByName("challenge")
	p.RequestedAt = cr.RequestedAt

	hr, err := h.M.HandleConsentRequest(r.Context(), ps.ByName("challenge"), &p)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	} else if hr.Skip && p.Remember {
		h.H.WriteErrorCode(w, r, http.StatusBadRequest, errors.New("Can not remember consent because no user interaction was required"))
		return
	}

	ru, err := url.Parse(hr.RequestURL)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.Write(w, r, &RequestHandlerResponse{
		RedirectTo: urlx.SetQuery(ru, url.Values{"consent_verifier": {hr.Verifier}}).String(),
	})
}

// swagger:route PUT /oauth2/auth/requests/consent/{challenge}/reject oAuth2 rejectConsentRequest
//
// Reject an consent request
//
// When an authorization code, hybrid, or implicit OAuth 2.0 Flow is initiated, ORY Hydra asks the login provider
// to authenticate the user and then tell ORY Hydra now about it. If the user authenticated, he/she must now be asked if
// the OAuth 2.0 Client which initiated the flow should be allowed to access the resources on the user's behalf.
//
// The consent provider which handles this request and is a web app implemented and hosted by you. It shows a user interface which asks the user to
// grant or deny the client access to the requested scope ("Application my-dropbox-app wants write access to all your private files").
//
// The consent challenge is appended to the consent provider's URL to which the user's user-agent (browser) is redirected to. The consent
// provider uses that challenge to fetch information on the OAuth2 request and then tells ORY Hydra if the user accepted
// or rejected the request.
//
// This endpoint tells ORY Hydra that the user has not authorized the OAuth 2.0 client to access resources on his/her behalf.
// The consent provider must include a reason why the consent was not granted.
//
// The response contains a redirect URL which the consent provider should redirect the user-agent to.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: completedRequest
//       401: genericError
//       500: genericError
func (h *Handler) RejectConsentRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p RequestDeniedError
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		h.H.WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	hr, err := h.M.GetConsentRequest(r.Context(), ps.ByName("challenge"))
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	request, err := h.M.HandleConsentRequest(r.Context(), ps.ByName("challenge"), &HandledConsentRequest{
		Error:       &p,
		Challenge:   ps.ByName("challenge"),
		RequestedAt: hr.RequestedAt,
	})
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	ru, err := url.Parse(request.RequestURL)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.Write(w, r, &RequestHandlerResponse{
		RedirectTo: urlx.SetQuery(ru, url.Values{"consent_verifier": {request.Verifier}}).String(),
	})
}

// swagger:route GET /oauth2/auth/sessions/login/revoke oAuth2 revokeUserLoginCookie
//
// Logs user out by deleting the session cookie
//
// This endpoint deletes ths user's login session cookie and redirects the browser to the url
// listed in `LOGOUT_REDIRECT_URL` environment variable. This endpoint does not work as an API but has to
// be called from the user's browser.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       302: emptyResponse
//       404: genericError
//       500: genericError
func (h *Handler) LogoutUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	sid, err := revokeAuthenticationCookie(w, r, h.CookieStore)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if sid != "" {
		if err := h.M.DeleteAuthenticationSession(r.Context(), sid); err != nil {
			h.H.WriteError(w, r, err)
			return
		}
	}

	// remove client metadata from session
	h.removeClientMetadataFromSession(r)

	http.Redirect(w, r, h.LogoutRedirectURL, 302)
}

func (h *Handler) AuthUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	msg, err := h.verifyJWS(w, r, "signed_credentials", nil, checkAuthUserPayload)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	claims := make(map[string]string)
	if err := json.Unmarshal(msg, &claims); err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	request, err := h.M.GetAuthenticationRequest(r.Context(), claims["challenge"])
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if request.Client.ClientID != claims["client_id"] {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Client id is wrong")))
		return
	}

	apiBaseUrl := viper.GetString("CORP_INTERNAL_API_URL")
	if apiBaseUrl == "" {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrInvalidRequest.WithDebug("No corp internal api url")))
		return
	}
	body := `{"username":"` + claims["username"] + `","password":"` + claims["password"] + `"}`

	resp, err := resty.R().SetHeader("Content-Type", "application/json").SetBody(body).Post(apiBaseUrl + "/login")
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	responseMap := make(map[string]string)
	if err := json.Unmarshal(resp.Body(), &responseMap); err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	if responseMap["error"] == "" {
		h.H.Write(w, r, map[string]interface{}{"ok": true, "id": responseMap["id"]})
	} else {
		h.H.Write(w, r, map[string]interface{}{"ok": false, "id": responseMap["id"]})
	}
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	payload, err := pkg.GetValueFromRequestBody(r, "email")
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	email := string(payload)

	apiBaseUrl := viper.GetString("CORP_INTERNAL_API_URL")
	if apiBaseUrl == "" {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrInvalidRequest.WithDebug("No corp internal api url")))
		return
	}

	resetPasswordRoute := viper.GetString("RESET_PASSWORD_ROUTE")
	if resetPasswordRoute == "" {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrInvalidRequest.WithDebug("No reset password route")))
		return
	}

	resp, err := resty.R().Get(apiBaseUrl + "/ac/getIdByMail/" + base64.URLEncoding.EncodeToString([]byte(email)))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	responseMap := make(map[string]interface{})
	if err := json.Unmarshal(resp.Body(), &responseMap); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if responseMap["error"].(string) != "" {
		h.H.WriteError(w, r, errors.New(responseMap["error"].(string)))
		return
	}

	dataMap := responseMap["data"].(map[string]interface{})
	if dataMap["id"].(string) == "" {
		h.H.WriteError(w, r, errors.New("No this user"))
		return
	}
	id := dataMap["id"].(string)
	body := `{"id":"` + id + `","email":"` + email + `"}`

	resp, err = resty.R().SetHeader("Content-Type", "application/json").SetBody(body).Put(apiBaseUrl + "/ac/getPasswordMailCode")
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	responseMap = make(map[string]interface{})
	if err := json.Unmarshal(resp.Body(), &responseMap); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if responseMap["error"].(string) != "" {
		h.H.WriteError(w, r, errors.New(responseMap["error"].(string)))
		return
	}

	dataMap = responseMap["data"].(map[string]interface{})
	code := dataMap["code"].(string)

	result, err := pkg.SendTextMail(email, "忘記密碼", resetPasswordRoute + "?code=" + code)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if result != true {
		h.H.WriteError(w, r, errors.New("Unable to send email"))
		return
	}

	h.H.Write(w, r, map[string]interface{}{"ok": true})
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	bodyMap, err := pkg.GetMapFromRequestBody(r)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	err = checkResetPasswordPayload(bodyMap)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	apiBaseUrl := viper.GetString("CORP_INTERNAL_API_URL")
	if apiBaseUrl == "" {
		h.H.WriteError(w, r, errors.WithStack(fosite.ErrInvalidRequest.WithDebug("No corp internal api url")))
		return
	}

	code := bodyMap["code"].(string)
	newPassword := bodyMap["newPassword"].(string)

	resp, err := resty.R().Get(apiBaseUrl + "/ac/getInfoByCode/" + base64.URLEncoding.EncodeToString([]byte(code)))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	responseMap := make(map[string]interface{})
	if err := json.Unmarshal(resp.Body(), &responseMap); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if responseMap["error"].(string) != "" {
		h.H.WriteError(w, r, errors.New(responseMap["error"].(string)))
		return
	}

	dataMap := responseMap["data"].(map[string]interface{})
	id := dataMap["id"].(string)

	body := `{"id":"` + id + `","code":"` + code + `","newPassword":"` + newPassword + `"}`

	resp, err = resty.R().SetHeader("Content-Type", "application/json").SetBody(body).Put(apiBaseUrl + "/ac/resetPassword")
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	responseMap = make(map[string]interface{})
	if err := json.Unmarshal(resp.Body(), &responseMap); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if responseMap["error"].(string) != "" {
		h.H.WriteError(w, r, errors.New(responseMap["error"].(string)))
		return
	}

	h.H.Write(w, r, map[string]interface{}{"ok": true})
}

func (h *Handler) verifyJWS(w http.ResponseWriter, r *http.Request, field string, headerChecker func(map[string]interface{}) error, payloadChecker func(map[string]interface{}) error) ([]byte, error) {

	credential, err := pkg.GetValueFromRequestBody(r, field)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return nil, err
	}

	// Extract kid from JWE header
	kid, err := pkg.ExtractKidFromJWE(credential)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return nil, err
	}
	// Extract key set
	keySet, err := h.KeyManager.GetKeysById(r.Context(), kid)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return nil, err
	}
	// Get private key of oauth server
	authSrvPrivateKey, err := pkg.GetElementFromKeySet(keySet, kid)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return nil, err
	}

	// JWE decryption using private key of oauth server
	decryptedMsg, err := pkg.DecryptJWE(credential, authSrvPrivateKey.Key)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return nil, err
	}

	// JWS Verification using client's public key
	verifiedMsg, err := pkg.VerifyJWSUsingEmbeddedKey(decryptedMsg, headerChecker, payloadChecker)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return nil, err
	}

	return verifiedMsg, nil
}

func (h *Handler) removeClientMetadataFromSession(r *http.Request) {
	session := nSession.GetSession(r)
	session.Delete(ClientsMetadataSessionKey)
}

func checkAuthUserPayload(json map[string]interface{}) error {
	fields := []string{"challenge", "client_id", "username", "password"}
	return checkRequired(fields, json)
}

func checkResetPasswordPayload(json map[string]interface{}) error {
	fields := []string{"code", "newPassword"}
	return checkRequired(fields, json)
}

func checkRequired(fields []string, json map[string]interface{}) error {
	for _, v := range fields {
		if _, ok := json[v]; !ok {
			return errors.WithStack(fosite.ErrInvalidRequest.WithDebug(v + " is missing"))
		}
	}
	return nil
}
