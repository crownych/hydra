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

package client

import (
	"context"
	"encoding/json"
	"github.com/goincremental/negroni-sessions"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/pkg"
	"github.com/spf13/viper"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/pagination"
	"github.com/pkg/errors"
)

type Handler struct {
	Manager   Manager
	H         herodot.Writer
	Validator *Validator
	KeyManager jwk.Manager
}

const (
	ClientsHandlerPath = "/register"

	ClientsMetadataSessionKey = "client_metadata"

	// JSON fields
	SoftwareStatementField = "software_statement"
	SignedCredentialsField = "signed_credentials"
)

func NewHandler(
	manager Manager,
	h herodot.Writer,
	defaultClientScopes []string,
	subjectTypes []string,
	keyManager jwk.Manager,
) *Handler {
	return &Handler{
		Manager:   manager,
		H:         h,
		Validator: NewValidator(defaultClientScopes, subjectTypes),
		KeyManager: keyManager,
	}
}

func (h *Handler) SetRoutes(r *httprouter.Router) {
	r.GET(ClientsHandlerPath, h.List)
	r.POST(ClientsHandlerPath, h.Create)
	r.GET(ClientsHandlerPath+"/:id", h.checkClientCredentials(h.Get))
	r.PUT(ClientsHandlerPath+"/:id", h.checkClientCredentials(h.Update))
	r.DELETE(ClientsHandlerPath+"/:id", h.checkClientCredentials(h.Delete))
}

// swagger:route POST /clients oAuth2 createOAuth2Client
//
// Create an OAuth 2.0 client
//
// Create a new OAuth 2.0 client If you pass `client_secret` the secret will be used, otherwise a random secret will be generated. The secret will be returned in the response and you will not be able to retrieve it later on. Write the secret down and keep it somwhere safe.
//
// OAuth 2.0 clients are used to perform OAuth 2.0 and OpenID Connect flows. Usually, OAuth 2.0 clients are generated for applications which want to consume your OAuth 2.0 or OpenID Connect capabilities. To manage ORY Hydra, you will need an OAuth 2.0 Client as well. Make sure that this endpoint is well protected and only callable by first-party components.
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
//       200: oAuth2Client
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	bodyMap, err := pkg.GetJWTMapFromRequestBody(r)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	isConfidential := false

	// Get payload
	jweToken := ""
	swStatement := bodyMap[SoftwareStatementField]
	if swStatement != nil {
		jweToken = swStatement.(string)
	} else {
		signedCredential := bodyMap[SignedCredentialsField]
		if signedCredential != nil {
			jweToken = signedCredential.(string)
			isConfidential = true
		}
	}

	decryptedMsg, authSrvPrivateKey, err := h.decryptJWE(r.Context(), []byte(jweToken))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if isConfidential {
		h.processSignedCredentials(w, r, decryptedMsg, authSrvPrivateKey)
	} else {
		h.processSoftwareStatement(w, r, decryptedMsg, authSrvPrivateKey)
	}
}

// swagger:route PUT /clients/{id} oAuth2 updateOAuth2Client
//
// Update an OAuth 2.0 Client
//
// Update an existing OAuth 2.0 Client. If you pass `client_secret` the secret will be updated and returned via the API. This is the only time you will be able to retrieve the client secret, so write it down and keep it safe.
//
// OAuth 2.0 clients are used to perform OAuth 2.0 and OpenID Connect flows. Usually, OAuth 2.0 clients are generated for applications which want to consume your OAuth 2.0 or OpenID Connect capabilities. To manage ORY Hydra, you will need an OAuth 2.0 Client as well. Make sure that this endpoint is well protected and only callable by first-party components.
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
//       200: oAuth2Client
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	swStatement, err := pkg.GetJWTValueFromRequestBody(r, SoftwareStatementField)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	decryptedMsg, _, err := h.decryptJWE(r.Context(), swStatement)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	c, _, err := h.validateSoftwareStatement(decryptedMsg)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	var secret string
	if len(c.Secret) > 0 {
		err := validateClientSecret(c.Secret)
		if err != nil {
			h.H.WriteError(w, r, err)
			return
		}
		secret = c.Secret
	}

	if c.ClientID != ps.ByName("id") {
		h.H.WriteError(w, r, err)
		return
	}

	if err := h.Validator.Validate(c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if err := h.Manager.UpdateClient(r.Context(), c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	c.Secret = secret
	h.H.Write(w, r, &c)
}

// swagger:route GET /clients oAuth2 listOAuth2Clients
//
// List OAuth 2.0 Clients
//
// This endpoint lists all clients in the database, and never returns client secrets.
//
// OAuth 2.0 clients are used to perform OAuth 2.0 and OpenID Connect flows. Usually, OAuth 2.0 clients are generated for applications which want to consume your OAuth 2.0 or OpenID Connect capabilities. To manage ORY Hydra, you will need an OAuth 2.0 Client as well. Make sure that this endpoint is well protected and only callable by first-party components.
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
//       200: oAuth2ClientList
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) List(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	limit, offset := pagination.Parse(r, 100, 0, 500)
	c, err := h.Manager.GetClients(r.Context(), limit, offset)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	clients := make([]Client, len(c))
	k := 0
	for _, cc := range c {
		clients[k] = cc
		clients[k].Secret = ""
		k++
	}

	h.H.Write(w, r, clients)
}

// swagger:route GET /clients/{id} oAuth2 getOAuth2Client
//
// Get an OAuth 2.0 Client.
//
// Get an OAUth 2.0 client by its ID. This endpoint never returns passwords.
//
// OAuth 2.0 clients are used to perform OAuth 2.0 and OpenID Connect flows. Usually, OAuth 2.0 clients are generated for applications which want to consume your OAuth 2.0 or OpenID Connect capabilities. To manage ORY Hydra, you will need an OAuth 2.0 Client as well. Make sure that this endpoint is well protected and only callable by first-party components.
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
//       200: oAuth2Client
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	c, err := h.Manager.GetConcreteClient(r.Context(), id)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	c.Secret = ""
	h.H.Write(w, r, c)
}

// swagger:route DELETE /clients/{id} oAuth2 deleteOAuth2Client
//
// Deletes an OAuth 2.0 Client
//
// Delete an existing OAuth 2.0 Client by its ID.
//
// OAuth 2.0 clients are used to perform OAuth 2.0 and OpenID Connect flows. Usually, OAuth 2.0 clients are generated for applications which want to consume your OAuth 2.0 or OpenID Connect capabilities. To manage ORY Hydra, you will need an OAuth 2.0 Client as well. Make sure that this endpoint is well protected and only callable by first-party components.
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
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	if err := h.Manager.DeleteClient(r.Context(), id); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) validateSoftwareStatement(swStatementJWS []byte) (*Client, []byte, error) {
	// JWS Verification using client's public key
	verifiedMsg, err := pkg.VerifyJWSUsingEmbeddedKey(swStatementJWS, h.validateClientMetadataHeader, nil)
	if err != nil {
		return nil, nil, err
	}

	var c Client

	if err := json.Unmarshal(verifiedMsg, &c); err != nil {
		return nil, verifiedMsg, err
	}

	if err := h.Validator.Validate(&c); err != nil {
		return nil, verifiedMsg, err
	}
	return &c, verifiedMsg, nil
}

func (h *Handler) processSoftwareStatement(w http.ResponseWriter, r *http.Request, swStatementJWS []byte, authSrvPrivateKey *jose.JSONWebKey) {
	c, verifiedMsg, err := h.validateSoftwareStatement(swStatementJWS)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if c.IsPublic() {
		// Save client to storage
		if _, err := h.createActualClient(r.Context(), c); err != nil {
			h.H.WriteError(w, r, err)
			return
		}
	}

	// Save client metadata to session
	h.saveClientMetadataToSession(r, string(verifiedMsg))

	// create registration response
	registrationResponse, err := h.createPublicClientResponse(authSrvPrivateKey, c.GetID())

	if c.IsPublic() {
		h.H.WriteCreated(w, r, ClientsHandlerPath+"/"+c.GetID(), registrationResponse)
	} else {
		h.H.Write(w, r, registrationResponse)
	}
}

func (h *Handler) processSignedCredentials(w http.ResponseWriter, r *http.Request, signedCredentialsJWS []byte, authSrvPrivateKey *jose.JSONWebKey) {
	// JWS Verification using client's public key
	_, err := pkg.VerifyJWSUsingEmbeddedKey(signedCredentialsJWS, nil, h.validateSignedCredentialsPayload)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	// get client_metadata from session
	clientMetadata := h.getClientMetadataFromSession(r)

	if clientMetadata == "" {
		h.H.WriteError(w, r, pkg.NewBadRequestError("client_metadata not found in session"))
		return
	}

	var c Client

	if err := json.Unmarshal([]byte(clientMetadata), &c); err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	if err := h.Validator.Validate(&c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if c.IsPublic() {
		h.H.WriteError(w, r, pkg.NewBadRequestError("public client does not support this operation"))
		return
	}

	// create actual client
	plainSecret, err := h.createActualClient(r.Context(), &c)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	// remove client metadata from session
	h.removeClientMetadataFromSession(r)

	// create save registration response
	saveRegistrationResponse, err := h.createConfidentialClientResponse(authSrvPrivateKey, c.GetID(), plainSecret)
	if err := h.Validator.Validate(&c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.WriteCreated(w, r, ClientsHandlerPath+"/"+c.GetID(), saveRegistrationResponse)
}

func (h *Handler) createActualClient(ctx context.Context, c *Client) (string, error) {
	if c.IsPublic() {
		c.Secret = ""
	}

	origSecret := c.Secret
	if len(c.Secret) == 0 {
		secret, err := pkg.GenerateSecret(26)
		if err != nil {
			return origSecret, err
		}
		c.Secret = string(secret)
	}

	err := validateClientSecret(c.Secret)
	if err != nil {
		c.Secret = origSecret
		return origSecret, err
	}
	plainSecret := c.Secret

	if err := h.Manager.CreateClient(ctx, c); err != nil {
		c.Secret = origSecret
		return origSecret, err
	}

	return plainSecret, nil
}

func (h *Handler) validateClientMetadataHeader(json map[string]interface{}) error {

	// validate `typ` should be `client-metadata+jwt` or `application/client-metadata+jwt`
	typ, found := json["typ"]
	if !found {
		return errors.New("`typ` not found in JOSE header")
	}
	if typ, ok := typ.(string); ok {
		if !strings.HasPrefix(typ, "application/") {
			typ = "application/" + typ
		}
		if typ != "application/client-metadata+jwt" {
			return errors.New("`typ` should be \"application/client-metadata+jwt\"")
		}
	} else {
		return errors.New("Invalid `typ` declaration")
	}

	return nil
}

func (h *Handler) validateSignedCredentialsPayload(credentials map[string]interface{}) error {
	user := credentials["user"]
	pwd := credentials["pwd"]
	if user == nil || pwd == nil {
		return errors.New("invalid signed credentials")
	}
	adLoginURL := viper.GetString("AD_LOGIN_URL")
	return validateADUser(adLoginURL, user.(string), pwd.(string))
}

func (h *Handler) saveClientMetadataToSession(r *http.Request, metadata string) {
	session := sessions.GetSession(r)
	session.Set(ClientsMetadataSessionKey, metadata)
}

func (h *Handler) getClientMetadataFromSession(r *http.Request) string {
	session := sessions.GetSession(r)
	data := session.Get(ClientsMetadataSessionKey)
	if data == nil {
		return ""
	}
	return data.(string)
}

func (h *Handler) removeClientMetadataFromSession(r *http.Request) {
	session := sessions.GetSession(r)
	session.Delete(ClientsMetadataSessionKey)
}

func (h *Handler) createPublicClientResponse(authSrvPrivateKey *jose.JSONWebKey, clientId string) (*RegistrationResponse, error) {
	claims := make(map[string]string)
	claims["client_id"] = clientId

	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return nil, err
	}

	return &RegistrationResponse{SignedClientId: responseJwt}, nil
}

func (h *Handler) createConfidentialClientResponse(authSrvPrivateKey *jose.JSONWebKey, clientId string, clientSecret string) (*SaveRegistrationResponse, error) {
	claims := make(map[string]string)
	claims["client_id"] = clientId
	claims["client_secret"] = clientSecret

	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return nil, err
	}

	return &SaveRegistrationResponse{SignedCredentials: responseJwt}, nil
}

func (h *Handler) checkClientCredentials(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		clientID, clientSecret, hasAuth := r.BasicAuth()

		pass := false
		if hasAuth {
			_, err := h.Manager.Authenticate(r.Context(), clientID, []byte(clientSecret))
			if err == nil {
				pass = true
			}
		}

		if pass {
			next(w, r, ps)
		} else {
			// Request Basic Authentication otherwise
			w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			h.H.WriteError(w, r, pkg.ErrUnauthorized)
		}
	}
}

func (h *Handler) decryptJWE(ctx context.Context, compactJwe []byte) ([]byte, *jose.JSONWebKey, error) {
	if compactJwe == nil || len(compactJwe) == 0 {
		return nil, nil, pkg.NewBadRequestError("empty payload")
	}

	// Extract kid from JWE header
	kid, err := pkg.ExtractKidFromJWE(compactJwe)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	// Extract key set
	keySet, err := h.KeyManager.GetKeysById(ctx, kid)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	// Get private key of oauth server
	authSrvPrivateKey, err := pkg.GetElementFromKeySet(keySet, kid)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	// JWE decryption using private key of oauth server
	decryptedMsg, err := pkg.DecryptJWE(compactJwe, authSrvPrivateKey.Key)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return decryptedMsg, authSrvPrivateKey, nil
}