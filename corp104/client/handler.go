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
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/pkg"
	"github.com/ory/hydra/rand/sequence"
	"gopkg.in/square/go-jose.v2"
	"log"
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
	WebSessionName string
}

const (
	ClientsHandlerPath = "/register"

	ClientMetadataSessionKey = "client_metadata"

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
	//clientCredentialsMiddleware := newClientCredentialsMiddleware(h.Manager)
	r.GET(ClientsHandlerPath, h.List)
	r.POST(ClientsHandlerPath, h.Create)
	r.GET(ClientsHandlerPath+"/:id", h.Get)
	r.PUT(ClientsHandlerPath+"/:id", h.Update)
	r.DELETE(ClientsHandlerPath+"/:id", h.Delete)
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

	isSignedCredentials := false

	// Get payload
	jwePayloadStr := ""
	swStatement := bodyMap[SoftwareStatementField]
	if swStatement != nil {
		jwePayloadStr = swStatement.(string)
	} else {
		signedCredential := bodyMap[SignedCredentialsField]
		if signedCredential != nil {
			jwePayloadStr = signedCredential.(string)
			isSignedCredentials = true
		}
	}
	if jwePayloadStr == "" {
		h.H.WriteError(w, r, errors.WithStack(errors.New("empty payload")))
		return
	}

	jwePayload := []byte(jwePayloadStr)

	// Extract kid from JWE header
	kid, err := pkg.ExtractKidFromJWE(jwePayload)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}
	// Extract key set
	keySet, err := h.KeyManager.GetKeysById(r.Context(), kid)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}
	// Get private key of oauth server
	authSrvPrivateKey, err := pkg.GetElementFromKeySet(keySet, kid)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	// JWE decryption using private key of oauth server
	decryptedMsg, err := jwe.Decrypt(jwePayload, jwa.ECDH_ES_A256KW, authSrvPrivateKey.Key)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	if isSignedCredentials {
		h.processSignedCredentials(w, r, decryptedMsg, authSrvPrivateKey)
	} else {
		h.processSoftwareStatement(w, r, decryptedMsg, authSrvPrivateKey)
	}
}

func (h *Handler) processSoftwareStatement(w http.ResponseWriter, r *http.Request, swStatementJWS []byte, authSrvPrivateKey *jose.JSONWebKey) {
	// JWS Verification using client's public key
	verifiedMsg, err := pkg.VerifyJWS(swStatementJWS, h.checkClientMetadata)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	var c Client

	if err := json.Unmarshal(verifiedMsg, &c); err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	if err := h.Validator.Validate(&c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if c.IsPublic() {
		// save public client to DB
		if err := h.createActualClient(r.Context(), &c); err != nil {
			h.H.WriteError(w, r, err)
			return
		}
	}

	// Save client metadata to session
	h.saveClientMetadataToSession(r, string(verifiedMsg))

	// create registration response
	registrationResponse, err := h.createRegistrationResponse(authSrvPrivateKey, c.GetID())

	if c.IsPublic() {
		h.H.WriteCreated(w, r, ClientsHandlerPath+"/"+c.GetID(), registrationResponse)
	} else {
		h.H.Write(w, r, registrationResponse)
	}
}

func (h *Handler) processSignedCredentials(w http.ResponseWriter, r *http.Request, signedCredentialsJWS []byte, authSrvPrivateKey *jose.JSONWebKey) {
	// JWS Verification using client's public key
	verifiedMsg, err := pkg.VerifyJWS(signedCredentialsJWS, h.checkSignedCredentials)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}
	log.Println("verifiedMsg:", string(verifiedMsg))

	// get client_metadata from session
	clientMetadata := h.getClientMetadataFromSession(r)
	log.Println("client_metadata:", clientMetadata)


	if clientMetadata == "" {
		h.H.WriteError(w, r, errors.New("client_metadata not found in session"))
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
		h.H.WriteError(w, r, errors.New("public client does not support this operation"))
		return
	}

	// create actual client
	if err := h.createActualClient(r.Context(), &c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	// remove client metadata from session
	h.removeClientMetadataFromSession(r)

	// create save registration response
	saveRegistrationResponse, err := h.createSaveRegistrationResponse(authSrvPrivateKey, c.GetID(), c.Secret)
	if err := h.Validator.Validate(&c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	log.Println("saveRegistrationResponse:", saveRegistrationResponse)

	h.H.WriteCreated(w, r, ClientsHandlerPath+"/"+c.GetID(), saveRegistrationResponse)
}

func (h *Handler) createActualClient(ctx context.Context, c *Client) error {
	if len(c.Secret) == 0 {
		secret, err := sequence.RuneSequence(12, []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.~"))
		if err != nil {
			return err
		}
		c.Secret = string(secret)
	}

	if err := h.Manager.CreateClient(ctx, c); err != nil {
		return err
	}

	return nil
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
	var c Client

	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	var secret string
	if len(c.Secret) > 0 {
		secret = c.Secret
	}

	c.ClientID = ps.ByName("id")
	if err := h.Validator.Validate(&c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	if err := h.Manager.UpdateClient(r.Context(), &c); err != nil {
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

func (h *Handler) checkClientMetadata(json map[string]interface{}) error {

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

func (h *Handler) checkSignedCredentials(json map[string]interface{}) error {
	return nil
}

func (h *Handler) saveClientMetadataToSession(r *http.Request, metadata string) {
	session := sessions.GetSession(r)
	session.Set(ClientMetadataSessionKey, metadata)
}

func (h *Handler) getClientMetadataFromSession(r *http.Request) string {
	session := sessions.GetSession(r)
	data := session.Get(ClientMetadataSessionKey)
	if data == nil {
		return ""
	}
	return data.(string)
}

func (h *Handler) removeClientMetadataFromSession(r *http.Request) {
	session := sessions.GetSession(r)
	session.Delete(ClientMetadataSessionKey)
}

func (h *Handler) createRegistrationResponse(authSrvPrivateKey *jose.JSONWebKey, clientId string) (*RegistrationResponse, error) {
	claims := make(map[string]string)
	claims["client_id"] = clientId

	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return nil, err
	}

	return &RegistrationResponse{SignedClientId: responseJwt}, nil
}

func (h *Handler) createSaveRegistrationResponse(authSrvPrivateKey *jose.JSONWebKey, clientId string, clientSecret string) (*SaveRegistrationResponse, error) {
	claims := make(map[string]string)
	claims["client_id"] = clientId
	claims["client_secret"] = clientSecret

	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return nil, err
	}

	return &SaveRegistrationResponse{SignedCredentials: responseJwt}, nil
}
