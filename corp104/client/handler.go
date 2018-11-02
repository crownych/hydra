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
	"encoding/json"
	"github.com/goincremental/negroni-sessions"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/pkg"
	"github.com/ory/hydra/rand/sequence"
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
	// Get software_statement from payload
	swStatement, err := pkg.GetJWTValueFromRequestBody(r, "software_statement")
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	// Extract kid from JWE header
	kid, err := pkg.ExtractKidFromJWE(swStatement)
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
	decryptedMsg, err := jwe.Decrypt(swStatement, jwa.ECDH_ES_A256KW, authSrvPrivateKey.Key)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	// JWS Verification using client's public key
	verifiedMsg, err := pkg.VerifyJWS(decryptedMsg, checkClientMetadata, nil)
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

	// TODO: 待建立 AD 登入驗證 Endpoint 時, 再將儲存動作移至該 Endpoint 中 (Confidential client only)
	if len(c.Secret) == 0 {
		secret, err := sequence.RuneSequence(12, []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.~"))
		if err != nil {
			h.H.WriteError(w, r, errors.WithStack(err))
			return
		}
		c.Secret = string(secret)
	}

	if err := h.Manager.CreateClient(r.Context(), &c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	// Save client metadata to session
	saveClientMetadataToSession(r, string(verifiedMsg))

	// Create registration response
	registrationResponse, err := createRegistrationResponse(authSrvPrivateKey, c.GetID())
	if err := h.Validator.Validate(&c); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.WriteCreated(w, r, ClientsHandlerPath+"/"+c.GetID(), registrationResponse)
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

func checkClientMetadata(json map[string]interface{}) error {

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

func saveClientMetadataToSession(r *http.Request, metadata string) {
	session := sessions.GetSession(r)
	session.Set("client_metadata", metadata)
}

func createRegistrationResponse(authSrvPrivateKey *jose.JSONWebKey, clientId string) (*RegistrationResponse, error) {
	claims := make(map[string]string)
	claims["client_id"] = clientId

	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return nil, err
	}

	return &RegistrationResponse{SignedClientId: responseJwt}, nil
}