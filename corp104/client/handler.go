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
	"fmt"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/spf13/viper"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"os"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/pagination"
	"github.com/pkg/errors"
)

type Handler struct {
	Manager         Manager
	H               herodot.Writer
	Validator       *Validator
	KeyManager      jwk.Manager
	IssuerURL       string
	offlineJWKSName string
}

const (
	ClientsHandlerPath = "/clients"

	ClientsMetadataSessionKey   = "client_metadata"
	ClientsCommitCodeSessionKey = "commit_code"
)

func NewHandler(
	manager Manager,
	h herodot.Writer,
	defaultClientScopes []string,
	subjectTypes []string,
	keyManager jwk.Manager,
	issuerURL string,
	offlineJWKSName string,
) *Handler {
	return &Handler{
		Manager:         manager,
		H:               h,
		Validator:       NewValidator(defaultClientScopes, subjectTypes),
		KeyManager:      keyManager,
		IssuerURL:       issuerURL,
		offlineJWKSName: offlineJWKSName,
	}
}

func (h *Handler) SetRoutes(r *httprouter.Router) {
	r.GET(ClientsHandlerPath, h.List)
	r.PUT(ClientsHandlerPath, h.Put)
	r.PUT(ClientsHandlerPath+"/commit", h.Commit)
	r.GET(ClientsHandlerPath+"/:id", h.checkClientCredentials(h.Get))
	r.DELETE(ClientsHandlerPath+"/:id", h.checkClientCredentials(h.Delete))
}

// swagger:route PUT /clients oAuth2 putOAuth2Client
//
// Create or update an OAuth 2.0 Client
//
// Create or update an existing OAuth 2.0 Client.
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
func (h *Handler) Put(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	bodyMap, err := pkg.GetJWTMapFromRequestBody(r)
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	// Get payload
	jweToken := ""
	swStatement := bodyMap["software_statement"]
	if swStatement != nil {
		jweToken = swStatement.(string)
	}

	decryptedMsg, authSrvPrivateKey, err := h.decryptJWE(r.Context(), []byte(jweToken))
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	h.processSoftwareStatement(w, r, decryptedMsg, authSrvPrivateKey)
}

// swagger:route PUT /clients oAuth2 commitOAuth2Client
//
// Create or update an OAuth 2.0 Client
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
func (h *Handler) Commit(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	bodyMap := convertJsonBodyToMap(r)
	commitCode := bodyMap["commit_code"]
	if commitCode == "" || commitCode != getSessionValue(r, ClientsCommitCodeSessionKey) {
		h.H.WriteError(w, r, pkg.NewError(http.StatusUnauthorized, "invalid commit code"))
		return
	}

	// get metadata from session and check client should not be public client
	metadata := getSessionValue(r, ClientsMetadataSessionKey)
	if metadata == "" {
		h.H.WriteError(w, r, pkg.NewBadRequestError("metadata not found"))
		return
	}
	var c Client
	err := json.Unmarshal([]byte(metadata), &c)
	if err != nil {
		h.H.WriteError(w, r, pkg.NewBadRequestError("invalid metadata"))
		return
	}
	if c.IsPublic() {
		h.H.WriteError(w, r, pkg.NewBadRequestError("confidential client only"))
		return
	}
	// commit client to database
	oc, _ := h.Manager.GetConcreteClient(r.Context(), c.ClientID)
	if oc != nil {
		if err = h.Manager.UpdateClient(r.Context(), &c); err != nil {
			h.H.WriteError(w, r, errors.New("failed to update metadata: "+err.Error()))
			return
		}
	} else {
		plainSecret, err := h.createActualClient(r.Context(), &c)
		if err != nil {
			h.H.WriteError(w, r, errors.New("failed to commit metadata: "+err.Error()))
			return
		}
		c.Secret = plainSecret
	}

	// remove session values
	removeSessionValue(r, ClientsMetadataSessionKey)
	removeSessionValue(r, ClientsCommitCodeSessionKey)

	// return location & signed_client_credentials
	authSrvPrivateKey, err := h.getOfflinePrivateJWK(r.Context())
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}
	resp, err := h.createCommitResponse(authSrvPrivateKey, &c)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	h.H.WriteCode(w, r, http.StatusOK, &resp)
}

/*
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
*/

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

func (h *Handler) processSoftwareStatement(w http.ResponseWriter, r *http.Request, swStatementJWS []byte, authSrvPrivateKey *jose.JSONWebKey) {
	stmt, _, err := h.validateSoftwareStatement(swStatementJWS)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	c := &stmt.Client
	if c.IsPublic() {
		if _, err := h.createActualClient(r.Context(), c); err != nil {
			h.H.WriteError(w, r, err)
			return
		}
	}
	cBuf, err := json.Marshal(&c)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	saveSessionValue(r, ClientsMetadataSessionKey, string(cBuf))

	signedClientID, err := h.createSignedClientID(authSrvPrivateKey, c.GetID())
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	resp := map[string]string{"signed_client_id": signedClientID}

	if c.IsPublic() {
		h.H.WriteCreated(w, r, ClientsHandlerPath+"/"+c.GetID(), &resp)
	} else {
		commitCode := uuid.New()
		if viper.GetBool("TEST_MODE") {
			os.Setenv("COMMIT_CODE", commitCode)
		}
		saveSessionValue(r, ClientsCommitCodeSessionKey, commitCode)
		//TODO: Send email to user

		h.H.WriteCode(w, r, http.StatusAccepted, &resp)
	}
}

func (h *Handler) validateSoftwareStatement(swStatementJWS []byte) (*SoftwareStatement, []byte, error) {
	// JWS Verification using client's public key
	verifiedMsg, err := pkg.VerifyJWSUsingEmbeddedKey(swStatementJWS, h.validateClientMetadataHeader, nil)
	if err != nil {
		return nil, nil, err
	}

	var stmt SoftwareStatement

	if err := json.Unmarshal(verifiedMsg, &stmt); err != nil {
		return nil, verifiedMsg, err
	}

	if err := h.Validator.Validate(&stmt.Client); err != nil {
		return nil, verifiedMsg, err
	}

	if !stmt.Client.IsPublic() { // authentication required for confidential client
		if err := h.Validator.validateAuthentication(stmt.Authentication); err != nil {
			return nil, verifiedMsg, err
		}
	}

	return &stmt, verifiedMsg, nil
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

func (h *Handler) createSignedClientID(authSrvPrivateKey *jose.JSONWebKey, clientId string) (string, error) {
	claims := make(map[string]string)
	claims["client_id"] = clientId

	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return "", err
	}

	return responseJwt, nil
}

func (h *Handler) createCommitResponse(authSrvPrivateKey *jose.JSONWebKey, c *Client) (*CommitResponse, error) {
	claims := make(map[string]string)
	claims["client_id"] = c.ClientID
	claims["client_secret"] = c.Secret

	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return nil, errors.New("failed to create response: " + err.Error())
	}
	location := strings.TrimRight(h.IssuerURL, "/") + ClientsHandlerPath + "/" + c.ClientID
	return &CommitResponse{Location: location, SignedClientCredentials: responseJwt}, nil
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
	// Get offline JWKS
	keySet, err := h.getOfflineJWKS(ctx)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	// Get private key of oauth server (only offline keys are valid)
	keys := keySet.Key(kid)
	if keys == nil || len(keys) == 0 {
		pubKeyId := strings.Replace(kid, "private", "public", 1)
		return nil, nil, pkg.NewBadRequestError(fmt.Sprintf("invalid offline public key (%s)", pubKeyId))
	}
	authSrvPrivateKey := &keys[0]
	// JWE decryption using private key of oauth server
	decryptedMsg, err := pkg.DecryptJWE(compactJwe, authSrvPrivateKey.Key)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return decryptedMsg, authSrvPrivateKey, nil
}

func (h *Handler) getOfflineJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return h.KeyManager.GetKeySet(ctx, h.offlineJWKSName)
}

func (h *Handler) getOfflinePrivateJWK(ctx context.Context) (*jose.JSONWebKey, error) {
	jwks, err := h.getOfflineJWKS(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range jwks.Keys {
		if k.Use == "sig" && strings.HasPrefix(k.KeyID, "private:") {
			return &k, nil
		}
	}
	return nil, errors.New("offline private key not found")
}
