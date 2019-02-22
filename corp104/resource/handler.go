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

package resource

import (
	"context"
	"encoding/json"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/pkg"
	"github.com/ory/pagination"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/square/go-jose.v2"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
)

const (
	ResourcesHandlerPath = "/resources"

	ResourceMetadataSessionKey   = "resource_metadata"
	ResourceCommitCodeSessionKey = "commit_code"
)

type Handler struct {
	Manager         Manager
	H               herodot.Writer
	Validator       *Validator
	KeyManager      jwk.Manager
	IssuerURL       string
	offlineJWKSName string
}

func NewHandler(
	manager Manager,
	h herodot.Writer,
	keyManager jwk.Manager,
	issuerURL string,
	offlineJWKSName string,
) *Handler {
	return &Handler{
		Manager:         manager,
		H:               h,
		Validator:       NewValidator(),
		KeyManager:      keyManager,
		IssuerURL:       issuerURL,
		offlineJWKSName: offlineJWKSName,
	}
}

func (h *Handler) SetRoutes(frontend, backend *httprouter.Router, corsMiddleware func(http.Handler) http.Handler) {
	frontend.Handler("OPTIONS", ResourcesHandlerPath, corsMiddleware(http.HandlerFunc(h.handleOptions)))
	frontend.Handler("GET", ResourcesHandlerPath, corsMiddleware(http.HandlerFunc(h.List)))
	frontend.PUT(ResourcesHandlerPath, h.Put)
	frontend.PUT(ResourcesHandlerPath+"/commit", h.Commit)
	frontend.Handler("OPTIONS", ResourcesHandlerPath+"/:urn", corsMiddleware(http.HandlerFunc(h.handleOptions)))
	frontend.Handler("GET", ResourcesHandlerPath+"/:urn", corsMiddleware(http.HandlerFunc(h.Get)))
	backend.DELETE(ResourcesHandlerPath+"/:urn", h.Delete)
}

// swagger:route PUT /resources resource createResource
//
// Create a new Resource
//
// This endpoint is able to register an OAuth 2.0 resource
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
//       202: Accepted and need user confirmation
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Put(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	bodyMap, err := pkg.GetMapFromRequestBody(r)
	if err != nil {
		h.H.WriteError(w, r, pkg.NewBadRequestError("invalid content: " + err.Error()))
		return
	}

	// Get payload
	jweToken := ""
	statement := bodyMap["resource_statement"]
	if statement != nil {
		jweToken = statement.(string)
	}

	// Get offline JWKS
	offlineJWKS, err := h.getOfflineJWKS(r.Context())
	if err != nil {
		h.H.WriteError(w, r, "offline JWKS not found")
		return
	}

	// Decrypt JWE
	decryptedMsg, authSrvPrivateKey, err := pkg.DecryptJWEByKid([]byte(jweToken), offlineJWKS)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	// Process resource statement and response
	h.processResourceStatement(w, r, decryptedMsg, authSrvPrivateKey)
}

// swagger:route PUT /resources/commit resource commitResource
//
// Commit to persist a Resource
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
//       200: location
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Commit(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	invalidCommitCode := true
	buf, _ := pkg.GetValueFromRequestBody(r, "commit_code")
	if buf != nil && len(buf) > 0 {
		commitCode := string(buf)
		if commitCode == pkg.GetSessionValue(r, ResourceCommitCodeSessionKey) {
			invalidCommitCode = false
		}
	}
	if invalidCommitCode {
		h.H.WriteError(w, r, pkg.NewError(http.StatusUnauthorized, "invalid commit code"))
		return
	}

	// get metadata from session
	metadata := pkg.GetSessionValue(r, ResourceMetadataSessionKey)
	if metadata == "" {
		h.H.WriteError(w, r, pkg.NewBadRequestError("metadata not found"))
		return
	}
	var c Resource
	err := json.Unmarshal([]byte(metadata), &c)
	if err != nil {
		h.H.WriteError(w, r, pkg.NewBadRequestError("invalid metadata"))
		return
	}

	// commit resource to database
	oc, _ := h.Manager.GetResource(r.Context(), c.GetUrn())
	if oc != nil {
		if err = h.Manager.UpdateResource(r.Context(), &c); err != nil {
			h.H.WriteError(w, r, errors.New("failed to update metadata: "+err.Error()))
			return
		}
	} else {
		err := h.Manager.CreateResource(r.Context(), &c)
		if err != nil {
			h.H.WriteError(w, r, errors.New("failed to commit metadata: "+err.Error()))
			return
		}
	}

	// remove session values
	pkg.RemoveSessionValue(r, ResourceMetadataSessionKey)
	pkg.RemoveSessionValue(r, ResourceCommitCodeSessionKey)

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

// swagger:route GET /resources oAuth2 resources
//
// Get OAuth 2.0 Resources
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: resourceList
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination.Parse(r, 100, 0, 500)
	c, err := h.Manager.GetResources(r.Context(), limit, offset)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	resources := make([]Resource, len(c))
	k := 0
	for _, cc := range c {
		resources[k] = cc
		k++
	}

	authSrvPrivateKey, err := h.getOfflinePrivateJWK(r.Context())
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	claims := map[string]interface{}{
		"iss":       h.IssuerURL,
		"iat":       time.Now().UTC().Unix(),
		"resources": resources,
	}
	signedResources, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	resp := map[string]string{"signed_resources": signedResources}
	h.H.Write(w, r, resp)
}

// swagger:route GET /resources/{urn} resource getResource
//
// Retrieve a resource
//
// This endpoint can be used to retrieve Resource stored in ORY Hydra.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: Resource
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	urn := strings.TrimPrefix(r.URL.Path, ResourcesHandlerPath+"/")
	c, err := h.Manager.GetResource(r.Context(), urn)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.Write(w, r, c)
}

// swagger:route DELETE /resources/{urn} oAuth2 deleteOAuth2Resource
//
// Deletes an OAuth 2.0 Resource
//
// Delete an existing OAuth 2.0 Resource by its URN.
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
	var urn = ps.ByName("urn")

	if err := h.Manager.DeleteResource(r.Context(), urn); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) processResourceStatement(w http.ResponseWriter, r *http.Request, statementJWS []byte, authSrvPrivateKey *jose.JSONWebKey) {
	stmt, _, err := h.validateResourceStatement(statementJWS)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	c := &stmt.Resource
	c.Urn = c.GetUrn()
	cBuf, err := json.Marshal(&c)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	pkg.SaveSessionValue(r, ResourceMetadataSessionKey, string(cBuf))

	signedResourceUrn, err := h.createSignedResourceUrn(authSrvPrivateKey, c.GetUrn())
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	resp := map[string]string{"signed_resource_urn": signedResourceUrn}

	commitCode := uuid.New()
	if viper.GetBool("TEST_MODE") {
		log.Println("resource commit code:", commitCode)
		viper.Set("COMMIT_CODE", commitCode)
	}
	pkg.SaveSessionValue(r, ResourceCommitCodeSessionKey, commitCode)

	// send email to user
	pkg.SendCommitCode(stmt.Authentication.User, "Resource註冊確認碼", commitCode)
	h.H.WriteCode(w, r, http.StatusAccepted, &resp)
}

func (h *Handler) validateResourceStatement(swStatementJWS []byte) (*ResourceStatement, []byte, error) {
	// JWS Verification using client's public key
	verifiedMsg, err := pkg.VerifyJWSUsingEmbeddedKey(swStatementJWS, h.validateResourceStatementHeader, nil)
	if err != nil {
		return nil, nil, err
	}

	var stmt ResourceStatement

	if err := json.Unmarshal(verifiedMsg, &stmt); err != nil {
		return nil, verifiedMsg, err
	}

	if strings.TrimRight(stmt.Audience, "/") != strings.TrimRight(h.IssuerURL, "/") {
		return nil, verifiedMsg, pkg.NewBadRequestError("invalid audience")
	}

	if err := h.Validator.Validate(&stmt.Resource); err != nil {
		return nil, verifiedMsg, err
	}

	if err := pkg.ValidateADUser(stmt.Authentication); err != nil {
		return nil, verifiedMsg, err
	}

	return &stmt, verifiedMsg, nil
}

func (h *Handler) validateResourceStatementHeader(json map[string]interface{}) error {

	// validate `typ` should be `client-metadata+jwt` or `application/client-metadata+jwt`
	typ, found := json["typ"]
	if !found {
		return errors.New("`typ` not found in JOSE header")
	}
	if typ, ok := typ.(string); ok {
		if !strings.HasPrefix(typ, "application/") {
			typ = "application/" + typ
		}
		if typ != "application/resource-metadata+jwt" {
			return errors.New("`typ` should be \"application/resource-metadata+jwt\"")
		}
	} else {
		return errors.New("invalid `typ` declaration")
	}

	return nil
}

func (h *Handler) createSignedResourceUrn(authSrvPrivateKey *jose.JSONWebKey, resourceUrn string) (string, error) {
	claims := map[string]interface{}{"resource_urn": resourceUrn}
	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return "", err
	}

	return responseJwt, nil
}

func (h *Handler) createCommitResponse(authSrvPrivateKey *jose.JSONWebKey, r *Resource) (*CommitResponse, error) {
	return &CommitResponse{Location: strings.TrimRight(h.IssuerURL, "/") + ResourcesHandlerPath + "/" + r.Urn}, nil
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

// This function will not be called, OPTIONS request will be handled by cors
// this is just a placeholder.
func (h *Handler) handleOptions(w http.ResponseWriter, r *http.Request) {}
