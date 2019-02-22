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

package jwk

import (
	"context"
	"encoding/json"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/spf13/viper"
	"gopkg.in/square/go-jose.v2"
	"log"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/pkg/errors"
)

const (
	IDTokenKeyName    = "openid.id-token"
	KeyHandlerPath    = "/keys"
	WellKnownKeysPath = "/jwks.json"

	KeysMetadataSessionKey   = "keys_metadata"
	KeysCommitCodeSessionKey = "commit_code"
)

type Handler struct {
	Manager       Manager
	Generators    map[string]KeyGenerator
	H             herodot.Writer
	WellKnownKeys []string
	Validator       *Validator
	IssuerURL       string
	offlineJWKSName string
}

func NewHandler(
	manager Manager,
	generators map[string]KeyGenerator,
	h herodot.Writer,
	wellKnownKeys []string,
	issuerURL string,
	offlineJWKSName string,
) *Handler {
	return &Handler{
		Manager:       manager,
		Generators:    generators,
		H:             h,
		WellKnownKeys: append(wellKnownKeys, IDTokenKeyName),
		Validator:       NewValidator(),
		IssuerURL:       issuerURL,
		offlineJWKSName: offlineJWKSName,
	}
}

func (h *Handler) GetGenerators() map[string]KeyGenerator {
	if h.Generators == nil || len(h.Generators) == 0 {
		h.Generators = map[string]KeyGenerator{
			"RS256": &RS256Generator{},
			"ES256": &ECDSA256Generator{},
			"ES512": &ECDSA512Generator{},
			"HS256": &HS256Generator{},
			"HS512": &HS512Generator{},
		}
	}
	return h.Generators
}

func (h *Handler) SetRoutes(frontend, backend *httprouter.Router, corsMiddleware func(http.Handler) http.Handler) {
	frontend.Handler("OPTIONS", WellKnownKeysPath, corsMiddleware(http.HandlerFunc(h.handleOptions)))
	frontend.Handler("GET", WellKnownKeysPath, corsMiddleware(http.HandlerFunc(h.WellKnown)))

	frontend.PUT(KeyHandlerPath, h.Put)
	frontend.PUT(KeyHandlerPath+"/commit", h.Commit)

	frontend.GET(KeyHandlerPath+"/:set/:key", h.adminADCredentialsMiddleware(h.GetKey))
	frontend.GET(KeyHandlerPath+"/:set", h.adminADCredentialsMiddleware(h.GetKeySet))

	backend.DELETE(KeyHandlerPath+"/:set/:key", h.adminADCredentialsMiddleware(h.DeleteKey))
	backend.DELETE(KeyHandlerPath+"/:set", h.adminADCredentialsMiddleware(h.DeleteKeySet))
}

// swagger:route GET /.well-known/jwks.json oAuth2 wellKnown
//
// Get Well-Known JSON Web Keys
//
// Returns metadata for discovering important JSON Web Keys. Currently, this endpoint returns the public key for verifying OpenID Connect ID Tokens.
//
// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.
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
//       200: JSONWebKeySet
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) WellKnown(w http.ResponseWriter, r *http.Request) {
	var jwks pkg.JSONWebKeySet

	for _, set := range h.WellKnownKeys {
		keys, err := h.Manager.GetActualKeySet(r.Context(), set, wellKnownJWKFilter)
		if err != nil {
			h.H.WriteError(w, r, err)
			return
		}

		keys, err = FindKeysByPrefix(keys, "public")
		if err != nil {
			h.H.WriteError(w, r, err)
			return
		}

		jwks.Keys = append(jwks.Keys, keys.Keys...)
	}

	h.H.Write(w, r, &jwks)
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
	statement := bodyMap["keys_statement"]
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
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}

	// Process keys statement and response
	h.processKeysStatement(w, r, decryptedMsg, authSrvPrivateKey)
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
		if commitCode == pkg.GetSessionValue(r, KeysCommitCodeSessionKey) {
			invalidCommitCode = false
		}
	}
	if invalidCommitCode {
		h.H.WriteError(w, r, pkg.NewError(http.StatusUnauthorized, "invalid commit code"))
		return
	}

	// get metadata from session
	metadata := pkg.GetSessionValue(r, KeysMetadataSessionKey)
	if metadata == "" {
		h.H.WriteError(w, r, pkg.NewBadRequestError("metadata not found"))
		return
	}

	var c KeysMetadata
	err := json.Unmarshal([]byte(metadata), &c)
	if err != nil {
		h.H.WriteError(w, r, pkg.NewBadRequestError("invalid metadata"))
		return
	}

	// commit keys to database
	oc, _ := h.Manager.GetActualKeySet(r.Context(), c.Set)

	if oc != nil {
		if err := h.Manager.DeleteKeySet(r.Context(), c.Set); err != nil {
			h.H.WriteError(w, r, errors.New("failed to delete key set: "+err.Error()))
			return
		}
	}

	if err = h.Manager.AddKeySet(r.Context(), c.Set, &c.JWKS); err != nil {
		h.H.WriteError(w, r, errors.New("failed to add key set: "+err.Error()))
		return
	}

	// remove session values
	pkg.RemoveSessionValue(r, KeysMetadataSessionKey)
	pkg.RemoveSessionValue(r, KeysCommitCodeSessionKey)

	// return location & signed_client_credentials
	authSrvPrivateKey, err := h.getOfflinePrivateJWK(r.Context())
	if err != nil {
		h.H.WriteError(w, r, errors.WithStack(err))
		return
	}
	resp := h.createCommitResponse(authSrvPrivateKey, &c)
	h.H.WriteCode(w, r, http.StatusOK, &resp)
}


// swagger:route GET /keys/{set}/{kid} jsonWebKey getJsonWebKey
//
// Retrieve a JSON Web Key
//
// This endpoint can be used to retrieve JWKs stored in ORY Hydra.
//
// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.
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
//       200: JSONWebKeySet
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) GetKey(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var setName = ps.ByName("set")
	var keyName = ps.ByName("key")

	keys, err := h.Manager.GetActualKey(r.Context(), setName, keyName)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.Write(w, r, keys)
}

// swagger:route GET /keys/{set} jsonWebKey getJsonWebKeySet
//
// Retrieve a JSON Web Key Set
//
// This endpoint can be used to retrieve JWK Sets stored in ORY Hydra.
//
// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.
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
//       200: JSONWebKeySet
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) GetKeySet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var setName = ps.ByName("set")

	keys, err := h.Manager.GetActualKeySet(r.Context(), setName)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	h.H.Write(w, r, keys)
}

// swagger:route DELETE /keys/{set} jsonWebKey deleteJsonWebKeySet
//
// Delete a JSON Web Key Set
//
// Use this endpoint to delete a complete JSON Web Key Set and all the keys in that set.
//
// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.
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
func (h *Handler) DeleteKeySet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var setName = ps.ByName("set")

	if err := h.Manager.DeleteKeySet(r.Context(), setName); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route DELETE /keys/{set}/{kid} jsonWebKey deleteJsonWebKey
//
// Delete a JSON Web Key
//
// Use this endpoint to delete a single JSON Web Key.
//
// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.
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
func (h *Handler) DeleteKey(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var setName = ps.ByName("set")
	var keyName = ps.ByName("key")

	if err := h.Manager.DeleteKey(r.Context(), setName, keyName); err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// This function will not be called, OPTIONS request will be handled by cors
// this is just a placeholder.
func (h *Handler) handleOptions(w http.ResponseWriter, r *http.Request) {}


func (h *Handler) processKeysStatement(w http.ResponseWriter, r *http.Request, statementJWS []byte, authSrvPrivateKey *jose.JSONWebKey) {
	stmt, _, err := h.validateKeysStatement(statementJWS)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}

	cBuf, err := json.Marshal(&stmt.Metadata)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	pkg.SaveSessionValue(r, KeysMetadataSessionKey, string(cBuf))

	signedKeys, err := h.createSignedKeys(authSrvPrivateKey, &stmt.Metadata)
	if err != nil {
		h.H.WriteError(w, r, err)
		return
	}
	resp := map[string]string{"signed_keys": signedKeys}

	commitCode := uuid.New()
	if viper.GetBool("TEST_MODE") {
		log.Println("keys commit code:", commitCode)
		viper.Set("COMMIT_CODE", commitCode)
	}
	pkg.SaveSessionValue(r, KeysCommitCodeSessionKey, commitCode)

	// send email to user
	pkg.SendCommitCode(stmt.Authentication.User, "Keys註冊確認碼", commitCode)
	h.H.WriteCode(w, r, http.StatusAccepted, &resp)
}

func (h *Handler) validateKeysStatement(keysStatementJWS []byte) (*KeysStatement, []byte, error) {
	verifiedMsg, err := pkg.VerifyJWSUsingEmbeddedKey(keysStatementJWS, h.validateKeysStatementHeader, nil)
	if err != nil {
		return nil, nil, err
	}

	var stmt KeysStatement

	if err := json.Unmarshal(verifiedMsg, &stmt); err != nil {
		return nil, verifiedMsg, err
	}

	if strings.TrimRight(stmt.Audience, "/") != strings.TrimRight(h.IssuerURL, "/") {
		return nil, verifiedMsg, pkg.NewBadRequestError("invalid audience")
	}

	// validate matadata
	if err := h.Validator.Validate(&stmt.Metadata); err != nil {
		return nil, verifiedMsg, err
	}

	// validate AD credentials
	if stmt.Authentication == nil || !h.isValidAdminUser(stmt.Authentication.User, stmt.Authentication.Pwd) {
		return nil, verifiedMsg, pkg.ErrUnauthorized
	}

	return &stmt, verifiedMsg, nil
}

func (h *Handler) validateKeysStatementHeader(json map[string]interface{}) error {
	// validate `typ` should be `keys-metadata+jwt` or `application/keys-metadata+jwt`
	typ, found := json["typ"]
	if !found {
		return errors.New("`typ` not found in JOSE header")
	}
	if typ, ok := typ.(string); ok {
		if !strings.HasPrefix(typ, "application/") {
			typ = "application/" + typ
		}
		if typ != "application/keys-metadata+jwt" {
			return errors.New("`typ` should be \"application/keys-metadata+jwt\"")
		}
	} else {
		return errors.New("invalid `typ` declaration")
	}

	return nil
}

func (h *Handler) createSignedKeys(authSrvPrivateKey *jose.JSONWebKey, metadata *KeysMetadata) (string, error) {
	signedKeys := map[string]interface{}{"set": metadata.Set}
	var records []map[string]string
	for _, key := range metadata.JWKS.Keys {
		records = append(records, map[string]string{"kid": key.KeyID})
	}
	signedKeys["jwks"] = records

	claims := map[string]interface{}{"signed_keys": signedKeys}
	responseJwt, err := pkg.GenerateResponseJWT(authSrvPrivateKey, claims)
	if err != nil {
		return "", err
	}

	return responseJwt, nil
}

func (h *Handler) createCommitResponse(authSrvPrivateKey *jose.JSONWebKey, c *KeysMetadata) *CommitResponse {
	return &CommitResponse{Location: strings.TrimRight(h.IssuerURL, "/") + KeyHandlerPath + "/" + c.Set}
}

func (h *Handler) getOfflineJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return h.Manager.GetKeySet(ctx, h.offlineJWKSName)
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

func (h *Handler) isValidAdminUser(user, pwd string) bool {
	if pkg.IsAdminUser(user) {
		err := pkg.ValidateADUser(&pkg.ADUserCredentials{User: user, Pwd: pwd})
		if err == nil {
			return true
		}
	}
	return false
}

// 檢查使用者必須是 Admin User 且 AD credentials 有效
func (h *Handler) adminADCredentialsMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		user, pwd, hasAuth := r.BasicAuth()

		pass := false
		if hasAuth && h.isValidAdminUser(user, pwd) {
			pass = true
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
