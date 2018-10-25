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

package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/pborman/uuid"
	"github.com/urfave/negroni"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/hydra/corp104/client"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestPublicClient(prefix string, pubJwk hydra.JsonWebKey) hydra.OAuth2Client {
	return hydra.OAuth2Client{
		ClientId:                  "1234",
		ClientName:                prefix + "name",
		ClientUri:                 prefix + "uri",
		Contacts:                  []string{prefix + "peter", prefix + "pan"},
		GrantTypes:                []string{"implicit"},
		ResponseTypes:             []string{"token", "id_token"},
		RedirectUris:              []string{prefix + "redirect-url", prefix + "redirect-uri"},
		SoftwareId:				   prefix + "SPA",
		SoftwareVersion: 		   prefix + "0.0.1",
		IdTokenSignedResponseAlg:  "ES256",
		RequestObjectSigningAlg:   "ES256",
	}
}

func createTestConfidentialClient(prefix string, pubJwk hydra.JsonWebKey) hydra.OAuth2Client {
	return hydra.OAuth2Client{
		ClientId:                  "5678",
		ClientName:                prefix + "name",
		ClientUri:                 prefix + "uri",
		Contacts:                  []string{prefix + "peter", prefix + "pan"},
		GrantTypes:                []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		TokenEndpointAuthMethod:   "private_key_jwt",
		SoftwareId:				   prefix + "client1",
		SoftwareVersion: 		   prefix + "0.0.1",
		Jwks:					   &hydra.JsonWebKeySet{Keys: []hydra.JsonWebKey{pubJwk}},
	}
}

func TestClientSDK(t *testing.T) {
	keyManager := &jwk.MemoryManager{Keys: map[string]*jose.JSONWebKeySet{}}
	authSrvJwks, err := (&jwk.ECDSA256Generator{}).Generate(uuid.New(), "sig")
	require.NoError(t, err)
	require.NoError(t, keyManager.AddKeySet(context.TODO(), "", authSrvJwks))

	manager := client.NewMemoryManager(nil)
	handler := client.NewHandler(manager, herodot.NewJSONWriter(nil), []string{"openid"}, []string{"public"}, keyManager)

	router := httprouter.New()
	handler.SetRoutes(router)
	mockOAuthServer(router, authSrvJwks)
	n := negroni.New()
	store := cookiestore.New()
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   0,
		Secure:   false,
		HTTPOnly: true,
	})
	n.Use(sessions.Sessions("sid", store))
	n.UseHandler(router)

	server := httptest.NewServer(n)

	c := hydra.NewOAuth2ApiWithBasePath(server.URL)

	// client key pair
	cPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cPrivJwk := &hydra.JsonWebKey{
		Alg: "ES256",
		Crv: "P-256",
		Use: "sig",
		Kty: "EC",
		X: base64.RawURLEncoding.EncodeToString(cPrivKey.X.Bytes()),
		Y: base64.RawURLEncoding.EncodeToString(cPrivKey.Y.Bytes()),
		D: base64.RawURLEncoding.EncodeToString(cPrivKey.D.Bytes()),
	}
	cPubJwk := hydra.JsonWebKey{
		Alg: "ES256",
		Crv: "P-256",
		Use: "sig",
		Kty: "EC",
		X: base64.RawURLEncoding.EncodeToString(cPrivKey.X.Bytes()),
		Y: base64.RawURLEncoding.EncodeToString(cPrivKey.Y.Bytes()),
	}

	t.Run("case=public client is created", func(t *testing.T) {
		createClient := createTestPublicClient("", cPubJwk)

		// returned client is correct on Create
		result, response, err := c.CreateOAuth2Client(createClient, cPrivJwk)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusCreated, response.StatusCode, "%s", response.Payload)
		assert.NotEmpty(t, result)
	})

	t.Run("case=confidential client is created", func(t *testing.T) {
		createClient := createTestConfidentialClient("", cPubJwk)

		// returned client is correct on Create
		result, response, err := c.CreateOAuth2Client(createClient, cPrivJwk)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusCreated, response.StatusCode, "%s", response.Payload)
		assert.NotEmpty(t, result)
	})
}

func mockOAuthServer(r *httprouter.Router, jwks *jose.JSONWebKeySet) {
	r.GET("/jwks.json", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "application/json")
		var keys []jose.JSONWebKey
		for _, key := range jwks.Keys {
			if key.IsPublic() {
				keys = append(keys, key)
			}
		}
		pubJwks := &jose.JSONWebKeySet{Keys: keys}
		buf, _ := json.Marshal(pubJwks)

		fmt.Fprint(w, string(buf))
	})
}