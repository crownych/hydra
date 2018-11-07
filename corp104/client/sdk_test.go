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
	"github.com/spf13/viper"
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

func createTestClient(prefix string) hydra.OAuth2Client {
	return hydra.OAuth2Client{
		ClientId:                  "1234",
		ClientName:                prefix + "name",
		ClientSecret:              prefix + "secret",
		ClientUri:                 prefix + "uri",
		Contacts:                  []string{prefix + "peter", prefix + "pan"},
		GrantTypes:                []string{prefix + "client_credentials", prefix + "authorize_code"},
		LogoUri:                   prefix + "logo",
		Owner:                     prefix + "an-owner",
		PolicyUri:                 prefix + "policy-uri",
		Scope:                     prefix + "foo bar baz",
		TosUri:                    prefix + "tos-uri",
		ResponseTypes:             []string{prefix + "id_token", prefix + "code"},
		RedirectUris:              []string{prefix + "redirect-url", prefix + "redirect-uri"},
		ClientSecretExpiresAt:     0,
		TokenEndpointAuthMethod:   "client_secret_basic",
		UserinfoSignedResponseAlg: "none",
		SubjectType:               "public",
		//SectorIdentifierUri:   "https://sector.com/foo",
	}
}

func TestClientSDK(t *testing.T) {
	webSessionName := "web_sid"
	keyManager := &jwk.MemoryManager{Keys: map[string]*jose.JSONWebKeySet{}}
	authSrvJwks, err := (&jwk.ECDSA256Generator{}).Generate(uuid.New(), "sig")
	require.NoError(t, err)
	require.NoError(t, keyManager.AddKeySet(context.TODO(), "", authSrvJwks))

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

	manager := client.NewMemoryManager(nil)
	handler := client.NewHandler(manager, herodot.NewJSONWriter(nil), []string{"foo", "bar"}, []string{"public"}, keyManager)

	router := httprouter.New()
	handler.SetRoutes(router)
	mockOAuthServer(router, authSrvJwks)
	mockADServer(router)
	n := negroni.New()
	store := cookiestore.New([]byte("secret"))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   0,
		Secure:   false,
		HTTPOnly: true,
	})
	n.Use(sessions.Sessions(webSessionName, store))
	n.UseHandler(router)
	server := httptest.NewServer(n)
	c := hydra.NewOAuth2ApiWithBasePath(server.URL)
	viper.Set("AD_LOGIN_URL", server.URL + "/ad/login")
	/*
	t.Run("case=client default scopes are set", func(t *testing.T) {
		createClient := createTestClient("")
		result, response, err := c.CreateOAuth2Client(hydra.OAuth2Client{
			ClientId: "scoped",
		})
		require.NoError(t, err)
		require.EqualValues(t, http.StatusCreated, response.StatusCode)
		//assert.EqualValues(t, handler.Validator.DefaultClientScopes, strings.Split(result.Scope, " "))
		assert.NotNil(result)

		response, err = c.DeleteOAuth2Client("scoped")
		require.NoError(t, err)
		require.EqualValues(t, http.StatusNoContent, response.StatusCode)
	})

	t.Run("case=client is created and updated", func(t *testing.T) {
		createClient := createTestClient("")
		compareClient := createClient
		createClient.ClientSecretExpiresAt = 10

		// returned client is correct on Create
		result, response, err := c.CreateOAuth2Client(createClient)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusCreated, response.StatusCode, "%s", response.Payload)
		assert.EqualValues(t, compareClient, *result)

		// secret is not returned on GetOAuth2Client
		compareClient.ClientSecret = ""
		result, response, err = c.GetOAuth2Client(createClient.ClientId)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, response.StatusCode, "%s", response.Payload)
		assert.EqualValues(t, compareClient, *result)

		// listing clients returns the only added one
		results, response, err := c.ListOAuth2Clients(100, 0)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, response.StatusCode, "%s", response.Payload)
		assert.Len(t, results, 1)
		assert.EqualValues(t, compareClient, results[0])

		// SecretExpiresAt gets overwritten with 0 on Update
		compareClient.ClientSecret = createClient.ClientSecret
		result, response, err = c.UpdateOAuth2Client(createClient.ClientId, createClient)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, response.StatusCode, "%s", response.Payload)
		assert.EqualValues(t, compareClient, *result)

		// create another client
		updateClient := createTestClient("foo")
		result, response, err = c.UpdateOAuth2Client(createClient.ClientId, updateClient)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, response.StatusCode, "%s", response.Payload)
		assert.EqualValues(t, updateClient, *result)

		// again, test if secret is not returned on Get
		compareClient = updateClient
		compareClient.ClientSecret = ""
		result, response, err = c.GetOAuth2Client(updateClient.ClientId)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, response.StatusCode, "%s", response.Payload)
		assert.EqualValues(t, compareClient, *result)

		// client can not be found after being deleted
		response, err = c.DeleteOAuth2Client(updateClient.ClientId)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusNoContent, response.StatusCode, "%s", response.Payload)

		_, response, err = c.GetOAuth2Client(updateClient.ClientId)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, response.StatusCode)
	})

	t.Run("case=public client is transmitted without secret", func(t *testing.T) {
		result, response, err := c.CreateOAuth2Client(hydra.OAuth2Client{
			TokenEndpointAuthMethod: "none",
		})
		require.NoError(t, err)
		require.EqualValues(t, http.StatusCreated, response.StatusCode, "%s", response.Payload)

		assert.Equal(t, "", result.ClientSecret)

		result, response, err = c.CreateOAuth2Client(createTestClient(""))
		require.NoError(t, err)
		require.EqualValues(t, http.StatusCreated, response.StatusCode, "%s", response.Payload)

		assert.Equal(t, "secret", result.ClientSecret)
	})

	t.Run("case=id should be set properly", func(t *testing.T) {
		for k, tc := range []struct {
			client   hydra.OAuth2Client
			expectID string
		}{
			{
				client: hydra.OAuth2Client{},
			},
			{
				client:   hydra.OAuth2Client{ClientId: "set-properly-1"},
				expectID: "set-properly-1",
			},
			{
				client:   hydra.OAuth2Client{ClientId: "set-properly-2"},
				expectID: "set-properly-2",
			},
		} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				result, response, err := c.CreateOAuth2Client(tc.client)
				require.NoError(t, err)
				require.EqualValues(t, http.StatusCreated, response.StatusCode, "%s", response.Payload)

				assert.NotEmpty(t, result.ClientId)

				id := result.ClientId
				if tc.expectID != "" {
					assert.EqualValues(t, tc.expectID, result.ClientId)
					id = tc.expectID
				}

				result, response, err = c.GetOAuth2Client(id)
				require.NoError(t, err)
				require.EqualValues(t, http.StatusOK, response.StatusCode, "%s", response.Payload)

				assert.EqualValues(t, id, result.ClientId)
			})
		}
	})
	*/

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

		// returned client is correct on Create (session only)
		result, response, err := c.CreateOAuth2Client(createClient, cPrivJwk)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, response.StatusCode, "%s", response.Payload)
		assert.NotEmpty(t, result)
		respCookies := response.Cookies()
		assert.NotEmpty(t, respCookies)

		t.Run("case=persist confidential client with invalid credentials", func(t *testing.T) {
			saveResult, response, err := c.SaveOAuth2Client(respCookies, "foo.bar", "wrong", cPrivJwk)
			require.NoError(t, err)
			require.EqualValues(t, http.StatusUnauthorized, response.StatusCode)
			assert.Empty(t, saveResult.SignedCredentials)
		})

		t.Run("case=persist confidential client with valid credentials", func(t *testing.T) {
			saveResult, response, err := c.SaveOAuth2Client(respCookies, "foo.bar", "secret", cPrivJwk)
			require.NoError(t, err)
			require.EqualValues(t, http.StatusCreated, response.StatusCode)
			assert.NotEmpty(t, saveResult.SignedCredentials)
		})
	})
}

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

func mockADServer(r *httprouter.Router) {
	r.POST("/ad/login", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		r.ParseForm()
		if r.Form.Get("id") == "foo.bar" && r.Form.Get("pwd") == "secret" {
			fmt.Fprint(w, "@Foo")
		} else {
			fmt.Fprint(w, "\r\n")
		}
	})
}