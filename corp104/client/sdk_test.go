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
	"fmt"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/corp104/jwk"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/ory/hydra/mock-dep"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/negroni"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"net/http/httptest"
	"testing"
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
	viper.Set("EMAIL_SERVICE_URL", "http://localhost:10025")
	viper.Set("TEST_MODE", true)
	webSessionName := "web_sid"
	keyManager := &jwk.MemoryManager{Keys: map[string]*jose.JSONWebKeySet{}}
	authSrvJwks, err := (&jwk.ECDSA256Generator{}).Generate(uuid.New(), "sig")
	require.NoError(t, err)
	require.NoError(t, keyManager.AddKeySet(context.TODO(), "jwk.offline", authSrvJwks))
	ecAuthSrvPubJwk := authSrvJwks.Keys[1].Key.(*ecdsa.PublicKey)
	authSrvPubJwk := &hydra.JsonWebKey{
		Kid: authSrvJwks.Keys[1].KeyID,
		Alg: authSrvJwks.Keys[1].Algorithm,
		Crv: ecAuthSrvPubJwk.Params().Name,
		Use: authSrvJwks.Keys[1].Use,
		Kty: "EC",
		X:   base64.RawURLEncoding.EncodeToString(ecAuthSrvPubJwk.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(ecAuthSrvPubJwk.Y.Bytes()),
	}

	// client key pair
	cPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cPrivJwk := &hydra.JsonWebKey{
		Alg: "ES256",
		Crv: "P-256",
		Use: "sig",
		Kty: "EC",
		X:   base64.RawURLEncoding.EncodeToString(cPrivKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(cPrivKey.Y.Bytes()),
		D:   base64.RawURLEncoding.EncodeToString(cPrivKey.D.Bytes()),
	}
	cPubJwk := hydra.JsonWebKey{
		Alg: "ES256",
		Crv: "P-256",
		Use: "sig",
		Kty: "EC",
		X:   base64.RawURLEncoding.EncodeToString(cPrivKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(cPrivKey.Y.Bytes()),
	}

	manager := client.NewMemoryManager(nil)
	handler := client.NewHandler(manager, herodot.NewJSONWriter(nil), []string{"foo", "bar"}, []string{"public"}, keyManager, "http://localhost:4444", "jwk.offline")

	router := httprouter.New()
	handler.SetRoutes(router, router, func(h http.Handler) http.Handler {
		return h
	})
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
	handler.IssuerURL = server.URL

	// start mock server
	viper.Set("AD_LOGIN_URL", fmt.Sprintf("http://localhost:%d/ad/login", mock_dep.GetPort()))
	err = mock_dep.StartMockServer()
	require.NoError(t, err)

	t.Run("case=public client is created", func(t *testing.T) {
		createClient := createTestPublicClient("", cPubJwk)

		// returned client is correct on Create
		result, response, err := c.PutOAuth2Client(createClient, cPrivJwk, authSrvPubJwk)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusCreated, response.StatusCode, "%s", response.Payload)
		assert.NotEmpty(t, result)
	})

	t.Run("case=confidential client is created", func(t *testing.T) {
		createClient := createTestConfidentialClient("", cPubJwk)

		t.Run("case=create client with invalid user credentials", func(t *testing.T) {
			c.Configuration.Username = "foo.bar"
			c.Configuration.Password = "wrong"

			_, response, err := c.PutOAuth2Client(createClient, cPrivJwk, authSrvPubJwk)
			require.NoError(t, err)
			require.EqualValues(t, http.StatusUnauthorized, response.StatusCode)
		})

		t.Run("case=create client", func(t *testing.T) {
			c.Configuration.Username = "foo.bar"
			c.Configuration.Password = "secret"

			// returned client is correct on Create (session only)
			result, response, err := c.PutOAuth2Client(createClient, cPrivJwk, authSrvPubJwk)
			require.NoError(t, err)
			require.EqualValues(t, http.StatusAccepted, response.StatusCode, "%s", response.Payload)
			assert.NotEmpty(t, result)
			sessionCookie := getCookieFromResponse(response)
			assert.NotEmpty(t, sessionCookie)

			t.Run("case=commit confidential client", func(t *testing.T) {
				commitResult, response, err := c.CommitOAuth2Client(sessionCookie, viper.GetString("COMMIT_CODE"))
				require.NoError(t, err)
				require.EqualValues(t, http.StatusOK, response.StatusCode)
				require.NotEmpty(t, commitResult.SignedClientCredentials)
				clientSecret, err := getClientSecretFromSignedCredentials(commitResult.SignedClientCredentials)
				require.NoError(t, err)

				t.Run("case=get client with client credentials", func(t *testing.T) {
					result, response, err := c.GetOAuth2Client(createClient.ClientId, clientSecret)
					require.NoError(t, err)
					require.EqualValues(t, http.StatusOK, response.StatusCode)
					require.EqualValues(t, createClient.ClientId, result.ClientId)
					require.EqualValues(t, createClient.SoftwareId, result.SoftwareId)
					require.EqualValues(t, createClient.SoftwareVersion, result.SoftwareVersion)
				})

				// update client fields
				t.Run("case=update client", func(t *testing.T) {
					updateClient := createClient
					updateClient.SoftwareVersion = "0.0.2"

					_, response, err := c.PutOAuth2Client(updateClient, cPrivJwk, authSrvPubJwk)
					require.NoError(t, err)
					require.EqualValues(t, http.StatusAccepted, response.StatusCode, "%s", response.Payload)

					sessionCookie := getCookieFromResponse(response)
					assert.NotEmpty(t, sessionCookie)

					_, response, err = c.CommitOAuth2Client(sessionCookie, viper.GetString("COMMIT_CODE"))
					require.NoError(t, err)
					require.EqualValues(t, http.StatusOK, response.StatusCode)

					c, response, err := c.GetOAuth2Client(updateClient.ClientId, clientSecret)
					require.NoError(t, err)
					require.EqualValues(t, http.StatusOK, response.StatusCode)
					require.EqualValues(t, updateClient.SoftwareVersion, c.SoftwareVersion)
				})

				t.Run("case=delete client", func(t *testing.T) {
					response, err := c.DeleteOAuth2Client(createClient.ClientId)
					require.NoError(t, err)
					require.EqualValues(t, http.StatusNoContent, response.StatusCode)
				})
			})
		})
	})

	// stop mock server
	mock_dep.StopMockServer()
}

func createTestPublicClient(prefix string, pubJwk hydra.JsonWebKey) hydra.OAuth2Client {
	return hydra.OAuth2Client{
		ClientId:                 "1234",
		ClientName:               prefix + "name",
		ClientUri:                prefix + "uri",
		Contacts:                 []string{prefix + "peter", prefix + "pan"},
		GrantTypes:               []string{"implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		ResponseTypes:            []string{"token", "id_token"},
		RedirectUris:             []string{prefix + "redirect-url", prefix + "redirect-uri"},
		SoftwareId:               prefix + "SPA",
		SoftwareVersion:          prefix + "0.0.1",
		IdTokenSignedResponseAlg: "ES256",
		RequestObjectSigningAlg:  "ES256",
		TokenEndpointAuthMethod:  "private_key_jwt+session",
	}
}

func createTestConfidentialClient(prefix string, pubJwk hydra.JsonWebKey) hydra.OAuth2Client {
	return hydra.OAuth2Client{
		ClientId:                "5678",
		ClientName:              prefix + "name",
		ClientUri:               prefix + "uri",
		Contacts:                []string{prefix + "peter", prefix + "pan"},
		GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		TokenEndpointAuthMethod: "private_key_jwt",
		SoftwareId:              prefix + "client1",
		SoftwareVersion:         prefix + "0.0.1",
		Jwks:                    &hydra.JsonWebKeySet{Keys: []hydra.JsonWebKey{pubJwk}},
	}
}

func getClientSecretFromSignedCredentials(signedCredentials string) (string, error) {
	_, payload, err := pkg.GetContentFromJWS(signedCredentials)
	if err != nil {
		return "", nil
	}
	clientSecret := payload["client_secret"]
	if clientSecret == "" {
		return "", errors.New("empty client secret")
	}
	return clientSecret.(string), nil
}

func getCookieFromResponse(response *hydra.APIResponse) map[string]string {
	respCookies := response.Cookies()
	sessionCookie := map[string]string{}
	for _, respCookie := range respCookies {
		sessionCookie[respCookie.Name] = respCookie.Value
	}
	return sessionCookie
}
