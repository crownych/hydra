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

package jwk_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	sessions "github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	mock_dep "github.com/ory/hydra/mock-dep"
	"github.com/pborman/uuid"
	"github.com/spf13/viper"
	"github.com/urfave/negroni"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	. "github.com/ory/hydra/corp104/jwk"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKSDK(t *testing.T) {
	err := mock_dep.StartMockServer()
	require.NoError(t, err)
	defer mock_dep.StopMockServer()

	viper.Set("AD_LOGIN_URL", fmt.Sprintf("http://localhost:%d/ad/login", mock_dep.GetPort()))
	viper.Set("ADMIN_USERS", "auth.admin")
	viper.Set("EMAIL_SERVICE_URL", "http://localhost:10025")
	viper.Set("TEST_MODE", true)

	webSessionName := "web_sid"
	authOfflineJWKSName := "auth.offline"

	manager := new(MemoryManager)

	authSrvJwks, err := (&ECDSA256Generator{}).Generate(uuid.New(), "sig")
	require.NoError(t, err)
	require.NoError(t, manager.AddKeySet(context.TODO(), authOfflineJWKSName, authSrvJwks))
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

	// client's signing key
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

	router := httprouter.New()
	h := NewHandler(manager, nil, herodot.NewJSONWriter(nil), nil, "http://localhost:4444", authOfflineJWKSName)
	h.SetRoutes(router, router, func(h http.Handler) http.Handler {
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

	client := hydra.NewJsonWebKeyApiWithBasePath(server.URL)
	client.Configuration.PrivateJWK = cPrivJwk
	client.Configuration.AuthSvcOfflinePublicJWK = authSrvPubJwk
	h.IssuerURL = server.URL

	t.Run("JWK Set", func(t *testing.T) {
		client.Configuration.ADUsername = "auth.admin"
		client.Configuration.ADPassword = "secret"

		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.NoError(t, err)

		keyX := base64.RawURLEncoding.EncodeToString(privKey.X.Bytes())
		keyY := base64.RawURLEncoding.EncodeToString(privKey.Y.Bytes())
		keyD := base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())

		kid := uuid.New()
		crv := "P-256"
		kty := "EC"
		alg := "ES256"
		use := "sig"

		jwks := hydra.JsonWebKeySet{
			Keys: []hydra.JsonWebKey{
				{
					Kid: "private:" + kid,
					Crv: crv,
					Kty: kty,
					Alg: alg,
					Use: use,
					X: keyX,
					Y: keyY,
					D: keyD,
				},
				{
					Kid: "public:" + kid,
					Crv: crv,
					Kty: kty,
					Alg: alg,
					Use: use,
					X: keyX,
					Y: keyY,
				},
			},
		}

		cookies := map[string]string{}
		t.Run("PutJwkSet", func(t *testing.T) {
			resp, apiResp, err := client.PutJsonWebKeySet("set-foo2", jwks)
			require.NoError(t, err)
			cookies = hydra.GetCookieFromAPIResponse(apiResp)

			assert.Equal(t, http.StatusAccepted, apiResp.StatusCode)
			assert.NotEmpty(t, resp.SignedKeys)
			assert.NotEmpty(t, cookies)
		})

		t.Run("CommitJwkSet", func(t *testing.T) {
			resp, apiResp, err := client.CommitJsonWebKeySet(cookies, viper.GetString("COMMIT_CODE"))
			require.NoError(t, err)

			assert.Equal(t, http.StatusOK, apiResp.StatusCode)
			assert.NotEmpty(t, resp.Location)
		})

		t.Run("GetJwkSet after commit", func(t *testing.T) {
			resp, apiResp, err := client.GetJsonWebKeySet("set-foo2")
			require.NoError(t, err)

			assert.Equal(t, http.StatusOK, apiResp.StatusCode)
			for _, key := range resp.Keys {
				assert.Equal(t, alg, key.Alg)
				assert.Equal(t, use, key.Use)
				assert.Contains(t, key.Kid, kid)
				assert.Equal(t, key.X, keyX)
				assert.Equal(t, key.Y, keyY)
				if key.D != "" {
					assert.Equal(t, key.D, keyD)
				}
			}
		})

		t.Run("DeleteJwkSet", func(t *testing.T) {
			response, err := client.DeleteJsonWebKeySet("set-foo2")
			require.NoError(t, err)
			assert.Equal(t, http.StatusNoContent, response.StatusCode)
		})

		t.Run("GetJwkSet after delete", func(t *testing.T) {
			_, response, err := client.GetJsonWebKeySet("set-foo2")
			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, response.StatusCode)
		})

		t.Run("GetJwkSetKey after delete", func(t *testing.T) {
			_, response, err := client.GetJsonWebKey("public:"+kid, "set-foo2")
			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, response.StatusCode)
		})
	})
}
