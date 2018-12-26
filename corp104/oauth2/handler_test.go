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

package oauth2_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwt2 "github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/herodot"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/corp104/oauth2"
	"github.com/ory/hydra/corp104/resource"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

var lifespan = time.Hour
var flushRequests = []*fosite.Request{
	{
		ID:            "flush-1",
		RequestedAt:   time.Now().Round(time.Second),
		Client:        &client.Client{ClientID: "foobar"},
		Scopes:        fosite.Arguments{"fa", "ba"},
		GrantedScopes: fosite.Arguments{"fa", "ba"},
		Form:          url.Values{"foo": []string{"bar", "baz"}},
		Session:       &fosite.DefaultSession{Subject: "bar"},
	},
	{
		ID:            "flush-2",
		RequestedAt:   time.Now().Round(time.Second).Add(-(lifespan + time.Minute)),
		Client:        &client.Client{ClientID: "foobar"},
		Scopes:        fosite.Arguments{"fa", "ba"},
		GrantedScopes: fosite.Arguments{"fa", "ba"},
		Form:          url.Values{"foo": []string{"bar", "baz"}},
		Session:       &fosite.DefaultSession{Subject: "bar"},
	},
	{
		ID:            "flush-3",
		RequestedAt:   time.Now().Round(time.Second).Add(-(lifespan + time.Hour)),
		Client:        &client.Client{ClientID: "foobar"},
		Scopes:        fosite.Arguments{"fa", "ba"},
		GrantedScopes: fosite.Arguments{"fa", "ba"},
		Form:          url.Values{"foo": []string{"bar", "baz"}},
		Session:       &fosite.DefaultSession{Subject: "bar"},
	},
}

func TestHandlerFlushHandler(t *testing.T) {
	store := oauth2.NewFositeMemoryStore(nil, lifespan)
	h := &oauth2.Handler{
		H:             herodot.NewJSONWriter(nil),
		ScopeStrategy: fosite.HierarchicScopeStrategy,
		IssuerURL:     "https://hydra.localhost",
		Storage:       store,
	}

	for _, r := range flushRequests {
		require.NoError(t, store.CreateAccessTokenSession(nil, r.ID, r))
	}

	r := httprouter.New()
	h.SetRoutes(r, r, func(h http.Handler) http.Handler {
		return h
	})
	ts := httptest.NewServer(r)
	c := hydra.NewOAuth2ApiWithBasePath(ts.URL)

	ds := new(fosite.DefaultSession)
	ctx := context.Background()

	resp, err := c.FlushInactiveOAuth2Tokens(hydra.FlushInactiveOAuth2TokensRequest{NotAfter: time.Now().Add(-time.Hour * 24)})
	require.NoError(t, err)
	assert.EqualValues(t, http.StatusNoContent, resp.StatusCode)

	_, err = store.GetAccessTokenSession(ctx, "flush-1", ds)
	require.NoError(t, err)
	_, err = store.GetAccessTokenSession(ctx, "flush-2", ds)
	require.NoError(t, err)
	_, err = store.GetAccessTokenSession(ctx, "flush-3", ds)
	require.NoError(t, err)

	resp, err = c.FlushInactiveOAuth2Tokens(hydra.FlushInactiveOAuth2TokensRequest{NotAfter: time.Now().Add(-(lifespan + time.Hour/2))})
	require.NoError(t, err)
	assert.EqualValues(t, http.StatusNoContent, resp.StatusCode)

	_, err = store.GetAccessTokenSession(ctx, "flush-1", ds)
	require.NoError(t, err)
	_, err = store.GetAccessTokenSession(ctx, "flush-2", ds)
	require.NoError(t, err)
	_, err = store.GetAccessTokenSession(ctx, "flush-3", ds)
	require.Error(t, err)

	resp, err = c.FlushInactiveOAuth2Tokens(hydra.FlushInactiveOAuth2TokensRequest{NotAfter: time.Now()})
	require.NoError(t, err)
	assert.EqualValues(t, http.StatusNoContent, resp.StatusCode)

	_, err = store.GetAccessTokenSession(ctx, "flush-1", ds)
	require.NoError(t, err)
	_, err = store.GetAccessTokenSession(ctx, "flush-2", ds)
	require.Error(t, err)
	_, err = store.GetAccessTokenSession(ctx, "flush-3", ds)
	require.Error(t, err)
}

func TestUserinfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	op := NewMockOAuth2Provider(ctrl)
	defer ctrl.Finish()

	jm := &jwk.MemoryManager{Keys: map[string]*jose.JSONWebKeySet{}}
	keys, err := (&jwk.ECDSA256Generator{}).Generate("signing", "sig")
	require.NoError(t, err)
	require.NoError(t, jm.AddKeySet(context.TODO(), oauth2.OpenIDConnectKeyName, keys))
	jwtStrategy, err := jwk.NewES256JWTStrategy(jm, oauth2.OpenIDConnectKeyName)

	h := &oauth2.Handler{
		OAuth2:            op,
		H:                 herodot.NewJSONWriter(logrus.New()),
		OpenIDJWTStrategy: jwtStrategy,
	}
	router := httprouter.New()
	h.SetRoutes(router, router, func(h http.Handler) http.Handler {
		return h
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	for k, tc := range []struct {
		setup            func(t *testing.T)
		check            func(t *testing.T, body []byte)
		expectStatusCode int
	}{
		{
			setup: func(t *testing.T) {
				op.EXPECT().IntrospectToken(gomock.Any(), gomock.Eq("access-token"), gomock.Eq(fosite.AccessToken), gomock.Any()).Return(fosite.AccessToken, nil, errors.New("asdf"))
			},
			expectStatusCode: http.StatusInternalServerError,
		},
		{
			setup: func(t *testing.T) {
				op.EXPECT().
					IntrospectToken(gomock.Any(), gomock.Eq("access-token"), gomock.Eq(fosite.AccessToken), gomock.Any()).
					Return(fosite.RefreshToken, nil, nil)
			},
			expectStatusCode: http.StatusUnauthorized,
		},
		{
			setup: func(t *testing.T) {
				op.EXPECT().
					IntrospectToken(gomock.Any(), gomock.Eq("access-token"), gomock.Eq(fosite.AccessToken), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ string, _ fosite.TokenType, session fosite.Session, _ ...string) (fosite.TokenType, fosite.AccessRequester, error) {
						session = &oauth2.Session{
							DefaultSession: &openid.DefaultSession{
								Claims: &jwt.IDTokenClaims{
									Subject: "alice",
								},
								Headers: new(jwt.Headers),
								Subject: "alice",
							},
							Audience: []string{},
							Extra:    map[string]interface{}{},
						}

						return fosite.AccessToken, &fosite.AccessRequest{
							Request: fosite.Request{
								Client:  &client.Client{},
								Session: session,
							},
						}, nil
					})
			},
			expectStatusCode: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				assert.True(t, strings.Contains(string(body), `"sub":"alice"`), "%s", body)
			},
		},
		{
			setup: func(t *testing.T) {
				op.EXPECT().
					IntrospectToken(gomock.Any(), gomock.Eq("access-token"), gomock.Eq(fosite.AccessToken), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ string, _ fosite.TokenType, session fosite.Session, _ ...string) (fosite.TokenType, fosite.AccessRequester, error) {
						session = &oauth2.Session{
							DefaultSession: &openid.DefaultSession{
								Claims: &jwt.IDTokenClaims{
									Subject: "another-alice",
								},
								Headers: new(jwt.Headers),
								Subject: "alice",
							},
							Audience: []string{},
							Extra:    map[string]interface{}{},
						}

						return fosite.AccessToken, &fosite.AccessRequest{
							Request: fosite.Request{
								Client:  &client.Client{},
								Session: session,
							},
						}, nil
					})
			},
			expectStatusCode: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				assert.False(t, strings.Contains(string(body), `"sub":"alice"`), "%s", body)
				assert.True(t, strings.Contains(string(body), `"sub":"another-alice"`), "%s", body)
			},
		},
		{
			setup: func(t *testing.T) {
				op.EXPECT().
					IntrospectToken(gomock.Any(), gomock.Eq("access-token"), gomock.Eq(fosite.AccessToken), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ string, _ fosite.TokenType, session fosite.Session, _ ...string) (fosite.TokenType, fosite.AccessRequester, error) {
						session = &oauth2.Session{
							DefaultSession: &openid.DefaultSession{
								Claims: &jwt.IDTokenClaims{
									Subject: "alice",
								},
								Headers: new(jwt.Headers),
								Subject: "alice",
							},
							Audience: []string{},
							Extra:    map[string]interface{}{},
						}

						return fosite.AccessToken, &fosite.AccessRequest{
							Request: fosite.Request{
								Client: &client.Client{
									UserinfoSignedResponseAlg: "none",
								},
								Session: session,
							},
						}, nil
					})
			},
			expectStatusCode: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				assert.True(t, strings.Contains(string(body), `"sub":"alice"`), "%s", body)
			},
		},
		{
			setup: func(t *testing.T) {
				op.EXPECT().
					IntrospectToken(gomock.Any(), gomock.Eq("access-token"), gomock.Eq(fosite.AccessToken), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ string, _ fosite.TokenType, session fosite.Session, _ ...string) (fosite.TokenType, fosite.AccessRequester, error) {
						session = &oauth2.Session{
							DefaultSession: &openid.DefaultSession{
								Claims: &jwt.IDTokenClaims{
									Subject: "alice",
								},
								Headers: new(jwt.Headers),
								Subject: "alice",
							},
							Audience: []string{},
							Extra:    map[string]interface{}{},
						}

						return fosite.AccessToken, &fosite.AccessRequest{
							Request: fosite.Request{
								Client: &client.Client{
									UserinfoSignedResponseAlg: "asdfasdf",
								},
								Session: session,
							},
						}, nil
					})
			},
			expectStatusCode: http.StatusInternalServerError,
		},
		{
			setup: func(t *testing.T) {
				op.EXPECT().
					IntrospectToken(gomock.Any(), gomock.Eq("access-token"), gomock.Eq(fosite.AccessToken), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ string, _ fosite.TokenType, session fosite.Session, _ ...string) (fosite.TokenType, fosite.AccessRequester, error) {
						session = &oauth2.Session{
							DefaultSession: &openid.DefaultSession{
								Claims: &jwt.IDTokenClaims{
									Subject: "alice",
								},
								Headers: new(jwt.Headers),
								Subject: "alice",
							},
							Audience: []string{},
							Extra:    map[string]interface{}{},
						}

						return fosite.AccessToken, &fosite.AccessRequest{
							Request: fosite.Request{
								Client: &client.Client{
									UserinfoSignedResponseAlg: "ES256",
								},
								Session: session,
							},
						}, nil
					})
			},
			expectStatusCode: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				claims, err := jwt2.Parse(string(body), func(token *jwt2.Token) (interface{}, error) {
					return keys.Key("public:signing")[0].Key.(*ecdsa.PublicKey), nil
				})
				require.NoError(t, err)
				assert.EqualValues(t, "alice", claims.Claims.(jwt2.MapClaims)["sub"])
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			tc.setup(t)

			req, err := http.NewRequest("GET", ts.URL+"/userinfo", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer access-token")
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.EqualValues(t, tc.expectStatusCode, resp.StatusCode)
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			if tc.expectStatusCode == http.StatusOK {
				tc.check(t, body)
			}
		})
	}
}

func TestHandlerWellKnown(t *testing.T) {
	jwkManager := new(jwk.MemoryManager)
	keySet := "jwk.offline"
	keys, _ := (&jwk.ECDSA256Generator{}).Generate("test-offline-jks", "sig")
	jwkManager.AddKeySet(context.TODO(), keySet, keys)
	metadataStrategy, _ := jwk.NewES256JWTStrategy(jwkManager, keySet)

	h := &oauth2.Handler{
		H:                           herodot.NewJSONWriter(nil),
		ScopeStrategy:               fosite.WildcardScopeStrategy,
		IssuerURL:                   "https://auth.v3.104.com.tw",
		SubjectTypes:                []string{"public"},
		OAuthServerMetadataStrategy: metadataStrategy,
		ResourceManager:             resource.NewMemoryManager(),
	}

	r := httprouter.New()
	h.SetRoutes(r, r, func(h http.Handler) http.Handler {
		return h
	})
	ts := httptest.NewServer(r)

	res, err := http.Get(ts.URL + oauth2.WellKnownPath)
	require.NoError(t, err)
	defer res.Body.Close()

	trueConfig := (&oauth2.WellKnown{
		Issuer:                            strings.TrimRight(h.IssuerURL, "/") + "/",
		JWKsURI:                           strings.TrimRight(h.IssuerURL, "/") + oauth2.JWKPath,
		ServiceDocumentation:              oauth2.ServiceDocURL,
		AuthURL:                           strings.TrimRight(h.IssuerURL, "/") + oauth2.AuthPath,
		TokenURL:                          strings.TrimRight(h.IssuerURL, "/") + oauth2.TokenPath,
		RegistrationEndpoint:              strings.TrimRight(h.IssuerURL, "/") + client.ClientsHandlerPath,
		RevocationEndpoint:                strings.TrimRight(h.IssuerURL, "/") + oauth2.RevocationPath,
		CheckSessionIFrame:                strings.TrimRight(h.IssuerURL, "/") + oauth2.CheckSessionPath,
		EndSessionEndpoint:                strings.TrimRight(h.IssuerURL, "/") + oauth2.EndSessionPath,
		ResourcesEndpoint:                 strings.TrimRight(h.IssuerURL, "/") + resource.ResourcesHandlerPath,
		ScopesSupported:                   []string{"openid"},
		ResponseTypes:                     []string{"id_token", "token"},
		GrantTypesSupported:               []string{"client_credentials", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt", "private_key_jwt+session"},
		TokenEndpointAuthSigningAlgValuesSupported:      []string{"ES256"},
		RevocationEndpointAuthMethodsSupported:          []string{"private_key_jwt"},
		RevocationEndpointAuthSigningAlgValuesSupported: []string{"ES256"},
		IDTokenSigningAlgValuesSupported:                []string{"ES256"},
		RequestParameterSupported:                       true,
		RequestObjectSigningAlgValuesSupported:          []string{"ES256"},
	}).ToMap()

	var signedMetadataResp oauth2.SignedMetadata
	err = json.NewDecoder(res.Body).Decode(&signedMetadataResp)
	require.NoError(t, err, "problem decoding signed_metadata json response: %+v", err)
	// validate & decode
	dToken, err := metadataStrategy.Decode(context.TODO(), signedMetadataResp.Token)
	require.NoError(t, err, "problem validating signed_metadata json response: %+v", err)
	// compare content
	claimMap := map[string]interface{}(dToken.Claims.(jwt2.MapClaims))
	for k, v := range trueConfig {
		switch v := v.(type) {
		case string:
			assert.EqualValues(t, v, claimMap[k])
		case []string:
			actual := claimMap[k]
			if mv, ok := claimMap[k].([]interface{}); ok {
				mvs := make([]string, len(mv))
				for mvsi, mvsv := range mv {
					mvs[mvsi] = fmt.Sprint(mvsv)
				}
				actual = mvs
			}
			assert.EqualValues(t, v, actual)
		}
	}
}
