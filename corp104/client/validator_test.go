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
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/pborman/uuid"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestValidate(t *testing.T) {
	v := &Validator{
		DefaultClientScopes: []string{"openid"},
		SubjectTypes:        []string{"public"},
	}

	var ecTestKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	for k, tc := range []struct {
		in        *Client
		check     func(t *testing.T, c *Client)
		expectErr bool
		v         *Validator
	}{
		{
			// public client (user-agent-based application)
			in: &Client{
				ClientID:                       uuid.New(),
				RedirectURIs:                   []string{"https://localhost/login/cb"},
				GrantTypes:                     []string{"implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
				ResponseTypes:                  []string{"token", "id_token"},
				Name:                           "SPA",
				ClientURI:                      "https://localhost/spa",
				Contacts:                       []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:                     "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:                "0.0.1",
				IdTokenSignedResponseAlgorithm: "ES256",
				RequestObjectSigningAlgorithm:  "ES256",
				TokenEndpointAuthMethod:        "private_key_jwt+session",
				Scope: 							"openid",
				ClientProfile:					UserAgentBasedClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.NotEmpty(t, c.ClientID)
				assert.NotEmpty(t, c.GetID())
				assert.Equal(t, c.GetID(), c.ClientID)
			},
		},
		{
			// public client (native application)
			in: &Client{
				ClientID:                       uuid.New(),
				RedirectURIs:                   []string{"https://localhost/login/cb"},
				GrantTypes:                     []string{"implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
				ResponseTypes:                  []string{"token", "id_token"},
				Name:                           "SPA",
				ClientURI:                      "https://localhost/spa",
				Contacts:                       []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:                     "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:                "0.0.1",
				IdTokenSignedResponseAlgorithm: "ES256",
				RequestObjectSigningAlgorithm:  "ES256",
				TokenEndpointAuthMethod:        "private_key_jwt+session",
				Scope: 							"openid",
				ClientProfile:					NativeClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.NotEmpty(t, c.ClientID)
				assert.NotEmpty(t, c.GetID())
				assert.Equal(t, c.GetID(), c.ClientID)
			},
		},
		{
			// confidential client (web application with "urn:ietf:params:oauth:grant-type:jwt-bearer" grant type)
			in: &Client{
				ClientID: uuid.New(),
				JSONWebKeys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       &ecTestKey256.PublicKey,
							KeyID:     "public:" + uuid.New(),
							Algorithm: "ES256",
							Use:       "sig",
						},
					},
				},
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Name:                    "foo",
				ClientURI:               "https://localhost/client",
				Contacts:                []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:              "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:         "0.0.1",
				RedirectURIs:            []string{"https://localhost/oauth/cb"},
				ClientProfile:			 WebClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.Equal(t, c.GetID(), c.ClientID)
			},
		},
		{
			// confidential client (web application with "client_credentials" grant type)
			in: &Client{
				ClientID: uuid.New(),
				JSONWebKeys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       &ecTestKey256.PublicKey,
							KeyID:     "public:" + uuid.New(),
							Algorithm: "ES256",
							Use:       "sig",
						},
					},
				},
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"client_credentials"},
				Name:                    "foo",
				ClientURI:               "https://localhost/client",
				Contacts:                []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:              "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:         "0.0.1",
				ClientProfile:			 WebClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.Equal(t, c.GetID(), c.ClientID)
			},
		},
		{
			// confidential client (web application with "urn:ietf:params:oauth:grant-type:jwt-bearer" and "client_credentials" grant types)
			in: &Client{
				ClientID: uuid.New(),
				JSONWebKeys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       &ecTestKey256.PublicKey,
							KeyID:     "public:" + uuid.New(),
							Algorithm: "ES256",
							Use:       "sig",
						},
					},
				},
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:jwt-bearer", "client_credentials"},
				Name:                    "foo",
				ClientURI:               "https://localhost/client",
				Contacts:                []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:              "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:         "0.0.1",
				RedirectURIs:            []string{"https://localhost/oauth/cb"},
				ClientProfile:			 WebClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.Equal(t, c.GetID(), c.ClientID)
			},
		},
		{
			// confidential client (batch application)
			in: &Client{
				ClientID: uuid.New(),
				JSONWebKeys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       &ecTestKey256.PublicKey,
							KeyID:     "public:" + uuid.New(),
							Algorithm: "ES256",
							Use:       "sig",
						},
					},
				},
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"client_credentials"},
				Name:                    "foo",
				ClientURI:               "https://localhost/client",
				Contacts:                []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:              "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:         "0.0.1",
				ClientProfile:			 BatchClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.Equal(t, c.GetID(), c.ClientID)
			},
		},
		{
			// fail with duplicate scope
			in: &Client{
				ClientID:                       uuid.New(),
				RedirectURIs:                   []string{"https://localhost/login/cb"},
				GrantTypes:                     []string{"implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
				ResponseTypes:                  []string{"token", "id_token"},
				Name:                           "SPA",
				ClientURI:                      "https://localhost/spa",
				Contacts:                       []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:                     "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:                "0.0.1",
				IdTokenSignedResponseAlgorithm: "ES256",
				RequestObjectSigningAlgorithm:  "ES256",
				TokenEndpointAuthMethod:        "private_key_jwt+session",
				Scope: 							"openid openid",
				ClientProfile:					UserAgentBasedClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.NotEmpty(t, c.ClientID)
				assert.NotEmpty(t, c.GetID())
				assert.Equal(t, c.GetID(), c.ClientID)
			},
			expectErr: true,
		},
		{
			// fail with invalid scope
			in: &Client{
				ClientID: uuid.New(),
				JSONWebKeys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       &ecTestKey256.PublicKey,
							KeyID:     "public:" + uuid.New(),
							Algorithm: "ES256",
							Use:       "sig",
						},
					},
				},
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"client_credentials"},
				Name:                    "foo",
				ClientURI:               "https://localhost/client",
				Contacts:                []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:              "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:         "0.0.1",
				Scope:                   "undefined",
				ClientProfile:			 WebClientProfile,
			},
			check: func(t *testing.T, c *Client) {},
			expectErr: true,
		},
		{
			// fail with empty client profile
			in: &Client{
				ClientID:                       uuid.New(),
				RedirectURIs:                   []string{"https://localhost/login/cb"},
				GrantTypes:                     []string{"implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
				ResponseTypes:                  []string{"token", "id_token"},
				Name:                           "SPA",
				ClientURI:                      "https://localhost/spa",
				Contacts:                       []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:                     "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:                "0.0.1",
				IdTokenSignedResponseAlgorithm: "ES256",
				RequestObjectSigningAlgorithm:  "ES256",
				TokenEndpointAuthMethod:        "private_key_jwt+session",
				Scope: 							"openid",
			},
			check: func(t *testing.T, c *Client) {
				assert.NotEmpty(t, c.ClientID)
				assert.NotEmpty(t, c.GetID())
				assert.Equal(t, c.GetID(), c.ClientID)
			},
			expectErr: true,
		},
		{
			// fail when public client with wrong client profile
			in: &Client{
				ClientID:                       uuid.New(),
				RedirectURIs:                   []string{"https://localhost/login/cb"},
				GrantTypes:                     []string{"implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
				ResponseTypes:                  []string{"token", "id_token"},
				Name:                           "SPA",
				ClientURI:                      "https://localhost/spa",
				Contacts:                       []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:                     "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:                "0.0.1",
				IdTokenSignedResponseAlgorithm: "ES256",
				RequestObjectSigningAlgorithm:  "ES256",
				TokenEndpointAuthMethod:        "private_key_jwt+session",
				Scope: 							"openid",
				ClientProfile:					WebClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.NotEmpty(t, c.ClientID)
				assert.NotEmpty(t, c.GetID())
				assert.Equal(t, c.GetID(), c.ClientID)
			},
			expectErr: true,
		},
		{
			// fail when confidential client with wrong client profile
			in: &Client{
				ClientID: uuid.New(),
				JSONWebKeys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       &ecTestKey256.PublicKey,
							KeyID:     "public:" + uuid.New(),
							Algorithm: "ES256",
							Use:       "sig",
						},
					},
				},
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"client_credentials"},
				Name:                    "foo",
				ClientURI:               "https://localhost/client",
				Contacts:                []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:              "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:         "0.0.1",
				ClientProfile:			 UserAgentBasedClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.Equal(t, c.GetID(), c.ClientID)
			},
			expectErr: true,
		},
		{
			// fail when batch client with "urn:ietf:params:oauth:grant-type:jwt-bearer" grant type
			in: &Client{
				ClientID: uuid.New(),
				JSONWebKeys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:       &ecTestKey256.PublicKey,
							KeyID:     "public:" + uuid.New(),
							Algorithm: "ES256",
							Use:       "sig",
						},
					},
				},
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:jwt-bearer", "client_credentials"},
				Name:                    "foo",
				ClientURI:               "https://localhost/client",
				Contacts:                []string{"周星馳(星輝海外有限公司)"},
				SoftwareId:              "4d51529c-37cd-424c-ba19-cba742d60903",
				SoftwareVersion:         "0.0.1",
				ClientProfile:			 BatchClientProfile,
			},
			check: func(t *testing.T, c *Client) {
				assert.Equal(t, c.GetID(), c.ClientID)
			},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			if tc.v == nil {
				tc.v = v
			}
			err := tc.v.Validate(tc.in, []string{"openid"})
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tc.check(t, tc.in)
			}
		})
	}
}

func TestValidateSectorIdentifierURL(t *testing.T) {
	var payload string

	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}
	ts := httptest.NewTLSServer(h)
	defer ts.Close()

	v := &Validator{
		c: ts.Client(),
	}

	for k, tc := range []struct {
		p         string
		r         []string
		u         string
		expectErr bool
	}{
		{
			u:         "",
			expectErr: true,
		},
		{
			u:         "http://foo/bar",
			expectErr: true,
		},
		{
			u:         ts.URL,
			expectErr: true,
		},
		{
			p:         `["http://foo"]`,
			u:         ts.URL,
			expectErr: false,
			r:         []string{"http://foo"},
		},
		{
			p:         `["http://foo"]`,
			u:         ts.URL,
			expectErr: true,
			r:         []string{"http://foo", "http://not-foo"},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			payload = tc.p
			err := v.validateSectorIdentifierURL(tc.u, tc.r)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
