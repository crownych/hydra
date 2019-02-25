package resource_test

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
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/corp104/resource"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	mock_dep "github.com/ory/hydra/mock-dep"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/negroni"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResourceSDK(t *testing.T) {
	err := mock_dep.StartMockServer()
	require.NoError(t, err)
	defer mock_dep.StopMockServer()

	viper.Set("AD_LOGIN_URL", fmt.Sprintf("http://localhost:%d/ad/login", mock_dep.GetPort()))
	viper.Set("EMAIL_SERVICE_URL", "http://localhost:10025")
	viper.Set("TEST_MODE", true)
	webSessionName := "web_sid"
	keyManager := &jwk.MemoryManager{Keys: map[string]*pkg.JSONWebKeySet{}}
	authSrvJwks, err := (&jwk.ECDSA256Generator{}).Generate(uuid.New(), "sig")
	require.NoError(t, err)
	require.NoError(t, keyManager.AddKeySet(context.TODO(), "auth.offline", authSrvJwks))
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

	manager := resource.NewMemoryManager()
	handler := resource.NewHandler(manager, herodot.NewJSONWriter(nil), keyManager, "http://localhost:4444", "auth.offline")

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
	c.Configuration.PrivateJWK = cPrivJwk
	c.Configuration.AuthSvcOfflinePublicJWK = authSrvPubJwk
	handler.IssuerURL = server.URL

	for _, tc := range []struct {
		name	 string
		resource hydra.OAuth2Resource
	} {
		{
			name: "rest resource",
			resource: createRestResource(cPubJwk),
		},
		{
			name: "graphql resource",
			resource: createGraphQLResource(cPubJwk),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			createResource := tc.resource

			t.Run("case=create resource with invalid user credentials", func(t *testing.T) {
				c.Configuration.ADUsername = "foo.bar"
				c.Configuration.ADPassword = "wrong"

				_, response, err := c.PutOAuth2Resource(createResource)
				require.NoError(t, err)
				require.EqualValues(t, http.StatusUnauthorized, response.StatusCode)
			})

			t.Run("case=create resource", func(t *testing.T) {
				c.Configuration.ADUsername = "foo.bar"
				c.Configuration.ADPassword = "secret"

				// returned resource is correct on Create (session only)
				result, response, err := c.PutOAuth2Resource(createResource)
				require.NoError(t, err)
				require.EqualValues(t, http.StatusAccepted, response.StatusCode, "%s", response.Payload)
				assert.NotEmpty(t, result)
				sessionCookie := getCookieFromResponse(response)
				assert.NotEmpty(t, sessionCookie)

				t.Run("case=commit resource", func(t *testing.T) {
					commitResult, response, err := c.CommitOAuth2Resource(sessionCookie, viper.GetString("COMMIT_CODE"))
					require.NoError(t, err)
					require.EqualValues(t, http.StatusOK, response.StatusCode)
					require.NotEmpty(t, commitResult.Location)

					t.Run("case=get resource", func(t *testing.T) {
						result, response, err := c.GetOAuth2Resource(createResource.GetUrn())
						require.NoError(t, err)
						require.EqualValues(t, http.StatusOK, response.StatusCode)
						require.EqualValues(t, createResource.Uri, result.Uri)
						require.EqualValues(t, createResource.Name, result.Name)
						require.EqualValues(t, createResource.Type, result.Type)
					})

					// update resource
					t.Run("case=update resource", func(t *testing.T) {
						updateResource := createResource
						updateResource.Scopes = append(updateResource.Scopes, )
						updateResource.Description = updateResource.Description+"-updated"

						_, response, err := c.PutOAuth2Resource(updateResource)
						require.NoError(t, err)
						require.EqualValues(t, http.StatusAccepted, response.StatusCode, "%s", response.Payload)

						sessionCookie := getCookieFromResponse(response)
						assert.NotEmpty(t, sessionCookie)

						_, response, err = c.CommitOAuth2Resource(sessionCookie, viper.GetString("COMMIT_CODE"))
						require.NoError(t, err)
						require.EqualValues(t, http.StatusOK, response.StatusCode)

						c, response, err := c.GetOAuth2Resource(updateResource.GetUrn())
						require.NoError(t, err)
						require.EqualValues(t, http.StatusOK, response.StatusCode)
						require.EqualValues(t, updateResource.Scopes, c.Scopes)
						require.EqualValues(t, updateResource.Description, c.Description)
					})

					t.Run("case=delete resource", func(t *testing.T) {
						response, err := c.DeleteOAuth2Resource(createResource.GetUrn())
						require.NoError(t, err)
						require.EqualValues(t, http.StatusNoContent, response.StatusCode)
					})
				})
			})
		})
	}
}

func createRestResource(pubJwk hydra.JsonWebKey) hydra.OAuth2Resource {
	return hydra.OAuth2Resource{
		Urn:          "urn:104:v3:resource:rest:jobs",
		Uri:          "https://v3ms.104.com.tw/jobs",
		Name:         "jobs",
		Type:         "rest",
		AuthService:  "https://v3auth.104.com.tw",
		DefaultScope: "rest:jobs",
		DefaultScopeAuthType: "company",
		GrantTypes:   []string{
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
			"client_credentials",
		},
		Scopes: []hydra.OAuth2ResourceScope{
			{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
			{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
		},
		Paths: []hydra.OAuth2ResourcePath{
			{
				Name: "/",
				Methods: []hydra.OAuth2ResourceMethod{
					{
						Name:        "GET",
						Description: "取得 job 列表",
						Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},
					},
				},
			},
			{
				Name: "/",
				Methods: []hydra.OAuth2ResourceMethod{
					{
						Name:        "POST",
						Description: "取得 job 列表",
						Scopes:      []string{"rest:jobs:write"},
					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []hydra.OAuth2ResourceMethod{
					{
						Name:        "GET",
						Description: "取得 job 資料",
						Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},

					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []hydra.OAuth2ResourceMethod{
					{
						Name:        "DELETE",
						Description: "刪除 job 資料",
						Scopes:      []string{"rest:jobs:write"},
					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []hydra.OAuth2ResourceMethod{
					{
						Name:        "PATCH",
						Description: "修改 job 資料",
						Scopes:      []string{"rest:jobs:write"},
					},
				},
			},
		},
		Contacts:      []string{"someone@104.com.tw"},
		Description:   "公司資料",
	}
}

func createGraphQLResource(pubJwk hydra.JsonWebKey) hydra.OAuth2Resource {
	return hydra.OAuth2Resource{
		Urn:          "urn:104:v3:resource:graphql:resumes",
		Uri:          "https://v3ms.104.com.tw/graphql",
		Name:         "resumes",
		Type:         "graphql",
		AuthService:  "https://v3auth.104.com.tw",
		DefaultScope: "graphql:resumes",
		DefaultScopeAuthType: "company",
		GrantTypes:   []string{
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
			"client_credentials",
		},
		Scopes: []hydra.OAuth2ResourceScope{
			{Name: "graphql:resumes:read", ScopeAuthType: "", Description: "關於rest:jobs:read"},
			{Name: "graphql:resumes:edu:read", ScopeAuthType: "", Description: "關於rest:jobs:edu:read"},
			{Name: "graphql:resumes:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
		},
		GraphQLOperations: []hydra.GraphQLOperation{
			{
				Name: "resumes",
				Type: "query",
				Scopes: []string{"graphql:resumes:read", "graphql:resumes:write"},
				Description: "查詢履歷",
			},
			{
				Name: "resumes/edu",
				Type: "query",
				Scopes: []string{"graphql:resumes:edu:read", "graphql:resumes:write"},
				Description: "查詢履歷的教育程度",
			},
			{
				Name: "createResume",
				Type: "mutation",
				Scopes: []string{"graphql:resumes:write"},
				Description: "新增履歷",
			},
			{
				Name: "deleteResume",
				Type: "mutation",
				Scopes: []string{"graphql:resumes:write"},
				Description: "刪除履歷",
			},
		},
		Contacts:      []string{"someone@104.com.tw"},
		Description:   "歷履表",
	}
}

func getCookieFromResponse(response *hydra.APIResponse) map[string]string {
	respCookies := response.Cookies()
	sessionCookie := map[string]string{}
	for _, respCookie := range respCookies {
		sessionCookie[respCookie.Name] = respCookie.Value
	}
	return sessionCookie
}

