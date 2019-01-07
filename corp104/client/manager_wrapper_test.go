package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ory/fosite"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/corp104/resource"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"strings"
	"testing"
)

func TestManagerWrapper_GetClient(t *testing.T) {
	ctx := context.TODO()
	resourceManager, err := initTestResourceManager(ctx)
	assert.NoError(t, err)

	m := &client.ManagerWrapper{
		Manager: client.NewMemoryManager(&fosite.BCrypt{}),
		ResourceManager: resourceManager,
	}

	var ecTestKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &client.Client{
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
		Scope:                   "graphql:resumes:read graphql:resumes:write urn:104:v3:resource:rest:jobs",
	}
	err = m.CreateClient(ctx, c)
	assert.NoError(t, err)

	fc, err := m.GetClient(ctx, c.ClientID)
	assert.NoError(t, err)
	// fc.GetScopes() 的傳回值會將 "urn:104:v3:resource:rest:jobs" 轉換為 "rest:jobs rest:jobs:read rest:jobs:write"
	assert.Equal(t, "graphql:resumes:read graphql:resumes:write rest:jobs rest:jobs:read rest:jobs:write", strings.Join(fc.GetScopes(), " "))
}

func initTestResourceManager(ctx context.Context) (resource.Manager, error) {
	rm := resource.NewMemoryManager()

	// create "jobs" resource
	jobs := &resource.Resource{
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
		Scopes: []resource.Scope{
			{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
			{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
		},
		Paths: []resource.Path{
			{
				Name: "/",
				Methods: []resource.Method{
					{
						Name:        "GET",
						Description: "取得 job 列表",
						Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},
					},
				},
			},
			{
				Name: "/",
				Methods: []resource.Method{
					{
						Name:        "POST",
						Description: "取得 job 列表",
						Scopes:      []string{"rest:jobs:write"},
					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []resource.Method{
					{
						Name:        "GET",
						Description: "取得 job 資料",
						Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},

					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []resource.Method{
					{
						Name:        "DELETE",
						Description: "刪除 job 資料",
						Scopes:      []string{"rest:jobs:write"},
					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []resource.Method{
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
	err := rm.CreateResource(ctx, jobs)
	if err != nil {
		return nil, err
	}

	// create "resumes" resource
	resumes := &resource.Resource{
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
		Scopes: []resource.Scope{
			{Name: "graphql:resumes:read", ScopeAuthType: "", Description: "關於rest:jobs:read"},
			{Name: "graphql:resumes:edu:read", ScopeAuthType: "", Description: "關於rest:jobs:edu:read"},
			{Name: "graphql:resumes:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
		},
		GraphQLOperations: []resource.GraphQLOperation{
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
	err = rm.CreateResource(ctx, resumes)
	if err != nil {
		return nil, err
	}

	return rm, nil
}
