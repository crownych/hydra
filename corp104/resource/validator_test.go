package resource

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidate(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct {
		name	  string
		in        *Resource
		check     func(t *testing.T, r *Resource)
		expectErr bool
		v         *Validator
	}{
		{
			name: "valid rest resource",
			in: &Resource{
				Urn:          "urn:104:v3:resource:rest:jobs",
				Uri:          "https://v3ms.104.com.tw/jobs",
				Name:         "jobs",
				Type:         "rest",
				AuthService:  "https://v3auth.104.com.tw",
				DefaultScope: "rest:job",
				DefaultScopeAuthType: "company",
				GrantTypes:   []string{
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
					"client_credentials",
				},
				Scopes: []Scope{
					{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				Paths: []Path{
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},
							},
						},
					},
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "POST",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:write"},
							},
						},
					},
					{
						Name: "/{jobNo}",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "取得 job 資料",
								Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},

							},
						},
					},
					{
						Name: "/{jobNo}",
						Methods: []Method{
							{
								Name:        "DELETE",
								Description: "刪除 job 資料",
								Scopes:      []string{"rest:jobs:write"},
							},
						},
					},
					{
						Name: "/{jobNo}",
						Methods: []Method{
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
			},
			check: func(t *testing.T, r *Resource) {},
		},
		{
			name: "invalid scheme of Uri",
			in: &Resource{
				Urn:         "urn:104:v3:resource:rest:jobs",
				Uri:         "http://v3ms.104.com.tw/jobs",
				Name:        "jobs",
				Type:        "rest",
				AuthService: "https://v3auth.104.com.tw",
				DefaultScope: "rest:jobs",
				DefaultScopeAuthType: "company",
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Scopes: []Scope{
					{Name: "rest:jobs:read", ScopeAuthType: "user"},
					{Name: "rest:jobs:list", ScopeAuthType: "user"},
				},
				Paths: []Path{
					{
						Name: "/{jobNo}",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job",
								Scopes:      []string{"job:v1.0:read"},
							},
						},
					},
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job list",
								Scopes:      []string{"job:v1.0:list"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "uri must not contain a fragment",
			in: &Resource{
				Urn:         "urn:104:v3:resource:rest:jobs",
				Uri:         "https://v3ms.104.com.tw/jobs#fragment",
				Name:        "jobs",
				Type:        "rest",
				AuthService: "https://v3auth.104.com.tw",
				DefaultScope: "rest:jobs",
				DefaultScopeAuthType: "company",
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Scopes: []Scope{
					{Name: "rest:jobs:read", ScopeAuthType: "user"},
					{Name: "rest:jobs:list", ScopeAuthType: "user"},
				},
				Paths: []Path{
					{
						Name: "/{jobNo}",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job",
								Scopes:      []string{"job:v1.0:read"},
							},
						},
					},
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job list",
								Scopes:      []string{"job:v1.0:list"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "invalid default scope auth type",
			in: &Resource{
				Urn:         "urn:104:v3:rest:jobs",
				Uri:         "https://v3ms.104.com.tw/jobs",
				Name:        "jobs",
				Type:        "rest",
				AuthService: "https://v3auth.104.com.tw",
				DefaultScope: "rest:jobs",
				DefaultScopeAuthType: "wrong",
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Scopes: []Scope{
					{Name: "rest:jobs:read", ScopeAuthType: "user"},
					{Name: "rest:jobs:list", ScopeAuthType: "user"},
				},
				Paths: []Path{
					{
						Name: "/{jobNo}",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job",
								Scopes:      []string{"rest:jobs:read"},
							},
						},
					},
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job list",
								Scopes:      []string{"rest:jobs:list"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "invalid grant types",
			in: &Resource{
				Urn:         "urn:104:v3:rest:jobs",
				Uri:         "https://v3ms.104.com.tw/jobs",
				Name:        "jobs",
				Type:        "rest",
				AuthService: "https://v3auth.104.com.tw",
				DefaultScope: "rest:jobs",
				DefaultScopeAuthType: "company",
				GrantTypes:    []string{"wrong"},
				Scopes: []Scope{
					{Name: "rest:jobs:read", ScopeAuthType: "user"},
					{Name: "rest:jobs:list", ScopeAuthType: "user"},
				},
				Paths: []Path{
					{
						Name: "/{jobNo}",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job",
								Scopes:      []string{"rest:jobs:read"},
							},
						},
					},
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job list",
								Scopes:      []string{"rest:jobs:list"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "paths not defined",
			in: &Resource{
				Urn:         "urn:104:v3:rest:jobs",
				Uri:         "https://v3ms.104.com.tw/jobs",
				Name:        "jobs",
				Type:        "rest",
				AuthService: "https://v3auth.104.com.tw",
				DefaultScope: "rest:jobs",
				DefaultScopeAuthType: "company",
				GrantTypes:    []string{"client_credentials"},
				Scopes: []Scope{
					{Name: "jobs:v1.0:read", ScopeAuthType: ""},
					{Name: "jobs:v1.0:list", ScopeAuthType: ""},
				},
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "paths must not be empty",
			in: &Resource{
				Urn:         "urn:104:v3:rest:jobs",
				Uri:         "https://v3ms.104.com.tw/jobs",
				Name:        "jobs",
				Type:        "rest",
				AuthService: "https://v3auth.104.com.tw",
				DefaultScope: "rest:jobs",
				DefaultScopeAuthType: "company",
				GrantTypes:    []string{"client_credentials"},
				Scopes: []Scope{
					{Name: "jobs:v1.0:read", ScopeAuthType: ""},
					{Name: "jobs:v1.0:list", ScopeAuthType: ""},
				},
				Paths: []Path{},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "path name not defined",
			in: &Resource{
				Urn:          "urn:104:v3:resource:rest:jobs",
				Uri:          "https://v3ms.104.com.tw/jobs",
				Name:         "jobs",
				Type:         "rest",
				AuthService:  "https://v3auth.104.com.tw",
				DefaultScope: "rest:job",
				DefaultScopeAuthType: "company",
				GrantTypes:   []string{
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
					"client_credentials",
				},
				Scopes: []Scope{
					{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				Paths: []Path{
					{
						Methods: []Method{
							{
								Name:        "GET",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},
							},
						},
					},
					{
						Methods: []Method{
							{
								Name:        "GET",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:write"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "公司資料",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "methods must not be empty",
			in: &Resource{
				Urn:          "urn:104:v3:resource:rest:jobs",
				Uri:          "https://v3ms.104.com.tw/jobs",
				Name:         "jobs",
				Type:         "rest",
				AuthService:  "https://v3auth.104.com.tw",
				DefaultScope: "rest:job",
				DefaultScopeAuthType: "company",
				GrantTypes:   []string{
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
					"client_credentials",
				},
				Scopes: []Scope{
					{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				Paths: []Path{
					{
						Name: "/",
						Methods: []Method{},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "公司資料",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "invalid path name",
			in: &Resource{
				Urn:          "urn:104:v3:resource:rest:jobs",
				Uri:          "https://v3ms.104.com.tw/jobs",
				Name:         "jobs",
				Type:         "rest",
				AuthService:  "https://v3auth.104.com.tw",
				DefaultScope: "rest:job",
				DefaultScopeAuthType: "company",
				GrantTypes:   []string{
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
					"client_credentials",
				},
				Scopes: []Scope{
					{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				Paths: []Path{
					{
						Name: "jobs",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},
							},
						},
					},
					{
						Name: "jobs",
						Methods: []Method{
							{
								Name:        "POST",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:write"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "公司資料",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "invalid method name",
			in: &Resource{
				Urn:          "urn:104:v3:resource:rest:jobs",
				Uri:          "https://v3ms.104.com.tw/jobs",
				Name:         "jobs",
				Type:         "rest",
				AuthService:  "https://v3auth.104.com.tw",
				DefaultScope: "rest:job",
				DefaultScopeAuthType: "company",
				GrantTypes:   []string{
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
					"client_credentials",
				},
				Scopes: []Scope{
					{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				Paths: []Path{
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "Wrong",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:read", "rest:jobs:write"},
							},
						},
					},
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "post",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:write"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "公司資料",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "method has duplicate scope",
			in: &Resource{
				Urn:          "urn:104:v3:resource:rest:jobs",
				Uri:          "https://v3ms.104.com.tw/jobs",
				Name:         "jobs",
				Type:         "rest",
				AuthService:  "https://v3auth.104.com.tw",
				DefaultScope: "rest:job",
				DefaultScopeAuthType: "company",
				GrantTypes:   []string{
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
					"client_credentials",
				},
				Scopes: []Scope{
					{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				Paths: []Path{
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "取得 job 列表",
								Scopes:      []string{"rest:jobs:read", "rest:jobs:read"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "公司資料",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "method scope is not defined in the resource scope list",
			in: &Resource{
				Urn:         "urn:104:v3:rest:jobs",
				Uri:         "https://v3ms.104.com.tw/jobs",
				Name:        "jobs",
				Type:        "rest",
				AuthService: "https://v3auth.104.com.tw",
				DefaultScope: "rest:jobs",
				DefaultScopeAuthType: "company",
				GrantTypes:    []string{"client_credentials"},
				Scopes: []Scope{
					{Name: "rest:jobs:read", ScopeAuthType: "user"},
					{Name: "rest:jobs:list", ScopeAuthType: "user"},
				},
				Paths: []Path{
					{
						Name: "/{jobNo}",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job",
								Scopes:      []string{"rest:jobs:write"},
							},
						},
					},
					{
						Name: "/",
						Methods: []Method{
							{
								Name:        "GET",
								Description: "Get job list",
								Scopes:      []string{"rest:jobs:list"},
							},
						},
					},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "valid graphql resource",
			in: &Resource{
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
				Scopes: []Scope{
					{Name: "graphql:resumes:read", ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "graphql:resumes:edu:read", ScopeAuthType: "", Description: "關於rest:jobs:edu:read"},
					{Name: "graphql:resumes:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				GraphQLOperations: []GraphQLOperation{
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
			},
			check: func(t *testing.T, r *Resource) {},
		},
		{
			name: "graphql_operations not defined",
			in: &Resource{
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
				Scopes: []Scope{
					{Name: "graphql:resumes:read", ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "graphql:resumes:edu:read", ScopeAuthType: "", Description: "關於rest:jobs:edu:read"},
					{Name: "graphql:resumes:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "歷履表",
			},
			check: func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			name: "graphql_operations must not be empty",
			in: &Resource{
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
				Scopes: []Scope{
					{Name: "graphql:resumes:read", ScopeAuthType: "", Description: "關於rest:jobs:read"},
					{Name: "graphql:resumes:edu:read", ScopeAuthType: "", Description: "關於rest:jobs:edu:read"},
					{Name: "graphql:resumes:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				},
				GraphQLOperations: []GraphQLOperation{},
				Contacts:      []string{"someone@104.com.tw"},
				Description:   "歷履表",
			},
			check: func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%s", tc.name), func(t *testing.T) {
			if tc.v == nil {
				tc.v = v
			}
			err := tc.v.Validate(tc.in)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tc.check(t, tc.in)
			}
		})
	}
}
