package resource

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidate(t *testing.T) {
	v := NewValidator()

	for k, tc := range []struct {
		in        *Resource
		check     func(t *testing.T, r *Resource)
		expectErr bool
		v         *Validator
	}{
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Scopes: []Scope{
					{Name: "job:v1.0:read", AuthType: "user"},
					{Name: "job:v1.0:list", AuthType: "user"},
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
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Version:       "1.0",
				Contacts:      []string{"someone@104.com.tw"},
				ScopeAuthType: "client",
				Description:   "Job data",
			},
			check: func(t *testing.T, r *Resource) {},
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Scopes: []Scope{
					{Name: "job:v1.0:read", AuthType: "user"},
					{Name: "job:v1.0:list", AuthType: "user"},
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
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Version:       "1.0",
				Contacts:      []string{"someone@104.com.tw"},
				ScopeAuthType: "wrong",
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Scopes: []Scope{
					{Name: "job:v1.0:read", AuthType: "wrong"},
					{Name: "job:v1.0:list", AuthType: "user"},
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
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Version:       "1.0",
				Contacts:      []string{"someone@104.com.tw"},
				ScopeAuthType: "company",
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
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
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				Version:       "1.0",
				Contacts:      []string{"someone@104.com.tw"},
				ScopeAuthType: "user",
				Description:   "Job data",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "http://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Version:     "1.0",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job#ha",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Version:     "1.0",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:           "urn:104:v3:job:v1.0",
				Uri:           "https://v3ms.104.com.tw/job",
				Name:          "job",
				AuthService:   "https://v3auth.104.com.tw",
				Version:       "1.0",
				ScopeAuthType: "none",
				GrantTypes:    []string{"wrong"},
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:           "urn:104:v3:job:v1.0",
				Uri:           "https://v3ms.104.com.tw/job",
				Name:          "job",
				AuthService:   "https://v3auth.104.com.tw",
				Version:       "1.0",
				ScopeAuthType: "none",
				GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:jwt-bearer", "wrong"},
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "_job",
				AuthService: "https://v3auth.104.com.tw",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Version:     "v1",
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Version:     "1.0",
				Scopes: []Scope{
					{Name: "resume:v1.0:read", AuthType: "user"},
					{Name: "resume:v1.0:list", AuthType: "user"},
				},
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
		{
			in: &Resource{
				Urn:         "urn:104:v3:job:v1.0",
				Uri:         "https://v3ms.104.com.tw/job",
				Name:        "job",
				AuthService: "https://v3auth.104.com.tw",
				Version:     "1.0",
				Scopes: []Scope{
					{Name: "resume:v1.0:read", AuthType: "user"},
					{Name: "resume:v1.0:read", AuthType: "user"},
				},
			},
			check:     func(t *testing.T, r *Resource) {},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
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
