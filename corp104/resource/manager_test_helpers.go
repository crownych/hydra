package resource

import (
	"testing"

	"context"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelperCreateGetDeleteResource(k string, m Manager) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		ctx := context.TODO()
		_, err := m.GetResource(ctx, "urn:104:v3:resource:resume:v1.0")
		assert.NotNil(t, err)

		c := &Resource{
			Urn:         "urn:104:v3:resource:resume:v1.0",
			Uri:         "https://v3ms.104.com.tw/resume/v1.0",
			Name:        "resume",
			AuthService: "https://auth.v3.104.com.tw",
			Scopes: []Scope{
				{Name: "resume:v1.0:semi-read", AuthType: "", Description: "讀半顯履歷資料"},
				{Name: "resume:v1.0:read", AuthType: "", Description: "讀履歷資料"},
			},
			Paths: []Path{
				{
					Name: "/{resume_id}",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 resume 資料",
							Scopes:      []string{"resume:v1.0:semi-read", "resume:v1.0:read"},
						},
					},
				},
				{
					Name: "/",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 resume 列表",
							Scopes:      []string{"resume:v1.0:semi-read", "resume:v1.0:read"},
						},
					},
				},
			},
			GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
			Version:       "1.0",
			Contacts:      []string{"some.one@104.com.tw"},
			ScopeAuthType: "company",
			Description:   "履歷資料API",
		}
		assert.NoError(t, m.CreateResource(ctx, c))
		assert.Equal(t, "urn:104:v3:resource:resume:v1.0", c.Urn)
		assert.Equal(t, "urn:104:v3:resource:resume:v1.0", c.GetUrn())

		d, err := m.GetResource(ctx, c.GetUrn())
		require.NoError(t, err)
		assert.Equal(t, "urn:104:v3:resource:resume:v1.0", d.Urn)
		assert.Equal(t, "urn:104:v3:resource:resume:v1.0", d.GetUrn())

		assert.NoError(t, m.CreateResource(ctx, &Resource{
			Urn:         "urn:104:v3:resource:resume:v2.0",
			Uri:         "https://v3ms.104.com.tw/resume/v2.0",
			Name:        "resume",
			AuthService: "https://auth.v3.104.com.tw",
			Scopes: []Scope{
				{Name: "resume:v2.0:semi-read", AuthType: "", Description: "讀半顯履歷資料"},
				{Name: "resume:v2.0:read", AuthType: "", Description: "讀履歷資料"},
			},
			Paths: []Path{
				{
					Name: "/{resume_id}",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 resume 資料",
							Scopes:      []string{"resume:v2.0:semi-read", "resume:v2.0:read"},
						},
					},
				},
				{
					Name: "/",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 resume 列表",
							Scopes:      []string{"resume:v2.0:semi-read", "resume:v2.0:read"},
						},
					},
				},
			},
			GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
			Version:       "2.0",
			Contacts:      []string{"some.one@104.com.tw"},
			ScopeAuthType: "company",
			Description:   "履歷資料API",
		}))

		ds, err := m.GetResources(ctx, 100, 0)
		assert.NoError(t, err)
		assert.Len(t, ds, 2)
		assert.NotEqual(t, ds["urn:104:v3:resource:resume:v1.0"].Urn, ds["urn:104:v3:resource:resume:v2.0"].Urn)

		//test if properties were set properly
		assert.Equal(t, ds["urn:104:v3:resource:resume:v1.0"].Uri, c.Uri)
		assert.Equal(t, ds["urn:104:v3:resource:resume:v1.0"].Name, c.Name)
		assert.Equal(t, ds["urn:104:v3:resource:resume:v1.0"].AuthService, c.AuthService)
		assert.EqualValues(t, ds["urn:104:v3:resource:resume:v1.0"].Scopes, c.Scopes)
		assert.EqualValues(t, ds["urn:104:v3:resource:resume:v1.0"].Paths, c.Paths)
		assert.EqualValues(t, ds["urn:104:v3:resource:resume:v1.0"].GrantTypes, c.GrantTypes)
		assert.Equal(t, ds["urn:104:v3:resource:resume:v1.0"].Version, c.Version)
		assert.EqualValues(t, ds["urn:104:v3:resource:resume:v1.0"].Contacts, c.Contacts)
		assert.Equal(t, ds["urn:104:v3:resource:resume:v1.0"].ScopeAuthType, c.ScopeAuthType)
		assert.Equal(t, ds["urn:104:v3:resource:resume:v1.0"].Description, c.Description)

		ds, err = m.GetResources(ctx, 1, 0)
		assert.NoError(t, err)
		assert.Len(t, ds, 1)

		ds, err = m.GetResources(ctx, 100, 100)
		assert.NoError(t, err)
		assert.Len(t, ds, 0)

		err = m.UpdateResource(ctx, &Resource{
			Urn:         "urn:104:v3:resource:resume:v2.0",
			Uri:         "https://v3ms.104.com.tw/resume/v2.0",
			Name:        "resume",
			AuthService: "https://auth.v3.104.com.tw",
			Scopes: []Scope{
				{Name: "resume:v2.0:semi-read", AuthType: "company", Description: "讀半顯履歷資料"},
				{Name: "resume:v2.0:read", AuthType: "company", Description: "讀履歷資料"},
			},
			Paths: []Path{
				{
					Name: "/{resume_id}",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 resume 資料-update",
							Scopes:      []string{"resume:v2.0:semi-read", "resume:v2.0:read"},
						},
					},
				},
				{
					Name: "/",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 resume 列表-update",
							Scopes:      []string{"resume:v2.0:semi-read", "resume:v2.0:read"},
						},
					},
				},
			},
			GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
			Version:       "2.0",
			Contacts:      []string{"some.two@104.com.tw"},
			ScopeAuthType: "company",
			Description:   "履歷資料API-update",
		})
		require.NoError(t, err)

		nc, err := m.GetResource(ctx, "urn:104:v3:resource:resume:v2.0")
		require.NoError(t, err)

		assert.EqualValues(t, []Scope{
			{Name: "resume:v2.0:semi-read", AuthType: "company", Description: "讀半顯履歷資料"},
			{Name: "resume:v2.0:read", AuthType: "company", Description: "讀履歷資料"},
		}, nc.Scopes)
		assert.EqualValues(t, []Path{
			{
				Name: "/{resume_id}",
				Methods: []Method{
					{
						Name:        "GET",
						Description: "取得 resume 資料-update",
						Scopes:      []string{"resume:v2.0:semi-read", "resume:v2.0:read"},
					},
				},
			},
			{
				Name: "/",
				Methods: []Method{
					{
						Name:        "GET",
						Description: "取得 resume 列表-update",
						Scopes:      []string{"resume:v2.0:semi-read", "resume:v2.0:read"},
					},
				},
			},
		}, nc.Paths)
		assert.EqualValues(t, []string{"some.two@104.com.tw"}, nc.Contacts)
		assert.Equal(t, "履歷資料API-update", nc.Description)

		err = m.DeleteResource(ctx, "urn:104:v3:resource:resume:v1.0")
		assert.NoError(t, err)

		err = m.DeleteResource(ctx, "urn:104:v3:resource:resume:v2.0")
		assert.NoError(t, err)

		_, err = m.GetResource(ctx, "urn:104:v3:resource:resume:v1.0")
		assert.NotNil(t, err)
	}
}
