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
		_, err := m.GetResource(ctx, "urn:104:v3:resource:rest:jobs")
		assert.NotNil(t, err)

		c := &Resource{
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
							Scopes:      []string{"rest:job:read", "rest:jobs:write"},
						},
					},
				},
				{
					Name: "/",
					Methods: []Method{
						{
							Name:        "POST",
							Description: "取得 job 列表",
							Scopes:      []string{"rest:job:write"},
						},
					},
				},
				{
					Name: "/{jobNo}",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 job 資料",
							Scopes:      []string{"rest:job:read", "rest:jobs:write"},

						},
					},
				},
				{
					Name: "/{jobNo}",
					Methods: []Method{
						{
							Name:        "DELETE",
							Description: "刪除 job 資料",
							Scopes:      []string{"rest:job:write"},
						},
					},
				},
				{
					Name: "/{jobNo}",
					Methods: []Method{
						{
							Name:        "PATCH",
							Description: "修改 job 資料",
							Scopes:      []string{"rest:job:write"},
						},
					},
				},
			},
			Contacts:      []string{"someone@104.com.tw"},
			Description:   "公司資料",
		}
		assert.NoError(t, m.CreateResource(ctx, c))
		assert.Equal(t, "urn:104:v3:resource:rest:jobs", c.Urn)
		assert.Equal(t, "urn:104:v3:resource:rest:jobs", c.GetUrn())

		d, err := m.GetResource(ctx, c.GetUrn())
		require.NoError(t, err)
		assert.Equal(t, "urn:104:v3:resource:rest:jobs", d.Urn)
		assert.Equal(t, "urn:104:v3:resource:rest:jobs", d.GetUrn())

		//create duplicate resource should fail
		assert.Error(t, m.CreateResource(ctx, c))

		ds, err := m.GetResources(ctx, 100, 0)
		assert.NoError(t, err)
		assert.Len(t, ds, 1)
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].Urn, ds["urn:104:v3:resource:rest:jobs"].Urn)

		//test if properties were set properly
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].Uri, c.Uri)
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].Name, c.Name)
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].Type, c.Type)
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].AuthService, c.AuthService)
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].DefaultScope, c.DefaultScope)
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].DefaultScopeAuthType, c.DefaultScopeAuthType)
		assert.EqualValues(t, ds["urn:104:v3:resource:rest:jobs"].GrantTypes, c.GrantTypes)
		assert.EqualValues(t, ds["urn:104:v3:resource:rest:jobs"].Scopes, c.Scopes)
		assert.EqualValues(t, ds["urn:104:v3:resource:rest:jobs"].Paths, c.Paths)
		assert.EqualValues(t, ds["urn:104:v3:resource:rest:jobs"].Contacts, c.Contacts)
		assert.Equal(t, ds["urn:104:v3:resource:rest:jobs"].Description, c.Description)

		ds, err = m.GetResources(ctx, 1, 0)
		assert.NoError(t, err)
		assert.Len(t, ds, 1)

		ds, err = m.GetResources(ctx, 100, 100)
		assert.NoError(t, err)
		assert.Len(t, ds, 0)

		err = m.UpdateResource(ctx, &Resource{
			Urn:         "urn:104:v3:resource:rest:jobs",
			Uri:         "https://v3ms.104.com.tw/jobs",
			Name:        "jobs",
			Type:		 "rest",
			AuthService: "https://auth.v3.104.com.tw",
			DefaultScope: "rest:job",
			DefaultScopeAuthType: "company",
			GrantTypes:   []string{
				"urn:ietf:params:oauth:grant-type:jwt-bearer",
				"client_credentials",
			},
			Scopes: []Scope{
				{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
				{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
				{Name: "rest:jobs:list",  ScopeAuthType: "", Description: "關於rest:jobs:list"},
			},
			Paths: []Path{
				{
					Name: "/",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 job 列表",
							Scopes:      []string{"rest:job:list"},
						},
					},
				},
				{
					Name: "/",
					Methods: []Method{
						{
							Name:        "POST",
							Description: "取得 job 列表",
							Scopes:      []string{"rest:job:read", "rest:job:write"},
						},
					},
				},
				{
					Name: "/{jobNo}",
					Methods: []Method{
						{
							Name:        "GET",
							Description: "取得 job 資料",
							Scopes:      []string{"rest:job:read"},

						},
					},
				},
				{
					Name: "/{jobNo}",
					Methods: []Method{
						{
							Name:        "DELETE",
							Description: "刪除 job 資料",
							Scopes:      []string{"rest:job:read", "rest:job:write"},
						},
					},
				},
				{
					Name: "/{jobNo}",
					Methods: []Method{
						{
							Name:        "PATCH",
							Description: "修改 job 資料",
							Scopes:      []string{"rest:job:read", "rest:job:write"},
						},
					},
				},
			},
			Contacts:      []string{"some.two@104.com.tw"},
			Description:   "公司資料-update",
		})
		require.NoError(t, err)

		nc, err := m.GetResource(ctx, "urn:104:v3:resource:rest:jobs")
		require.NoError(t, err)

		assert.EqualValues(t, []Scope{
			{Name: "rest:jobs:read",  ScopeAuthType: "", Description: "關於rest:jobs:read"},
			{Name: "rest:jobs:write", ScopeAuthType: "", Description: "關於rest:jobs:write"},
			{Name: "rest:jobs:list",  ScopeAuthType: "", Description: "關於rest:jobs:list"},
		}, nc.Scopes)
		assert.EqualValues(t, []Path{
			{
				Name: "/",
				Methods: []Method{
					{
						Name:        "GET",
						Description: "取得 job 列表",
						Scopes:      []string{"rest:job:list"},
					},
				},
			},
			{
				Name: "/",
				Methods: []Method{
					{
						Name:        "POST",
						Description: "取得 job 列表",
						Scopes:      []string{"rest:job:read", "rest:job:write"},
					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []Method{
					{
						Name:        "GET",
						Description: "取得 job 資料",
						Scopes:      []string{"rest:job:read"},

					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []Method{
					{
						Name:        "DELETE",
						Description: "刪除 job 資料",
						Scopes:      []string{"rest:job:read", "rest:job:write"},
					},
				},
			},
			{
				Name: "/{jobNo}",
				Methods: []Method{
					{
						Name:        "PATCH",
						Description: "修改 job 資料",
						Scopes:      []string{"rest:job:read", "rest:job:write"},
					},
				},
			},
		}, nc.Paths)
		assert.EqualValues(t, []string{"some.two@104.com.tw"}, nc.Contacts)
		assert.Equal(t, "公司資料-update", nc.Description)

		err = m.DeleteResource(ctx, "urn:104:v3:resource:rest:jobs")
		assert.NoError(t, err)

		_, err = m.GetResource(ctx, "urn:104:v3:resource:rest:jobs")
		assert.NotNil(t, err)
	}
}
