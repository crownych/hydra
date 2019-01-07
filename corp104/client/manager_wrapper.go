package client

import (
	"context"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/hydra/corp104/resource"
)

type ManagerWrapper struct {
	Manager
	ResourceManager resource.Manager
}

func (m *ManagerWrapper) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	c, err := m.GetConcreteClient(ctx, id)
	if err != nil {
		return c, err
	}
	// Scope 中包含 resource 定義
	if strings.Contains(c.Scope, resource.UrnPrefix) {
		// 取得 resource scopes
		rsmap, err := m.ResourceManager.GetResourceScopeMap(ctx)
		if err != nil {
			return c, err
		}
		// 將 resource urn 轉換為對應的 scopes
		for _, scope := range c.GetScopes() {
			if strings.HasPrefix(scope, resource.UrnPrefix) {
				c.Scope = strings.Replace(c.Scope, scope, strings.Join(rsmap[scope], " "), 1)
			}
		}
	}
	return c, nil
}