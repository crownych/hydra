package resource

import (
	"context"
	"sync"

	"github.com/imdario/mergo"
	"github.com/ory/pagination"
	"github.com/ory/sqlcon"
	"github.com/pkg/errors"
)

type MemoryManager struct {
	Resources []Resource
	sync.RWMutex
}

func NewMemoryManager() *MemoryManager {
	return &MemoryManager{
		Resources: []Resource{},
	}
}

func (m *MemoryManager) GetResource(ctx context.Context, urn string) (*Resource, error) {
	m.RLock()
	defer m.RUnlock()

	for _, r := range m.Resources {
		if r.GetUrn() == urn {
			return &r, nil
		}
	}

	return nil, errors.WithStack(sqlcon.ErrNoRows)
}

func (m *MemoryManager) UpdateResource(ctx context.Context, r *Resource) error {
	o, err := m.GetResource(ctx, r.GetUrn())
	if err != nil {
		return err
	}

	if err := mergo.Merge(r, o); err != nil {
		return errors.WithStack(err)
	}

	m.Lock()
	defer m.Unlock()
	for k, f := range m.Resources {
		if f.GetUrn() == r.GetUrn() {
			m.Resources[k] = *r
		}
	}

	return nil
}

func (m *MemoryManager) CreateResource(ctx context.Context, r *Resource) error {
	if _, err := m.GetResource(ctx, r.GetUrn()); err == nil {
		return sqlcon.ErrUniqueViolation
	}

	m.Lock()
	defer m.Unlock()

	m.Resources = append(m.Resources, *r)
	return nil
}

func (m *MemoryManager) DeleteResource(ctx context.Context, urn string) error {
	m.Lock()
	defer m.Unlock()

	for k, f := range m.Resources {
		if f.GetUrn() == urn {
			m.Resources = append(m.Resources[:k], m.Resources[k+1:]...)
			return nil
		}
	}

	return nil
}

func (m *MemoryManager) GetResources(ctx context.Context, limit, offset int) (map[string]Resource, error) {
	m.RLock()
	defer m.RUnlock()
	resources := make(map[string]Resource)

	start, end := pagination.Index(limit, offset, len(m.Resources))
	for _, r := range m.Resources[start:end] {
		resources[r.GetUrn()] = r
	}

	return resources, nil
}

func (m *MemoryManager) GetAllScopeNames() ([]string, error) {
	m.RLock()
	defer m.RUnlock()

	var scopes []string
	for _, resource := range m.Resources {
		for _, scope := range resource.Scopes {
			scopes = append(scopes, scope.Name)
		}
	}

	return scopes, nil
}
