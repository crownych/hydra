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

package jwk

import (
	"fmt"
	"net/http"
	"sync"

	"context"

	"github.com/ory/fosite"
	"github.com/ory/hydra/pkg"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

type MemoryManager struct {
	Keys map[string]*pkg.JSONWebKeySet
	sync.RWMutex
}

func (m *MemoryManager) AddKey(ctx context.Context, set string, key *pkg.JSONWebKey) error {
	m.Lock()
	defer m.Unlock()

	m.alloc()
	if m.Keys[set] == nil {
		m.Keys[set] = &pkg.JSONWebKeySet{Keys: []pkg.JSONWebKey{}}
	}

	for _, k := range m.Keys[set].Keys {
		if k.KeyID == key.KeyID {
			return errors.WithStack(&fosite.RFC6749Error{
				Code:        http.StatusConflict,
				Name:        http.StatusText(http.StatusConflict),
				Description: fmt.Sprintf("Unable to create key with kid \"%s\" in set \"%s\" because that kid already exists in the set.", key.KeyID, set),
			})
		}
	}

	m.Keys[set].Keys = append([]pkg.JSONWebKey{*key}, m.Keys[set].Keys...)
	return nil
}

func (m *MemoryManager) AddKeySet(ctx context.Context, set string, keys *pkg.JSONWebKeySet) error {
	for _, key := range keys.Keys {
		err := m.AddKey(ctx, set, &key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *MemoryManager) GetKey(ctx context.Context, set, kid string) (*jose.JSONWebKeySet, error) {
	jwks, err := m.GetActualKey(ctx, set, kid)
	if err != nil {
		return nil, err
	}

	return jwks.ToJoseJSONWebKeySet(), nil
}

func (m *MemoryManager) GetKeySet(ctx context.Context, set string) (*jose.JSONWebKeySet, error) {
	jwks, err := m.GetActualKeySet(ctx, set, ActiveJWKFilter)
	if err != nil {
		return nil, err
	}

	return jwks.ToJoseJSONWebKeySet(), nil
}

func (m *MemoryManager) GetActualKey(ctx context.Context, set, kid string) (*pkg.JSONWebKeySet, error) {
	m.RLock()
	defer m.RUnlock()

	m.alloc()
	keys, found := m.Keys[set]
	if !found {
		return nil, errors.WithStack(pkg.ErrNotFound)
	}

	result := keys.Key(kid)
	if len(result) == 0 {
		return nil, errors.WithStack(pkg.ErrNotFound)
	}

	return &pkg.JSONWebKeySet{
		Keys: result,
	}, nil
}

func (m *MemoryManager) GetActualKeySet(ctx context.Context, set string, filter... func(pkg.JSONWebKey) bool) (*pkg.JSONWebKeySet, error) {
	m.RLock()
	defer m.RUnlock()

	m.alloc()
	keys, found := m.Keys[set]
	if !found {
		return nil, errors.WithStack(pkg.ErrNotFound)
	}

	if len(filter) > 0 {
		var fKeys []pkg.JSONWebKey
		for _, key := range keys.Keys {
			if filter[0](key) {
				fKeys = append(fKeys, key)
			}
		}
		keys.Keys = fKeys
	}

	if len(keys.Keys) == 0 {
		return nil, errors.WithStack(pkg.ErrNotFound)
	}

	return keys, nil
}

func (m *MemoryManager) DeleteKey(ctx context.Context, set, kid string) error {
	keys, err := m.GetActualKeySet(ctx, set)
	if err != nil {
		return err
	}

	m.Lock()
	var results []pkg.JSONWebKey
	for _, key := range keys.Keys {
		if key.KeyID != kid {
			results = append(results, key)
		}
	}
	m.Keys[set].Keys = results
	defer m.Unlock()

	return nil
}

func (m *MemoryManager) DeleteKeySet(ctx context.Context, set string) error {
	m.Lock()
	defer m.Unlock()

	delete(m.Keys, set)
	return nil
}

func (m *MemoryManager) alloc() {
	if m.Keys == nil {
		m.Keys = make(map[string]*pkg.JSONWebKeySet)
	}
}
