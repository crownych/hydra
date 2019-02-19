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
	"context"
	"github.com/104corp/vip3-go-auth/vip3auth/di"
	"github.com/ory/hydra/pkg"
)

var (
	ActiveJWKFilter    = func(key pkg.JSONWebKey) bool { return key.IsActive() }
	wellKnownJWKFilter = func(key pkg.JSONWebKey) bool { return !key.IsExpired() }
)

type Manager interface {
	di.KeyStore

	AddKey(ctx context.Context, set string, key *pkg.JSONWebKey) error

	AddKeySet(ctx context.Context, set string, keys *pkg.JSONWebKeySet) error

	GetActualKey(ctx context.Context, set, kid string) (*pkg.JSONWebKeySet, error)

	// 指定 filter 時，只會將回傳 true 的 keys 會加到 JSONWebKeySet 中
	GetActualKeySet(ctx context.Context, set string, filter... func(pkg.JSONWebKey) bool) (*pkg.JSONWebKeySet, error)

	DeleteKey(ctx context.Context, set, kid string) error

	DeleteKeySet(ctx context.Context, set string) error
}
