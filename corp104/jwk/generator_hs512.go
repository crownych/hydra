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
	"crypto/rand"
	"crypto/x509"
	"github.com/ory/hydra/pkg"
	"io"

	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

type HS512Generator struct{}

func (g *HS512Generator) Generate(id, use string, options ...map[string]interface{}) (*pkg.JSONWebKeySet, error) {
	// Taken from NewHMACKey
	key := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if id == "" {
		id = uuid.New()
	}

	var sliceKey = key[:]

	var notBefore, expiresAt *int64
	if len(options) > 0 {
		props := options[0]
		if props["nbf"] != nil {
			notBefore = props["nbf"].(*int64)
		}
		if props["exp"] != nil {
			expiresAt = props["exp"].(*int64)
		}
	}

	return &pkg.JSONWebKeySet{
		Keys: []pkg.JSONWebKey{
			{
				JSONWebKey: jose.JSONWebKey{
					Algorithm:    "HS512",
					Key:          sliceKey,
					Use:          use,
					KeyID:        id,
					Certificates: []*x509.Certificate{},
				},
				NotBefore: notBefore,
				ExpiresAt: expiresAt,
			},
		},
	}, nil
}
