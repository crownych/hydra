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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

type ECDSA256Generator struct{}

func (g *ECDSA256Generator) Generate(id, use string, options ...map[string]interface{}) (*pkg.JSONWebKeySet, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Errorf("Could not generate key because %s", err)
	}

	if id == "" {
		id = uuid.New()
	}

	var notBefore, expiresAt *int64
	if len(options) > 0 {
		props := options[0]
		if props["nbf"] != nil {
			switch nbf := props["nbf"].(type) {
			case *int64:
				notBefore = nbf
			case int64:
				notBefore = &nbf
			default:
				return nil, errors.New("Could not generate key because \"nbf\" is invalid")
			}
		}
		if props["exp"] != nil {
			switch exp := props["exp"].(type) {
			case *int64:
				expiresAt = exp
			case int64:
				expiresAt = &exp
			default:
				return nil, errors.New("Could not generate key because \"exp\" is invalid")
			}
		}
	}

	return &pkg.JSONWebKeySet{
		Keys: []pkg.JSONWebKey{
			{
				JSONWebKey: jose.JSONWebKey{
					Algorithm:    "ES256",
					Key:          key,
					Use:          use,
					KeyID:        ider("private", id),
					Certificates: []*x509.Certificate{},
				},
				NotBefore: notBefore,
				ExpiresAt: expiresAt,
			},
			{
				JSONWebKey: jose.JSONWebKey{
					Algorithm:    "ES256",
					Key:          &key.PublicKey,
					Use:          use,
					KeyID:        ider("public", id),
					Certificates: []*x509.Certificate{},
				},
				NotBefore: notBefore,
				ExpiresAt: expiresAt,
			},
		},
	}, nil
}
