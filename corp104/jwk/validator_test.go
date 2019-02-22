package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"testing"
)

func TestValidate(t *testing.T) {
	v := NewValidator()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	kid := uuid.New()

	for _, tc := range []struct {
		name      string
		in        *KeysMetadata
		expectErr bool
	}{
		{
			name: `valid keys_metadata then pass`,
			in: &KeysMetadata{
				Set: "test",
				JWKS: pkg.JSONWebKeySet{
					Keys: []pkg.JSONWebKey{
						{
							JSONWebKey: jose.JSONWebKey{
								Key: key,
								KeyID: "private:" + kid,
								Algorithm: "ES256",
								Use: "sig",
							},
						},
						{
							JSONWebKey: jose.JSONWebKey{
								Key: key.Public(),
								KeyID: "public:" + kid,
								Algorithm: "ES256",
								Use: "sig",
							},
						},
					},
				},
			},
		},
		{
			name: `key set id not set then fail`,
			in: &KeysMetadata{
				JWKS: pkg.JSONWebKeySet{
					Keys: []pkg.JSONWebKey{
						{
							JSONWebKey: jose.JSONWebKey{
								Key: key,
								KeyID: "private:" + kid,
								Algorithm: "ES256",
								Use: "sig",
							},
						},
						{
							JSONWebKey: jose.JSONWebKey{
								Key: key.Public(),
								KeyID: "public:" + kid,
								Algorithm: "ES256",
								Use: "sig",
							},
						},
					},
				},
			},
			expectErr: true,
		},
		{
			name: `keys is empty then fail`,
			in: &KeysMetadata{
				Set: "test",
			},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%s", tc.name), func(t *testing.T) {
			err := v.Validate(tc.in)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
