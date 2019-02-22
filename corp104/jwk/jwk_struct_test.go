package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"testing"
	"time"
)

func TestJSONWebKeySet(t *testing.T) {
	jwks := &pkg.JSONWebKeySet{Keys: []pkg.JSONWebKey{}}
	generator := &ECDSA256Generator{}
	key1, err := generator.Generate("key-1", "sig")
	assert.NoError(t, err)
	for _, k := range key1.Keys {
		jwks.Keys = append(jwks.Keys, k)
	}
	key2, err := generator.Generate("key-2", "sig")
	assert.NoError(t, err)
	for _, k := range key2.Keys {
		jwks.Keys = append(jwks.Keys, k)
	}
	assert.Equal(t, 4, len(jwks.Keys))
	assert.Equal(t, "private:key-1", jwks.Key("private:key-1")[0].KeyID)
	assert.Equal(t, "public:key-1", jwks.Key("public:key-1")[0].KeyID)
	assert.Equal(t, "private:key-2", jwks.Key("private:key-2")[0].KeyID)
	assert.Equal(t, "public:key-2", jwks.Key("public:key-2")[0].KeyID)
}

func TestJSONWebKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	now := time.Now().UTC().Unix()
	anHourBefore := now - 3600
	anHourLater := now + 3600

	for _, tc := range []struct {
		name	  string
		in        *pkg.JSONWebKey
		check     func(t *testing.T, r *pkg.JSONWebKey)
	}{
		{
			name: "JSONWebKey is active when the `NotBefore` and `ExpiresAt` parameters are nil",
			in: &pkg.JSONWebKey{
				JSONWebKey: jose.JSONWebKey{
					Key: key,
					KeyID: "private:" + uuid.New(),
					Algorithm: "ES256",
					Use: "sig",
				},
			},
			check: func(t *testing.T, k *pkg.JSONWebKey){
				assert.True(t, k.IsActive())
			},
		},
		{
			name: "JSONWebKey is active when the `ExpiresAt` parameters is greater than the present",
			in: &pkg.JSONWebKey{
				JSONWebKey: jose.JSONWebKey{
					Key: key,
					KeyID: "private:" + uuid.New(),
					Algorithm: "ES256",
					Use: "sig",
				},
				ExpiresAt: &anHourLater,
			},
			check: func(t *testing.T, k *pkg.JSONWebKey){
				assert.True(t, k.IsActive())
			},
		},
		{
			name: "JSONWebKey is inactive when the `NotBefore` parameter is greater than the present",
			in: &pkg.JSONWebKey{
				JSONWebKey: jose.JSONWebKey{
					Key: key,
					KeyID: "private:" + uuid.New(),
					Algorithm: "ES256",
					Use: "sig",
				},
				NotBefore: &anHourLater,
			},
			check: func(t *testing.T, k *pkg.JSONWebKey){
				assert.False(t, k.IsActive())
			},
		},
		{
			name: "JSONWebKey is expired when the `ExpiresAt` parameters is less than or equal to the present",
			in: &pkg.JSONWebKey{
				JSONWebKey: jose.JSONWebKey{
					Key: key,
					KeyID: "private:" + uuid.New(),
					Algorithm: "ES256",
					Use: "sig",
				},
				ExpiresAt: &anHourBefore,
			},
			check: func(t *testing.T, k *pkg.JSONWebKey){
				assert.True(t, k.IsExpired())
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%s", tc.name), func(t *testing.T) {
			tc.check(t, tc.in)
		})
	}
}



