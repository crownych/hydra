package swagger_test

import (
	"fmt"
	. "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func _TestOAuth2API(t *testing.T) {
	var serverURL = "http://localhost:4444"

	oauth2Api := NewOAuth2ApiWithBasePath(serverURL)
	timeout := 5 * time.Second
	oauth2Api.Configuration.Timeout = &timeout

	authSrvPubKey := &JsonWebKey{
		Use: "sig",
		Kty: "EC",
		Kid: "public:7c337717-688f-453a-8c5e-d4601b4f79b6",
		Crv: "P-256",
		Alg: "ES256",
		X:   "SuUAlWvVgSSnyUlu6D5lKryGW71Zlp6iHils0iekJn4",
		Y:   "-RlN-Kk9VtncQ4Oev5rQGNTvruZ63mz_2XSACU2Jpt8",
	}

	t.Run("case=get oauth authorization server metadata", func(t *testing.T) {
		wellKnown, _, err := oauth2Api.GetWellKnown(authSrvPubKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, wellKnown.Issuer)
		fmt.Println("WellKnown: ", wellKnown)
	})

	t.Run("case=get oauth authorization server jwks.json", func(t *testing.T) {
		jwks, _, err := oauth2Api.WellKnown()
		assert.NoError(t, err)
		assert.NotNil(t, jwks)
		fmt.Println("jwks: ", jwks)
	})

	t.Run("case=get oauth 2.0 client", func(t *testing.T) {
		clients, _, err := oauth2Api.ListOAuth2Clients(authSrvPubKey, 100, 0)
		assert.NoError(t, err)
		fmt.Println("clients: ", clients)
	})

	t.Run("case=get oauth 2.0 resources", func(t *testing.T) {
		resources, _, err := oauth2Api.ListOAuth2Resources(authSrvPubKey, 100, 0)
		assert.NoError(t, err)
		fmt.Println("resources: ", resources)
	})
}
