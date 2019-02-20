package swagger_test

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	. "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

// [Prerequisite] register resources & clients before testing
func _TestOAuth2API(t *testing.T) {
	var serverURL = "http://localhost:4444"

	oauth2Api := NewOAuth2ApiWithBasePath(serverURL)
	timeout := 5 * time.Second
	oauth2Api.Configuration.Timeout = &timeout

	oauth2Api.Configuration.PrivateJWK = &JsonWebKey{
		Crv: "P-256",
		Alg: "ES256",
		Kty: "EC",
		Use: "sig",
		Kid: "private:89b940e8-a16f-48ce-a238-b52d7e252634",
		X: "6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA",
		Y: "kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg",
		D: "G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo",
	}

	oauth2Api.Configuration.AuthSvcOfflinePublicJWK = &JsonWebKey{
		Crv: "P-256",
		Alg: "ES256",
		Use: "sig",
		Kty: "EC",
		Kid: "public:7c337717-688f-453a-8c5e-d4601b4f79b6",
		X:   "SuUAlWvVgSSnyUlu6D5lKryGW71Zlp6iHils0iekJn4",
		Y:   "-RlN-Kk9VtncQ4Oev5rQGNTvruZ63mz_2XSACU2Jpt8",
	}

	t.Run("case=get oauth authorization server metadata", func(t *testing.T) {
		wellKnown, _, err := oauth2Api.GetWellKnown()
		assert.NoError(t, err)
		assert.NotEmpty(t, wellKnown.Issuer)
	})

	t.Run("case=get oauth authorization server jwks.json", func(t *testing.T) {
		jwks, _, err := oauth2Api.WellKnown()
		assert.NoError(t, err)
		assert.NotNil(t, jwks)
	})

	t.Run("case=get oauth 2.0 client", func(t *testing.T) {
		// [WARNING] this is for backend admin router only
		clients, _, err := oauth2Api.ListOAuth2Clients(100, 0)
		assert.NoError(t, err)
		assert.NotEmpty(t, clients)
	})

	t.Run("case=get oauth 2.0 resources", func(t *testing.T) {
		resources, _, err := oauth2Api.ListOAuth2Resources(100, 0)
		assert.NoError(t, err)
		assert.NotEmpty(t, resources)
	})

	t.Run("case=get oauth 2.0 client assertion", func(t *testing.T) {
		// set client ID & PrivateJWK
		oauth2Api.Configuration.Username = "client:" + uuid.New()
		popJWKS, err := oauth2Api.GetPoPKeyPair(uuid.New())
		assert.NoError(t, err)
		clientAssertion, err := oauth2Api.CreateOAuth2ClientAssertion(popJWKS)
		assert.NoError(t, err)
		assert.NotEmpty(t, clientAssertion)
		// 使用 client 的 public key 驗證 assertion
		ecPubKey, err := LoadECPublicKeyFromJsonWebKey(oauth2Api.Configuration.PrivateJWK)
		_, err = jws.Verify([]byte(clientAssertion), jwa.ES256, ecPubKey)
		assert.NoError(t, err)
	})

	t.Run("case=get oauth 2.0 access token", func(t *testing.T) {
		// Note: register client before running this test case
		// set client ID & PrivateJWK
		oauth2Api.Configuration.Username = "fa3030d2-9e16-4b7d-b27f-381e840175cb"
		oauth2Api.Configuration.PrivateJWK = &JsonWebKey{
			Crv: "P-256",
			Alg: "ES256",
			Kty: "EC",
			Kid: "private:89b940e8-a16f-48ce-a238-b52d7e252634",
			X: "6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA",
			Y: "kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg",
			D: "G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo",
		}

		token, popPrivKey, err := oauth2Api.GetOAuth2Token("", "")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.NotEmpty(t, popPrivKey)
	})

	// test loadECDSAPublicKey
	t.Run("case=load ecdsa private key from JsonWebKey", func(t *testing.T) {
		jsonWebKey := &JsonWebKey{
			Crv: "P-256",
			Alg: "ES256",
			Kty: "EC",
			Use: "sig",
			Kid: "public:89b940e8-a16f-48ce-a238-b52d7e252634",
			X: "6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA",
			Y: "kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg",
		}
		ecPubKey, err := LoadECPublicKeyFromJsonWebKey(jsonWebKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, ecPubKey)
	})

	// test loadECDSAPrivateKey
	t.Run("case=load ecdsa private key from JsonWebKey", func(t *testing.T) {
		jsonWebKey := &JsonWebKey{
			Crv: "P-256",
			Alg: "ES256",
			Kty: "EC",
			Kid: "private:89b940e8-a16f-48ce-a238-b52d7e252634",
			X: "6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA",
			Y: "kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg",
			D: "G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo",
		}
		ecPrivKey, err := LoadECPrivateKeyFromJsonWebKey(jsonWebKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, ecPrivKey)
	})

	// SendHttpGet
	t.Run("case=send get request", func(t *testing.T) {
		// Note: register resource first
		oauth2Api.Configuration.Username = "fa3030d2-9e16-4b7d-b27f-381e840175cb"
		apiResp, err := oauth2Api.SendHttpGet("http://localhost:4444/resources/urn:104:v3:resource:rest:jobs", map[string]string{"104-Token-Chain":"TokenA,TokenB"})
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, apiResp.StatusCode)
		assert.NotEmpty(t, apiResp.Payload)
	})

	t.Run("case=test cache", func(t *testing.T) {
		keyId := uuid.New()
		jwks, err := oauth2Api.GetPoPKeyPair(keyId)
		assert.NoError(t, err)
		assert.NotNil(t, jwks)
		cachedJwks, err := oauth2Api.GetPoPKeyPair(keyId)
		assert.NoError(t, err)
		assert.EqualValues(t, jwks, cachedJwks)
	})
}
