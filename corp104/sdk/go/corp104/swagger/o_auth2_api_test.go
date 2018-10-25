package swagger_test

import (
	"fmt"
	. "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)


func TestOAuth2API(t *testing.T) {
	//var serverURL = ""
	var serverURL = "http://localhost:4444"
	if serverURL == "" {
		return
	}

	oauth2Api := NewOAuth2ApiWithBasePath(serverURL)
	timeout := 5 * time.Second
	oauth2Api.Configuration.Timeout = &timeout

	t.Run("case=get oauth authorization server metadata", func(t *testing.T) {
		wellKnown, _, err := oauth2Api.GetWellKnown()
		assert.Nil(t, err)
		assert.NotNil(t, wellKnown)
		//fmt.Println("WellKnown: ", wellKnown)
	})

	t.Run("case=get oauth authorization server jwks.json", func(t *testing.T) {
		jwks, _, err := oauth2Api.WellKnown()
		assert.Nil(t, err)
		assert.NotNil(t, jwks)
		fmt.Println("jwks: ", jwks)
	})

}

