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

package cmd

import (
	"crypto/tls"
	"fmt"
	"github.com/ory/hydra/corp104/oauth2"
	"github.com/ory/hydra/mock-dep"
	"github.com/phayes/freeport"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var frontendPort, backendPort int

func init() {
	var err error
	frontendPort, err = freeport.GetFreePort()
	if err != nil {
		panic(err.Error())
	}

	backendPort, err = freeport.GetFreePort()
	if err != nil {
		panic(err.Error())
	}

	os.Setenv("PUBLIC_PORT", fmt.Sprintf("%d", frontendPort))
	os.Setenv("ADMIN_PORT", fmt.Sprintf("%d", backendPort))
	os.Setenv("DATABASE_URL", "memory")
	//os.Setenv("HYDRA_URL", fmt.Sprintf("https://localhost:%d/", frontendPort))
	os.Setenv("OAUTH2_ISSUER_URL", fmt.Sprintf("https://localhost:%d/", frontendPort))
}

func TestExecute(t *testing.T) {
	err := mock_dep.StartMockServer()
	require.NoError(t, err)
	defer mock_dep.StopMockServer()

	viper.Set("AD_LOGIN_URL", fmt.Sprintf("http://localhost:%d/ad/login", mock_dep.GetPort()))
	viper.Set("ADMIN_USERS", "auth.admin")
	viper.Set("TEST_MODE", true)

	var osArgs = make([]string, len(os.Args))
	copy(osArgs, os.Args)

	frontend := fmt.Sprintf("https://localhost:%d/", frontendPort)
	backend := fmt.Sprintf("https://localhost:%d/", backendPort)

	for _, c := range []struct {
		args      []string
		wait      func() bool
		expectErr bool
	}{
		{
			args: []string{"serve", "all", "--disable-telemetry"},
			wait: func() bool {
				client := &http.Client{
					Transport: &transporter{
						FakeTLSTermination: true,
						Transport: &http.Transport{
							TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						},
					},
				}

				for _, u := range []string{
					//fmt.Sprintf("https://127.0.0.1:%d/.well-known/openid-configuration", frontendPort),
					fmt.Sprintf("https://127.0.0.1:%d"+oauth2.WellKnownPath, frontendPort),
					fmt.Sprintf("https://127.0.0.1:%d/health/status", frontendPort),
				} {
					if resp, err := client.Get(u); err != nil {
						t.Logf("HTTP request to %s failed: %s", u, err)
						return true
					} else if resp.StatusCode != http.StatusOK {
						t.Logf("HTTP request to %s got status code %d but expected was 200", u, resp.StatusCode)
						return true
					}
				}

				// Give a bit more time to initialize
				time.Sleep(time.Second * 5)
				return false
			},
		},
		{args: []string{"clients", "put", "--endpoint", frontend, "--id", "foobarbaz", "--secret", "secret", "--name", "foobarbaz", "-g", "client_credentials", "--client-uri", "http://foobarbaz.org", "--contacts", "admin@foobarbaz.org", "--software-id", "4d51529c-37cd-424c-ba19-cba742d60903", "--software-version", "0.0.1", "--token-endpoint-auth-method", "private_key_jwt", "--client-profile", "web", "--jwks", `{"keys":[{"use":"sig","kty":"EC","kid":"public:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg"}]}`, "--auth-public-jwk", "env:OFFLINE_PUBLIC_KEY", "--user", "foo.bar", "--pwd", "secret"}},
		{args: []string{"clients", "commit", "--endpoint", frontend, "--id", "foobarbaz", "--commit-code", "env:COMMIT_CODE"}},
		{args: []string{"clients", "get", "--endpoint", frontend, "foobarbaz", "--secret", "secret"}},
		{args: []string{"clients", "delete", "--endpoint", backend, "foobarbaz"}},
		{args: []string{"keys", "put", "--endpoint", frontend, "foo", "--jwks", `{"keys":[{"alg":"ES256","crv":"P-256","kid":"public:487f8461-5cfc-4ed5-9e40-78b496b1c5d7","kty":"EC","use":"sig","x":"1ZWO7twIWsGNYEnb8DXzFst02_oibc7zkVY5GNHYPI0","y":"4ZxzYZeTowbOjsZRK3GlJUHBD2ufewq4PDyBbpFFJAA","nbf":1550000000,"exp":1560000000},{"alg":"ES256","crv":"P-256","d":"T8klJ70zcr3nS2ooQnD4I7-x3MQDvtsgQF7BO-7dEh0","kid":"private:487f8461-5cfc-4ed5-9e40-78b496b1c5d7","kty":"EC","use":"sig","x":"1ZWO7twIWsGNYEnb8DXzFst02_oibc7zkVY5GNHYPI0","y":"4ZxzYZeTowbOjsZRK3GlJUHBD2ufewq4PDyBbpFFJAA","nbf":1550000000,"exp":1560000000}]}`, "--auth-public-jwk", "env:OFFLINE_PUBLIC_KEY", "--user", "auth.admin", "--pwd", "secret"}},
		{args: []string{"keys", "commit", "--endpoint", frontend, "foo", "--commit-code", "env:COMMIT_CODE"}},
		{args: []string{"keys", "get", "--endpoint", frontend, "foo", "--user", "auth.admin", "--pwd", "secret"}},
		//{args: []string{"keys", "rotate", "--endpoint", backend, "foo"}},
		//{args: []string{"keys", "get", "--endpoint", frontend, "foo", "--user", "auth.admin", "--pwd", "secret"}},
		{args: []string{"keys", "delete", "--endpoint", backend, "foo", "--user", "auth.admin", "--pwd", "secret"}},
		{args: []string{"keys", "import", "--endpoint", frontend, "import-1", "../../test/stub/jwk.key", "../../test/stub/jwk.pub", "--use", "sig", "--auth-public-jwk", "env:OFFLINE_PUBLIC_KEY", "--user", "auth.admin", "--pwd", "secret"}},
		{args: []string{"keys", "commit", "--endpoint", frontend, "import-1", "--commit-code", "env:COMMIT_CODE"}},
		{args: []string{"keys", "get", "--endpoint", frontend, "import-1", "--user", "auth.admin", "--pwd", "secret"}},
		{args: []string{"keys", "delete", "--endpoint", backend, "import-1", "--user", "auth.admin", "--pwd", "secret"}},
		//{args: []string{"token", "revoke", "--endpoint", frontend, "--client-secret", "foobar", "--client-id", "foobarbaz", "foo"}},
		//{args: []string{"token", "client", "--endpoint", frontend, "--client-secret", "foobar", "--client-id", "foobarbaz"}},
		//{args: []string{"help", "migrate", "sql"}},
		{args: []string{"version"}},
		{args: []string{"token", "flush", "--endpoint", backend}},
		{args: []string{"resources", "put", "--endpoint", frontend, "--resource-metadata", `{"uri":"https://v3ms.104.com.tw/graphql","name":"resumes","type":"graphql","auth_service":"https://v3auth.104.com.tw","default_scope_auth_type":"company","grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer"],"scopes":[{"name":"graphql:resumes:read","scope_auth_type":"","description":"關於rest:jobs:read"},{"name":"graphql:resumes:edu:read","scope_auth_type":"","description":"關於rest:jobs:edu:read"},{"name":"graphql:resumes:write","scope_auth_type":"","description":"關於rest:jobs:write"}],"graphql_operations":[{"name":"resumes","type":"query","scopes":["graphql:resumes:read","graphql:resumes:write"],"description":"查詢履歷"},{"name":"resumes/edu","type":"query","scopes":["graphql:resumes:edu:read","graphql:resumes:write"],"description":"查詢履歷的教育程度"},{"name":"createResume","type":"mutation","scopes":["graphql:resumes:write"],"description":"新增履歷"},{"name":"deleteResume","type":"mutation","scopes":["graphql:resumes:write"],"description":"刪除履歷"}],"contacts":["someone@104.com.tw"],"description":"歷履表"}`, "--auth-public-jwk", "env:OFFLINE_PUBLIC_KEY", "--user", "foo.bar", "--pwd", "secret"}},
		{args: []string{"resources", "commit", "--endpoint", frontend, "--urn", "urn:104:v3:resource:graphql:resumes", "--commit-code", "env:COMMIT_CODE"}},
		{args: []string{"resources", "get", "--endpoint", frontend, "urn:104:v3:resource:graphql:resumes"}},
		{args: []string{"resources", "delete", "--endpoint", backend, "urn:104:v3:resource:graphql:resumes"}},
	} {
		for i, v := range c.args {
			envPrefix := "env:"
			if strings.HasPrefix(v, envPrefix) {
				c.args[i] = viper.GetString(strings.TrimPrefix(v, envPrefix))
			}
		}
		c.args = append(c.args, []string{"--skip-tls-verify"}...)
		RootCmd.SetArgs(c.args)

		t.Run(fmt.Sprintf("command=%v", c.args), func(t *testing.T) {
			if c.wait != nil {
				go func() {
					assert.Nil(t, RootCmd.Execute())
				}()
			}

			if c.wait != nil {
				var count = 0
				for c.wait() {
					t.Logf("Ports are not yet open, retrying attempt #%d...", count)
					count++
					if count > 15 {
						t.FailNow()
					}
					time.Sleep(time.Second)
				}
			} else {
				err := RootCmd.Execute()
				if c.expectErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}
