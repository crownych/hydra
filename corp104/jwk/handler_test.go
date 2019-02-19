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

package jwk_test

import (
	"encoding/json"
	"github.com/ory/hydra/pkg"
	"net/http"
	"net/http/httptest"
	"testing"

	"context"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	. "github.com/ory/hydra/corp104/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testServer *httptest.Server
var IDKS *pkg.JSONWebKeySet

func init() {
	router := httprouter.New()
	IDKS, _ = testGenerator.Generate("test-id", "sig")

	h := NewHandler(
		&MemoryManager{},
		nil,
		herodot.NewJSONWriter(nil),
		[]string{},
		"http://localhost:4444",
		"auth.offline",
	)
	h.Manager.AddKeySet(context.TODO(), IDTokenKeyName, IDKS)
	offlineKS, _ := testGenerator.Generate("test-offline-jwk", "sig")
	h.Manager.AddKeySet(context.TODO(), "auth.offline", offlineKS)
	h.SetRoutes(router, router, func(h http.Handler) http.Handler {
		return h
	})
	testServer = httptest.NewServer(router)
}

func TestHandlerWellKnown(t *testing.T) {

	JWKPath := WellKnownKeysPath
	res, err := http.Get(testServer.URL + JWKPath)
	require.NoError(t, err, "problem in http request")
	defer res.Body.Close()

	var known pkg.JSONWebKeySet
	err = json.NewDecoder(res.Body).Decode(&known)
	require.NoError(t, err, "problem in decoding response")

	resp := known.Key("public:test-id")
	require.NotNil(t, resp, "Could not find key public")
	assert.Equal(t, resp, IDKS.Key("public:test-id"))
}
