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

package server

import (
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/go-convenience/corsx"
	"github.com/ory/herodot"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/corp104/config"
	"github.com/ory/hydra/corp104/consent"
	"github.com/spf13/viper"
)

func injectConsentManager(c *config.Config, cm client.Manager) {
	var ctx = c.Context()
	ctx.ConsentManager = ctx.Connection.NewConsentManager(cm, ctx.FositeStore)
}

func newConsentHandler(c *config.Config, frontend, backend *httprouter.Router, o fosite.OAuth2Provider, clm client.Manager) *consent.Handler {
	var ctx = c.Context()

	w := herodot.NewJSONWriter(c.GetLogger())
	w.ErrorEnhancer = writerErrorEnhancer

	expectDependency(c.GetLogger(), ctx.ConsentManager)
	h := consent.NewHandler(w, ctx.ConsentManager, sessions.NewCookieStore(c.GetCookieSecret()), c.LogoutRedirectURL, c.Context().KeyManager, c.GetOfflineJWKSName())

	corsMiddleware := newCORSMiddleware(viper.GetString("CORS_ENABLED") == "true", c, corsx.ParseOptions(), o.IntrospectToken, clm.GetConcreteClient)
	h.SetRoutes(frontend, backend, corsMiddleware)
	return h
}
