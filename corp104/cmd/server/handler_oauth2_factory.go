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
	"fmt"
	"github.com/pborman/uuid"
	"net/url"
	"strings"
	"time"

	"github.com/104corp/vip3-go-auth/vip3auth"
	"github.com/104corp/vip3-go-auth/vip3auth/token"
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	foauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/go-convenience/corsx"
	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/herodot"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/corp104/config"
	"github.com/ory/hydra/corp104/consent"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/corp104/oauth2"
	"github.com/ory/hydra/corp104/resource"
	"github.com/ory/hydra/pkg"
	"github.com/ory/hydra/tracing"
	"github.com/spf13/viper"
)

func injectFositeStore(c *config.Config, clients client.Manager) {
	var ctx = c.Context()
	ctx.FositeStore = ctx.Connection.NewOAuth2Manager(clients, c.GetAccessTokenLifespan(), c.OAuth2AccessTokenStrategy)
}

func newOAuth2Provider(c *config.Config) fosite.OAuth2Provider {
	var hasher fosite.Hasher
	var ctx = c.Context()
	var store = ctx.FositeStore
	expectDependency(c.GetLogger(), ctx.FositeStore)

	privKey, err := createOrGetJWK(c, oauth2.OpenIDConnectKeyName, uuid.New(), "private")
	if err != nil {
		c.GetLogger().WithError(err).Fatalf(`Could not fetch private signing key for OpenID Connect - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
	}

	if _, err := createOrGetJWK(c, oauth2.OpenIDConnectKeyName, privKey.KeyID, "public"); err != nil {
		c.GetLogger().WithError(err).Fatalf(`Could not fetch public signing key for OpenID Connect - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
	}

	fc := &compose.Config{
		AccessTokenLifespan:            c.GetAccessTokenLifespan(),
		AuthorizeCodeLifespan:          c.GetAuthCodeLifespan(),
		IDTokenLifespan:                c.GetIDTokenLifespan(),
		IDTokenIssuer:                  c.Issuer,
		HashCost:                       c.BCryptWorkFactor,
		ScopeStrategy:                  c.GetScopeStrategy(),
		SendDebugMessagesToClients:     c.SendOAuth2DebugMessagesToClients,
		EnforcePKCE:                    false,
		EnablePKCEPlainChallengeMethod: false,
		TokenURL:                       strings.TrimRight(c.Issuer, "/") + oauth2.TokenPath,
	}

	oidcJWTStrategy := &token.Vip3ES256JWTStrategy{KeyStore: c.Context().KeyManager, Set: oauth2.OpenIDConnectKeyName}
	oauth2JWTStrategy := &token.Vip3ES256JWTStrategy{KeyStore: c.Context().KeyManager, Set: oauth2.OAuth2JWTKeyName}
	commonJWTStrategy := oidcJWTStrategy

	oidcStrategy := &openid.DefaultStrategy{
		JWTStrategy: oidcJWTStrategy,
		Expiry:      c.GetIDTokenLifespan(),
		Issuer:      c.Issuer,
	}

	var coreStrategy foauth2.CoreStrategy
	hmacStrategy := compose.NewOAuth2HMACStrategy(fc, c.GetSystemSecret(), nil)
	if c.OAuth2AccessTokenStrategy == "jwt" {
		privKey, err := createOrGetJWK(c, oauth2.OAuth2JWTKeyName, uuid.New(), "private")
		if err != nil {
			c.GetLogger().WithError(err).Fatalf(`Could not fetch private signing key for OAuth 2.0 Access Tokens - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
		}

		if _, err := createOrGetJWK(c, oauth2.OAuth2JWTKeyName, privKey.KeyID, "public"); err != nil {
			c.GetLogger().WithError(err).Fatalf(`Could not fetch public signing key for OAuth 2.0 Access Tokens - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
		}

		commonJWTStrategy = oauth2JWTStrategy

		coreStrategy = &foauth2.DefaultJWTStrategy{
			JWTStrategy:     oauth2JWTStrategy,
			HMACSHAStrategy: hmacStrategy,
		}
	} else if c.OAuth2AccessTokenStrategy == "opaque" {
		coreStrategy = hmacStrategy
	} else {
		c.GetLogger().Fatalf(`Environment variable OAUTH2_ACCESS_TOKEN_STRATEGY is set to "%s" but only "opaque" and "jwt" are valid values.`, c.OAuth2AccessTokenStrategy)
	}

	if tracer, err := c.GetTracer(); err == nil && tracer.IsLoaded() {
		hasher = &tracing.TracedBCrypt{fc.HashCost}
	}

	commonStrategy := &compose.CommonStrategy{
		CoreStrategy:               coreStrategy,
		OpenIDConnectTokenStrategy: oidcStrategy,
		JWTStrategy:                commonJWTStrategy,
	}

	oriProvider := compose.Compose(
		fc,
		store,
		commonStrategy,
		hasher,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	// JwtBearerGrantHandler 和 ClientCredentialsGrantHandler 簽發 Access Token 所需要的 HandleHelper
	accessTokenHelper := &foauth2.HandleHelper{
		AccessTokenStrategy: token.NewVip3AccessTokenStrategy(coreStrategy, fc.TokenURL, oauth2JWTStrategy),
		AccessTokenStorage:  store,
		AccessTokenLifespan: fc.AccessTokenLifespan,
	}

	// Vip3JwtBearerAssertionValidator 查驗 Id token 所需要的 KeySet 設定
	keyStoreConfig := vip3auth.KeyStoreConfig{
		KeyStore:          c.Context().KeyManager,
		IdTokenKeySetName: oauth2.OpenIDConnectKeyName,
	}

	// TODO 前端 SDK 完成 user id-token 重簽發為 company user id-token 時移除
	vip3auth.SetSkipAssertionsSignatureVerify(true)

	oauth2Provider := vip3auth.ComposeOAuth2Provider(fc, oriProvider.(*fosite.Fosite), accessTokenHelper, keyStoreConfig, pkg.GetSessionValue)
	return oauth2Provider
}

func setDefaultConsentURL(s string, c *config.Config, path string) string {
	if s != "" {
		return s
	}
	proto := "https"
	if c.ForceHTTP {
		proto = "http"
	}
	host := "localhost"
	if c.FrontendBindHost != "" {
		host = c.FrontendBindHost
	}
	return fmt.Sprintf("%s://%s:%d/%s", proto, host, c.FrontendBindPort, path)
}

//func newOAuth2Handler(c *config.Config, router *httprouter.Router, cm oauth2.ConsentRequestManager, o fosite.OAuth2Provider, idTokenKeyID string) *oauth2.Handler {
func newOAuth2Handler(c *config.Config, frontend, backend *httprouter.Router, cm consent.Manager, o fosite.OAuth2Provider, clm client.Manager, rm resource.Manager) *oauth2.Handler {
	expectDependency(c.GetLogger(), c.Context().FositeStore, clm, rm)

	c.ConsentURL = setDefaultConsentURL(c.ConsentURL, c, oauth2.DefaultConsentPath)
	c.LoginURL = setDefaultConsentURL(c.LoginURL, c, oauth2.DefaultConsentPath)
	c.ErrorURL = setDefaultConsentURL(c.ErrorURL, c, oauth2.DefaultErrorPath)

	errorURL, err := url.Parse(c.ErrorURL)
	pkg.Must(err, "Could not parse error url %s.", errorURL)

	openIDJWTStrategy, err := jwk.NewES256JWTStrategy(c.Context().KeyManager, oauth2.OpenIDConnectKeyName)
	pkg.Must(err, "Could not fetch private signing key for OpenID Connect - did you forget to run \"hydra migrate sql\" or forget to set the SYSTEM_SECRET?")
	oidcStrategy := &openid.DefaultStrategy{JWTStrategy: openIDJWTStrategy}

	w := herodot.NewJSONWriter(c.GetLogger())
	w.ErrorEnhancer = writerErrorEnhancer
	var accessTokenJWTStrategy *jwk.ES256JWTStrategy

	if c.OAuth2AccessTokenStrategy == "jwt" {
		accessTokenJWTStrategy, err = jwk.NewES256JWTStrategy(c.Context().KeyManager, oauth2.OAuth2JWTKeyName)
		if err != nil {
			c.GetLogger().WithError(err).Fatalf("Unable to refresh Access Token signing keys.")
		}
	}

	sias := map[string]consent.SubjectIdentifierAlgorithm{}
	if stringslice.Has(c.GetSubjectTypesSupported(), "pairwise") {
		sias["pairwise"] = consent.NewSubjectIdentifierAlgorithmPairwise([]byte(c.SubjectIdentifierAlgorithmSalt))
	}
	if stringslice.Has(c.GetSubjectTypesSupported(), "public") {
		sias["public"] = consent.NewSubjectIdentifierAlgorithmPublic()
	}

	handler := &oauth2.Handler{
		ScopesSupported:  c.OpenIDDiscoveryScopesSupported,
		UserinfoEndpoint: c.OpenIDDiscoveryUserinfoEndpoint,
		ClaimsSupported:  c.OpenIDDiscoveryClaimsSupported,
		ForcedHTTP:       c.ForceHTTP,
		OAuth2:           o,
		ScopeStrategy:    c.GetScopeStrategy(),
		Consent: consent.NewStrategy(
			c.LoginURL, c.ConsentURL, c.DisableConsentFlow, c.Issuer,
			oauth2.AuthPath, cm,
			sessions.NewCookieStore(c.GetCookieSecret()), c.GetScopeStrategy(),
			!c.ForceHTTP, time.Minute*15,
			oidcStrategy,
			openid.NewOpenIDConnectRequestValidator(nil, oidcStrategy),
			sias,
		),
		Storage:                c.Context().FositeStore,
		ErrorURL:               *errorURL,
		H:                      w,
		AccessTokenLifespan:    c.GetAccessTokenLifespan(),
		CookieStore:            sessions.NewCookieStore(c.GetCookieSecret()),
		IssuerURL:              c.Issuer,
		L:                      c.GetLogger(),
		OpenIDJWTStrategy:      openIDJWTStrategy,
		AccessTokenJWTStrategy: accessTokenJWTStrategy,
		AccessTokenStrategy:    c.OAuth2AccessTokenStrategy,
		//IDTokenLifespan:        c.GetIDTokenLifespan(),
		ShareOAuth2Debug:            c.SendOAuth2DebugMessagesToClients,
		OAuthServerMetadataStrategy: token.Vip3ES256JWTStrategy{KeyStore: c.Context().KeyManager, Set: c.GetOfflineJWKSName()},
		ResourceManager:             rm,
	}

	corsMiddleware := newCORSMiddleware(viper.GetString("CORS_ENABLED") == "true", c, corsx.ParseOptions(), o.IntrospectToken, clm.GetConcreteClient)
	handler.SetRoutes(frontend, backend, corsMiddleware)
	return handler
}
