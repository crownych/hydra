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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	foauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/herodot"
	"github.com/ory/hydra/corp104/client"
	"github.com/ory/hydra/corp104/config"
	"github.com/ory/hydra/corp104/consent"
	"github.com/ory/hydra/corp104/jwk"
	"github.com/ory/hydra/corp104/oauth2"
	"github.com/ory/hydra/pkg"
	"github.com/ory/hydra/tracing"
	"github.com/pborman/uuid"
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

	kid := uuid.New()
	if _, err := createOrGetJWK(c, oauth2.OpenIDConnectKeyName, kid, "private"); err != nil {
		c.GetLogger().WithError(err).Fatalf(`Could not fetch private signing key for OpenID Connect - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
	}

	if _, err := createOrGetJWK(c, oauth2.OpenIDConnectKeyName, kid, "public"); err != nil {
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

	jwtStrategy, err := jwk.NewES256JWTStrategy(c.Context().KeyManager, oauth2.OpenIDConnectKeyName)
	if err != nil {
		c.GetLogger().WithError(err).Fatalf("Unable to refresh OpenID Connect signing keys.")
	}
	oidcStrategy := &openid.DefaultStrategy{
		JWTStrategy: jwtStrategy,
		Expiry:      c.GetIDTokenLifespan(),
		Issuer:      c.Issuer,
	}

	var coreStrategy foauth2.CoreStrategy
	hmacStrategy := compose.NewOAuth2HMACStrategy(fc, c.GetSystemSecret(), nil)
	if c.OAuth2AccessTokenStrategy == "jwt" {
		kid := uuid.New()
		if _, err := createOrGetJWK(c, oauth2.OAuth2JWTKeyName, kid, "private"); err != nil {
			c.GetLogger().WithError(err).Fatalf(`Could not fetch private signing key for OAuth 2.0 Access Tokens - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
		}

		if _, err := createOrGetJWK(c, oauth2.OAuth2JWTKeyName, kid, "public"); err != nil {
			c.GetLogger().WithError(err).Fatalf(`Could not fetch public signing key for OAuth 2.0 Access Tokens - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
		}

		jwtStrategy, err := jwk.NewES256JWTStrategy(c.Context().KeyManager, oauth2.OAuth2JWTKeyName)
		if err != nil {
			c.GetLogger().WithError(err).Fatalf("Unable to refresh Access Token signing keys.")
		}

		coreStrategy = &foauth2.DefaultJWTStrategy{
			JWTStrategy:     jwtStrategy,
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

	return compose.Compose(
		fc,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               coreStrategy,
			OpenIDConnectTokenStrategy: oidcStrategy,
			JWTStrategy:                jwtStrategy,
		},
		hasher,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)
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
func newOAuth2Handler(c *config.Config, frontend, backend *httprouter.Router, cm consent.Manager, o fosite.OAuth2Provider, clm client.Manager) *oauth2.Handler {
	expectDependency(c.GetLogger(), c.Context().FositeStore, clm)

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
		OAuthServerMetadataStrategy: initOAuthServerMetadataJWKSAndStrategy(c),
	}

	corsMiddleware := newCORSMiddleware(viper.GetString("CORS_ENABLED") == "true", c, o.IntrospectToken, clm.GetConcreteClient)
	handler.SetRoutes(frontend, backend, corsMiddleware)
	return handler
}

// Generate JWKS for OAuth authorization server metadata and return JWTStrategy
func initOAuthServerMetadataJWKSAndStrategy(c *config.Config) jwk.JWTStrategy {
	// 產生 JWKS
	kid := uuid.New()
	if _, err := createOrGetJWK(c, oauth2.OAuthServerMetadataKeyName, kid, "private"); err != nil {
		c.GetLogger().WithError(err).Fatalf(`Could not fetch private signing key for OAuth 2.0 Authorization Server Metadata - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
	}
	pubKey, err := createOrGetJWK(c, oauth2.OAuthServerMetadataKeyName, kid, "public")
	if err != nil {
		c.GetLogger().WithError(err).Fatalf(`Could not fetch public signing key for OAuth 2.0 Authorization Server Metadata - did you forget to run "hydra migrate sql" or forget to set the SYSTEM_SECRET?`)
	}

	// 輸出驗證 Metadata 用的 Public Key JWK 及 PEM
	mataPubKeyBytes, _ := pubKey.MarshalJSON()
	var pubKeyInfo map[string]string
	json.Unmarshal(mataPubKeyBytes, &pubKeyInfo)
	pubX, _ := base64.RawURLEncoding.DecodeString(pubKeyInfo["x"])
	pubY, _ := base64.RawURLEncoding.DecodeString(pubKeyInfo["y"])
	derBytes, _ := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pubX), Y: new(big.Int).SetBytes(pubY)})
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
	c.GetLogger().Infof("JSON Web Key used to verify oauth server metadata\n\n%s\n\n%s", mataPubKeyBytes, pemBytes)

	// 建立 OAuth2 authorization server metadata strategy
	metadataStrategy, err := jwk.NewES256JWTStrategy(c.Context().KeyManager, oauth2.OAuthServerMetadataKeyName)
	pkg.Must(err, "Could not fetch private signing key for OAuth 2.0 Authorization Metadata - did you forget to run \"hydra migrate sql\" or forget to set the SYSTEM_SECRET?")

	return metadataStrategy
}