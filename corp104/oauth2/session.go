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
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package oauth2

import (
	"time"

	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

type Session struct {
	// JSON fields are needed for store serialization
	*openid.DefaultSession `json:"idToken"`
	Audience               []string
	Extra                  map[string]interface{} `json:"extra"`
	//JTI                    string
	KID      string
	ClientID string
}

func NewSession(subject string) *Session {
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims:  new(jwt.IDTokenClaims),
			Headers: new(jwt.Headers),
			Subject: subject,
		},
		Audience: []string{},
		Extra:    map[string]interface{}{},
	}
}

func (s *Session) GetJWTClaims() *jwt.JWTClaims {
	claims := &jwt.JWTClaims{
		Subject:   s.Subject,
		Audience:  s.Audience,
		Issuer:    s.DefaultSession.Claims.Issuer,
		Extra:     s.Extra,
		ExpiresAt: s.GetExpiresAt(fosite.AccessToken),
		IssuedAt:  time.Now(),
		NotBefore: time.Now(),
		// The JTI MUST NOT BE FIXED or refreshing tokens will yield the SAME token
		// JTI:       s.JTI,
		// These are set by the DefaultJWTStrategy
		// Scope:     s.Scope,
		// Setting these here will cause the token to have the same iat/nbf values always
		// IssuedAt:  s.DefaultSession.Claims.IssuedAt,
		// NotBefore: s.DefaultSession.Claims.IssuedAt,
	}

	if claims.Extra == nil {
		claims.Extra = map[string]interface{}{}
	}

	claims.Extra["client_id"] = s.ClientID
	return claims
}

func (s *Session) GetJWTHeader() *jwt.Headers {
	return &jwt.Headers{
		Extra: map[string]interface{}{"kid": s.KID},
	}
}

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(fosite.Session)
}