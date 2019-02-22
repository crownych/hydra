/*-
 * Copyright 2014 Square Inc.
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
 */

package pkg

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jws"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
)

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

func (s *JSONWebKeySet) Key(kid string) []JSONWebKey {
	var keys []JSONWebKey
	for _, key := range s.Keys {
		if key.KeyID == kid {
			keys = append(keys, key)
		}
	}

	return keys
}

func (s *JSONWebKeySet) ToJoseJSONWebKeySet() *jose.JSONWebKeySet {
	var result []jose.JSONWebKey
	for _, key := range s.Keys {
		result = append(result, key.JSONWebKey)
	}

	return &jose.JSONWebKeySet{
		Keys: result,
	}
}

type JSONWebKey struct {
	jose.JSONWebKey

	// NotBefore is an integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this key is not to be used before.
	NotBefore *int64 `json:"nbf,omitempty"`

	// ExpiresAt is an integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this key will expire.
	ExpiresAt *int64 `json:"exp,omitempty"`
}

func (k *JSONWebKey) IsActive() bool {
	if k.NotBefore != nil && *k.NotBefore > time.Now().UTC().Unix() {
		return false
	}
	if k.IsExpired() {
		return false
	}
	return true
}

func (k *JSONWebKey) IsExpired() bool {
	if k.ExpiresAt != nil && *k.ExpiresAt <= time.Now().UTC().Unix() {
		return true
	}
	return false
}

// Public creates JSONWebKey with corresponding public key if JWK represents asymmetric private key.
func (k *JSONWebKey) Public() JSONWebKey {
	if k.IsPublic() {
		return *k
	}
	ret := *k
	switch key := k.Key.(type) {
	case *ecdsa.PrivateKey:
		ret.Key = key.Public()
	case *rsa.PrivateKey:
		ret.Key = key.Public()
	case ed25519.PrivateKey:
		ret.Key = key.Public()
	default:
		return JSONWebKey{} // returning invalid key
	}
	return ret
}

func (k JSONWebKey) MarshalJSON() ([]byte, error) {
	buf, err := k.JSONWebKey.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var kmap map[string]interface{}
	err = json.Unmarshal(buf, &kmap)
	if err != nil {
		return nil, err
	}
	if k.NotBefore != nil {
		kmap["nbf"] = k.NotBefore
	}
	if k.ExpiresAt != nil {
		kmap["exp"] = k.ExpiresAt
	}
	return json.Marshal(kmap)
}

func (k *JSONWebKey) UnmarshalJSON(data []byte) (err error) {
	err = k.JSONWebKey.UnmarshalJSON(data)
	if err != nil {
		return err
	}
	var kmap map[string]interface{}
	err = json.Unmarshal(data, &kmap)
	if err != nil {
		return err
	}
	if kmap["nbf"] != nil {
		nbf := int64(kmap["nbf"].(float64))
		k.NotBefore = &nbf
	}
	if kmap["exp"] != nil {
		exp := int64(kmap["exp"].(float64))
		k.ExpiresAt = &exp
	}
	return
}

func LoadJSONWebKey(json []byte, pub bool) (*JSONWebKey, error) {
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}
	if !jwk.Valid() {
		return nil, errors.New("invalid JWK key")
	}
	if jwk.IsPublic() != pub {
		return nil, errors.New("priv/pub JWK key mismatch")
	}
	return &jwk, nil
}

// LoadPublicKey loads a public key from PEM/DER/JWK-encoded data.
func LoadPublicKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	// Try to load SubjectPublicKeyInfo
	pub, err0 := x509.ParsePKIXPublicKey(input)
	if err0 == nil {
		return pub, nil
	}

	cert, err1 := x509.ParseCertificate(input)
	if err1 == nil {
		return cert.PublicKey, nil
	}

	jwk, err2 := LoadJSONWebKey(data, true)
	if err2 == nil {
		return jwk, nil
	}

	return nil, fmt.Errorf("JOSE: parse error, got '%s', '%s' and '%s'", err0, err1, err2)
}

// LoadPrivateKey loads a private key from PEM/DER/JWK-encoded data.
func LoadPrivateKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)
	if err0 == nil {
		return priv, nil
	}

	priv, err1 := x509.ParsePKCS8PrivateKey(input)
	if err1 == nil {
		return priv, nil
	}

	priv, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv, nil
	}

	jwk, err3 := LoadJSONWebKey(input, false)
	if err3 == nil {
		return jwk, nil
	}

	return nil, fmt.Errorf("JOSE: parse error, got '%s', '%s', '%s' and '%s'", err0, err1, err2, err3)
}

func GetValueFromRequestBody(r *http.Request, field string) ([]byte, error) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, err
	}
	value := body[field]
	if value == "" {
		return nil, errors.New("Empty \"" + field + "\"")
	}
	return []byte(value), nil
}

func GetMapFromRequestBody(r *http.Request) (map[string]interface{}, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var bodyMap map[string]interface{}
	if err := json.NewDecoder(strings.NewReader(string(body))).Decode(&bodyMap); err != nil {
		return nil, err
	}
	return bodyMap, nil
}

func ExtractKidFromJWE(compactJwe []byte) (string, error) {
	jweMessage, err := jwe.Parse(compactJwe)
	if err != nil {
		return "", err
	}
	if len(jweMessage.Recipients) < 1 {
		return "", errors.New("\"kid\" not found in JWE header")
	}
	serverKeyId := jweMessage.Recipients[0].Header.KeyID
	if serverKeyId == "" {
		return "", errors.New("\"kid\" not found in JWE header")
	}
	serverKeyId = strings.Replace(serverKeyId, "public:", "private:", 1)

	return serverKeyId, nil
}

func VerifyJWSUsingEmbeddedKey(compactJws []byte,
	headerChecker func(map[string]interface{}) error,
	payloadChecker func(map[string]interface{}) error) ([]byte, error) {

	jwsStr := strings.Replace(string(compactJws), `"`, "", -1)
	header, payload, err := GetContentFromJWS(jwsStr)
	if err != nil {
		return nil, err
	}

	if headerChecker != nil {
		if err := headerChecker(header); err != nil {
			return nil, err
		}
	}

	if payloadChecker != nil {
		if err := payloadChecker(payload); err != nil {
			return nil, err
		}
	}

	pubJwkHeader, found := header["jwk"]
	if !found {
		return nil, errors.New("`jwk` not found in JOSE header")
	}
	pubJwsJson, err := json.Marshal(&pubJwkHeader)
	if err != nil {
		return nil, err
	}
	pubJwk := &jose.JSONWebKey{}
	err = pubJwk.UnmarshalJSON(pubJwsJson)
	if err != nil {
		return nil, err
	}
	verifiedMsg, err := jws.Verify([]byte(jwsStr), jwa.ES256, pubJwk.Key)
	if err != nil {
		return nil, err
	}
	return verifiedMsg, nil
}

func GetContentFromJWS(compactJws string) (map[string]interface{}, map[string]interface{}, error) {
	compactHeader, compactPayload, _, err := jws.SplitCompact(strings.NewReader(compactJws))
	if err != nil {
		return nil, nil, err
	}

	header := make(map[string]interface{})
	if err := unmarshalEncodedJsonString(string(compactHeader), header); err != nil {
		return nil, nil, err
	}

	payload := make(map[string]interface{})
	if err := unmarshalEncodedJsonString(string(compactPayload), payload); err != nil {
		return nil, nil, err
	}

	return header, payload, nil
}

func GenerateResponseJWT(authSrvPrivateKey *jose.JSONWebKey, claims map[string]interface{}, header ...map[string]interface{}) (string, error) {
	headers := &jws.StandardHeaders{}
	headers.Set("alg", authSrvPrivateKey.Algorithm)
	headers.Set("typ", "JWT")
	headers.Set("kid", strings.Replace(authSrvPrivateKey.KeyID, "private:", "public:", 1))

	if len(header) > 0 {
		for k, v := range header[0] {
			if k == "alg" || k == "kid" {
				continue
			}
			headers.Set(k, v)
		}
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	buf, err := jws.Sign(payload, jwa.ES256, authSrvPrivateKey.Key, jws.WithHeaders(headers))
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

func unmarshalEncodedJsonString(encodedStr string, buf map[string]interface{}) error {
	str, err := base64.RawURLEncoding.DecodeString(encodedStr)
	if err != nil {
		return err
	}
	err = json.Unmarshal(str, &buf)
	if err != nil {
		return err
	}
	return nil
}

func DecryptJWE(compactJwe []byte, key interface{}) ([]byte, error) {
	buf, err := jwe.Decrypt(compactJwe, jwa.ECDH_ES_A256KW, key)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// 檢查 `kid` header 宣告的 key 是否有效，key 有效時解密回傳 payload
func DecryptJWEByKid(compactJwe []byte, validKeySet *jose.JSONWebKeySet) ([]byte, *jose.JSONWebKey, error) {
	if compactJwe == nil || len(compactJwe) == 0 {
		return nil, nil, NewBadRequestError("empty payload")
	}

	// Extract kid from JWE header
	kid, err := ExtractKidFromJWE(compactJwe)
	if err != nil {
		return nil, nil, err
	}

	// Check private key from valid JWKS
	keys := validKeySet.Key(kid)
	if keys == nil || len(keys) == 0 {
		pubKeyId := strings.Replace(kid, "private:", "public:", 1)
		return nil, nil, NewBadRequestError(fmt.Sprintf("invalid public key (kid: %s)", pubKeyId))
	}

	// Decrypt JWE
	decryptedMsg, err := DecryptJWE(compactJwe, keys[0].Key)
	if err != nil {
		return nil, nil, err
	}
	return decryptedMsg, &keys[0], nil
}
