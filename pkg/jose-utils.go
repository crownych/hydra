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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jws"
	"net/http"
	"strings"

	"gopkg.in/square/go-jose.v2"
)

func LoadJSONWebKey(json []byte, pub bool) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
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

	return nil, fmt.Errorf("square/go-jose: parse error, got '%s', '%s' and '%s'", err0, err1, err2)
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

	return nil, fmt.Errorf("square/go-jose: parse error, got '%s', '%s', '%s' and '%s'", err0, err1, err2, err3)
}

func GetJWTValueFromRequestBody(r *http.Request, filed string) ([]byte, error) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, err
	}
	value := body[filed]
	if value == "" {
		return nil, errors.New("Empty \"" + filed + "\"")
	}
	return []byte(value), nil
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

func GetElementFromKeySet(setKeys map[string][]jose.JSONWebKey, kid string) (*jose.JSONWebKey, error) {
	for _, keys := range setKeys {
		for _, key := range keys {
			if key.KeyID == kid && !key.IsPublic() {
				return &key, nil
			}
		}
	}
	return nil, errors.New("JSONWebKey not found for kid: " + kid)
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

func VerifyJWS(compactJws []byte,
	headerChecker func(map[string]interface{}) (error),
	payloadChecker func(map[string]interface{}) (error)) ([]byte, error) {

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

func GenerateResponseJWT(authSrvPrivateKey *jose.JSONWebKey, keyValuePairs map[string]string) (string, error) {
	headers := &jws.StandardHeaders{}
	headers.Set("alg", authSrvPrivateKey.Algorithm)
	headers.Set("typ", "JWT")
	headers.Set("kid", strings.Replace(authSrvPrivateKey.KeyID, "private:", "public:", 1))

	claims := make(map[string]string)
	for k, v := range keyValuePairs {
		claims[k] = v
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

func unmarshalEncodedJsonString(encodedStr string, buf map[string]interface{}) (error) {
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
