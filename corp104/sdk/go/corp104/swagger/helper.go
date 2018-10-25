package swagger

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"math/big"
	"strconv"
	"strings"
)

func JsonStringToMap(str string) (map[string]interface{}, error) {
	var p interface{}
	err := json.Unmarshal([]byte(str), &p)
	if err != nil {
		return nil, err
	}
	return p.(map[string]interface{}), nil
}

func extractJWKStringFrom(joseString string) (string, error) {
	m, err := JsonStringToMap(joseString)
	if err != nil {
		return "", nil
	}

	buf, err := json.Marshal(m["jwk"].(map[string]interface{}))
	if err != nil {
		return "", nil
	}
	return string(buf), nil
}

func extractHeader(msg string) ([]byte, error) {
	compactHeader, _, _, err := jws.SplitCompact(strings.NewReader(msg))
	if err != nil {
		return nil, err
	}
	header, err := base64.RawURLEncoding.DecodeString(string(compactHeader))
	if err != nil {
		return nil, err
	}
	return header, nil
}

func extractKeyFromHeader(msg string, id int) (interface{}, error) {
	set, err := jwk.ParseString(msg)
	if err != nil {
		return nil, err
	}
	key, err := set.Keys[id].Materialize()
	if err != nil {
		return nil, err
	}
	return key, nil
}

func extractHeaderByName(msg, name string) (interface{}, error) {
	header, err := extractHeader(msg)
	if err != nil {
		return nil, err
	}
	var headerMap map[string]interface{}
	err = json.Unmarshal(header, &headerMap)
	if err != nil {
		return nil, err
	}
	return headerMap[name], nil
}

func extractKeyIdFromHeader(msg string) (string, error) {
	kid, err := extractHeaderByName(msg, jws.KeyIDKey)
	if err != nil {
		return "", nil
	}
	if kid, ok := kid.(string); !ok {
		return "", nil
	} else {
		return kid, nil
	}
}

// 將 JsonWebKey 轉換成 jwx library 所需的JWK
func convertToJwxJWK(key *JsonWebKey, publicKeyOnly bool) (jwk.Key, interface{}, error) {
	if key.Kty == "" {
		key.Kty = "EC"
	}
	switch key.Kty {
	case "EC":
		var curve elliptic.Curve
		switch key.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-512":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}

		var jwkKey jwk.Key
		var cryptoKey interface{}

		pX, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, nil, err
		}
		pY, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, nil, err
		}
		pubKey := ecdsa.PublicKey{
			Curve: curve,
			X: new(big.Int).SetBytes(pX),
			Y: new(big.Int).SetBytes(pY),
		}
		if err != nil {
			return nil, nil, err
		}

		if !publicKeyOnly && key.D != "" {
			pD, err := base64.RawURLEncoding.DecodeString(key.D)
			if err != nil {
				return nil, nil, err
			}
			cryptoKey = &ecdsa.PrivateKey{
				PublicKey: pubKey,
				D: new(big.Int).SetBytes(pD),
			}
		} else {
			cryptoKey = &pubKey
		}

		jwkKey, err = jwk.New(cryptoKey)
		if err != nil {
			return nil, nil, err
		}

		switch key.Alg {
		case "ES256":
			jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
		case "ES384":
			jwkKey.Set(jwk.AlgorithmKey, jwa.ES384)
		case "ES512":
			jwkKey.Set(jwk.AlgorithmKey, jwa.ES512)
		default:
			jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
		}
		jwkKey.Set(jwk.KeyIDKey, key.Kid)
		jwkKey.Set(jwk.KeyUsageKey, key.Use)
		jwkKey.Set(jwk.KeyTypeKey, key.Kty)
		return jwkKey, cryptoKey, nil
	case "RSA":
		pN, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, nil, err
		}
		pE, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, nil, err
		}
		intE, err := strconv.Atoi(string(pE))
		if err != nil {
			return nil, nil, err
		}

		var jwkKey jwk.Key
		var cryptoKey interface{}

		pubKey := rsa.PublicKey{
			N: new(big.Int).SetBytes(pN),
			E: intE,
		}

		if !publicKeyOnly && key.D != "" {
			pD, err := base64.RawURLEncoding.DecodeString(key.D)
			if err != nil {
				return nil, nil, err
			}
			cryptoKey = &rsa.PrivateKey{
				PublicKey: pubKey,
				D: new(big.Int).SetBytes(pD),
			}
		} else {
			cryptoKey = &pubKey
		}

		jwkKey, err = jwk.New(cryptoKey)
		if err != nil {
			return nil, nil, err
		}
		switch key.Alg {
		case "RS256":
			jwkKey.Set(jwk.AlgorithmKey, jwa.RS256)
		case "RS384":
			jwkKey.Set(jwk.AlgorithmKey, jwa.RS384)
		case "RS512":
			jwkKey.Set(jwk.AlgorithmKey, jwa.RS512)
		default:
			jwkKey.Set(jwk.AlgorithmKey, jwa.RS256)
		}
		jwkKey.Set(jwk.KeyIDKey, key.Kid)
		jwkKey.Set(jwk.KeyUsageKey, key.Use)
		jwkKey.Set(jwk.KeyTypeKey, key.Kty)
		return jwkKey, pubKey, nil
	default:
		return nil, nil, errors.New("Key type not supported: " + key.Kty)
	}
}
