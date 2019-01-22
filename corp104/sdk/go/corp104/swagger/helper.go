package swagger

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pborman/uuid"
	"math/big"
	"strconv"
	"strings"
	"time"
)

func CreateECKeyPair(kid, kidPrefix string) (*JsonWebKeySet, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	alg := "ES256"
	kty := "EC"
	use := "sig"
	x := base64.RawURLEncoding.EncodeToString(privKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privKey.Y.Bytes())
	d := base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())
	if kid == "" {
		kid = uuid.New()
	}
	jwks := &JsonWebKeySet{
		Keys: []JsonWebKey{
			{
				Crv: privKey.Params().Name,
				Alg: alg,
				Kid: kidPrefix + "private:" + kid,
				Kty: kty,
				Use: use,
				X: x,
				Y: y,
				D: d,
			},
			{
				Crv: privKey.Params().Name,
				Alg: alg,
				Kid: kidPrefix + "public:" + kid,
				Kty: kty,
				Use: use,
				X: x,
				Y: y,
			},
		},
	}
	return jwks, nil
}

func LoadJsonWebKeySet(jwksJSON []byte) *JsonWebKeySet {
	var jwks JsonWebKeySet
	err := json.Unmarshal(jwksJSON, &jwks)
	if err != nil {
		panic("Invalid jwks:" + err.Error())
	}
	return &jwks
}

func LoadJsonWebKey(jwkJSON []byte) *JsonWebKey {
	var jsonWebKey *JsonWebKey
	err := json.Unmarshal(jwkJSON, &jsonWebKey)
	if err != nil {
		panic("Invalid jwk:" + err.Error())
	}
	return jsonWebKey
}

func LoadECPublicKeyFromJsonWebKey(jsonWebKey *JsonWebKey) (*ecdsa.PublicKey, error) {
	if jsonWebKey == nil {
		return nil, errors.New("jsonWebKey must be set")
	}

	if jsonWebKey.X == "" || jsonWebKey.Y == "" {
		return nil, errors.New("invalid jsonWebKey")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jsonWebKey.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jsonWebKey.Y)
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	switch jsonWebKey.Crv {
	case "P-224":
		curve = elliptic.P224()
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X: big.NewInt(0).SetBytes(xBytes),
		Y: big.NewInt(0).SetBytes(yBytes),
	}

	return pubKey, nil
}

func LoadECPrivateKeyFromJsonWebKey(jsonWebKey *JsonWebKey) (*ecdsa.PrivateKey, error) {
	if jsonWebKey == nil {
		return nil, errors.New("jsonWebKey must not be nil")
	}

	if jsonWebKey.X == "" || jsonWebKey.Y == "" || jsonWebKey.D == "" {
		return nil, errors.New("invalid jsonWebKey")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jsonWebKey.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jsonWebKey.Y)
	if err != nil {
		return nil, err
	}
	dBytes, err := base64.RawURLEncoding.DecodeString(jsonWebKey.D)
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	switch jsonWebKey.Crv {
	case "P-224":
		curve = elliptic.P224()
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
	}

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X: big.NewInt(0).SetBytes(xBytes),
		Y: big.NewInt(0).SetBytes(yBytes),
	}

	return &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D: big.NewInt(0).SetBytes(dBytes),
	}, nil
}

func extractJWSHeader(msg string) ([]byte, error) {
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

func extractJWSHeaderByName(msg, name string) (interface{}, error) {
	header, err := extractJWSHeader(msg)
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

func extractKeyIdFromJWSHeader(msg string) (string, error) {
	kid, err := extractJWSHeaderByName(msg, jws.KeyIDKey)
	if err != nil {
		return "", nil
	}
	if kid, ok := kid.(string); !ok {
		return "", nil
	} else {
		return kid, nil
	}
}

func extractPublicJWK(privateKey *JsonWebKey) *JsonWebKey {
	if privateKey != nil {
		publicKey := *privateKey
		publicKey.D = ""
		publicKey.Kid = strings.Replace(privateKey.Kid, "private:", "public:", 1)
		if publicKey.Use == "" {
			publicKey.Use = "sig"
		}
		return &publicKey
	}
	return nil
}

// 將 JsonWebKey 轉換成 jwx library 所需的JWK
func convertToJwxJWK(key *JsonWebKey) (jwk.Key, interface{}, error) {
	if key.Kty == "" {
		key.Kty = "EC"
	}
	if key.Use == "" {
		key.Use = "sig"
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
			X:     new(big.Int).SetBytes(pX),
			Y:     new(big.Int).SetBytes(pY),
		}

		if key.D != "" {
			pD, err := base64.RawURLEncoding.DecodeString(key.D)
			if err != nil {
				return nil, nil, err
			}
			cryptoKey = &ecdsa.PrivateKey{
				PublicKey: pubKey,
				D:         new(big.Int).SetBytes(pD),
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

		if key.D != "" {
			pD, err := base64.RawURLEncoding.DecodeString(key.D)
			if err != nil {
				return nil, nil, err
			}
			cryptoKey = &rsa.PrivateKey{
				PublicKey: pubKey,
				D:         new(big.Int).SetBytes(pD),
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
		return nil, nil, errors.New("key type not supported: " + key.Kty)
	}
}

func convertToJwxJwsHeaders(headers map[string]interface{}) jws.Headers {
	if len(headers) == 0 {
		return nil
	}
	jwsHeaders := &jws.StandardHeaders{}
	for k, v := range headers {
		jwsHeaders.Set(k, v)
	}
	return jwsHeaders
}

func jwsSign(headers map[string]interface{}, payload []byte, key crypto.PrivateKey) ([]byte, error) {
	var buf []byte
	var err error
	jwsHeaders := convertToJwxJwsHeaders(headers)
	if jwsHeaders != nil {
		buf, err = jws.Sign(payload, jwa.ES256, key, jws.WithHeaders(jwsHeaders))
	} else {
		buf, err = jws.Sign(payload, jwa.ES256, key)
	}
	if err != nil {
		return nil, errors.New("failed to sign JWS: " + err.Error())
	}
	return buf, nil
}

func jweEncrypt(content []byte, key crypto.PublicKey, keyId string) ([]byte, error) {
	contentCrypt, err := jwe.NewAesCrypt(jwa.A256GCM)
	if err != nil {
		return nil, errors.New(`failed to create AES crypt: ` + err.Error())
	}

	keyenc, err := jwe.NewEcdhesKeyWrapEncrypt(jwa.ECDH_ES_A256KW, key.(*ecdsa.PublicKey))
	if err != nil {
		return nil, errors.New("failed to create ECDHS key wrap encrypt: " + err.Error())
	}

	keyenc.KeyID = keyId
	enc := jwe.NewMultiEncrypt(contentCrypt, jwe.NewRandomKeyGenerate(32), keyenc)
	encrypted, err := enc.Encrypt(content)
	if err != nil {
		return nil, errors.New("failed to encrypt payload: " + err.Error())
	}

	buf, err := jwe.CompactSerialize{}.Serialize(encrypted)
	if err != nil {
		return nil, errors.New("failed to serialize JWE: " + err.Error())
	}
	return buf, nil
}

func getSignedClaim(claim, signedJws, issuer string, publicJwk *JsonWebKey) ([]byte, error) {
	keyId, err := extractKeyIdFromJWSHeader(signedJws)
	if err != nil {
		return nil, err
	}
	if keyId != publicJwk.Kid {
		return nil, errors.New("JWS verification failed: kid not match")
	}
	srvJwk, _, err := convertToJwxJWK(publicJwk)
	if err != nil {
		return nil, err
	}
	claims, err := jws.VerifyWithJWK([]byte(signedJws), srvJwk)
	if err != nil {
		return nil, errors.New("JWS verification failed: " + err.Error())
	}

	var claimMap map[string]interface{}
	err = json.Unmarshal(claims, &claimMap)
	if err != nil {
		return nil, err
	}
	if strings.TrimRight(claimMap["iss"].(string), "/") != strings.TrimRight(issuer, "/") {
		return nil, errors.New("JWS verification failed: invalid issuer")
	}
	buf, err := json.Marshal(claimMap[claim])
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func getJWSContent(compactJws string) (map[string]interface{}, map[string]interface{}, error) {
	if compactJws == "" {
		return nil, nil, errors.New("empty JWS")
	}
	jwsSegments := strings.Split(compactJws, ".")
	if len(jwsSegments) != 3 {
		return nil, nil, errors.New("invalid JWS")
	}

	var header map[string]interface{}
	decodedHeader, err := base64.RawURLEncoding.DecodeString(string(jwsSegments[0]))
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal(decodedHeader, &header)
	if err != nil {
		return nil, nil, err
	}

	var payload map[string]interface{}
	decodedPayload, err := base64.RawURLEncoding.DecodeString(string(jwsSegments[1]))
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal(decodedPayload, &payload)
	if err != nil {
		return nil, nil, err
	}

	return header, payload, nil
}

func IsJWSExpired(compactJWS string) bool {
	_, claims, err := getJWSContent(compactJWS)
	if err != nil {
		return true
	}
	if exp, found := claims["exp"]; found {
		if time.Now().UTC().Unix() >= int64(exp.(float64)) {
			return true
		}
	}
	return false
}

func ecdsaSign(msg string, key *ecdsa.PrivateKey) (string, error) {
	hash := sha256.Sum256([]byte(msg))

	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}

	keyBits := key.Curve.Params().BitSize
	keyBytes := keyBits / 8
	if keyBits % 8 > 0 {
		keyBytes += 1
	}

	rBytes := r.Bytes()
	rPadded := make([]byte, keyBytes)
	copy(rPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sPadded := make([]byte, keyBytes)
	copy(sPadded[keyBytes-len(sBytes):], sBytes)

	return hex.EncodeToString(append(rPadded, sPadded...)), nil
}

func ecdsaVerify(msg, signature string, key *ecdsa.PublicKey) error {
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return errors.New("invalid signature")
	}

	hash := sha256.Sum256([]byte(msg))

	keySize := len(sig) / 2
	r := big.NewInt(0).SetBytes(sig[:keySize])
	s := big.NewInt(0).SetBytes(sig[keySize:])

	pass := ecdsa.Verify(key, hash[:], r, s)
	if !pass {
		return errors.New("signature verification failed")
	}
	return nil
}

func getPublicJWKFromJWKS(set *JsonWebKeySet) *JsonWebKey {
	if set == nil || len(set.Keys) == 0 {
		return nil
	}
	for _, key := range set.Keys {
		if key.D == "" {
			return &key
		}
	}
	return nil
}

func getPrivateJWKFromJWKS(set *JsonWebKeySet) *JsonWebKey {
	if set == nil || len(set.Keys) == 0 {
		return nil
	}
	for _, key := range set.Keys {
		if key.D != "" {
			return &key
		}
	}
	return nil
}

func getBasicAuthEncodedString(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func convertUnixTimestampToString(timestamp int64) string {
	return strconv.FormatInt(timestamp, 10)
}

func getHexEncodedHashString(data string) string {
	sizeBuf := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sizeBuf[:])
}