package jwk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"strings"

	"context"

	jwt2 "github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
)

func NewES256JWTStrategy(m Manager, set string) (*ES256JWTStrategy, error) {
	j := &ES256JWTStrategy{
		Manager:          m,
		ES256JWTStrategy: &jwt.ES256JWTStrategy{},
		Set:              set,
	}
	if err := j.refresh(context.TODO()); err != nil {
		return nil, err
	}
	return j, nil
}

type ES256JWTStrategy struct {
	ES256JWTStrategy *jwt.ES256JWTStrategy
	Manager          Manager
	Set              string

	publicKey    *ecdsa.PublicKey
	privateKey   *ecdsa.PrivateKey
	publicKeyID  string
	privateKeyID string
}

func (j *ES256JWTStrategy) Hash(ctx context.Context, in []byte) ([]byte, error) {
	return j.ES256JWTStrategy.Hash(ctx, in)
}

// GetSigningMethodLength will return the length of the signing method
func (j *ES256JWTStrategy) GetSigningMethodLength() int {
	return j.ES256JWTStrategy.GetSigningMethodLength()
}

func (j *ES256JWTStrategy) GetSignature(ctx context.Context, token string) (string, error) {
	return j.ES256JWTStrategy.GetSignature(ctx, token)
}

func (j *ES256JWTStrategy) Generate(ctx context.Context, claims jwt2.Claims, header jwt.Mapper) (string, string, error) {
	if err := j.refresh(ctx); err != nil {
		return "", "", err
	}

	return j.ES256JWTStrategy.Generate(ctx, claims, header)
}

func (j *ES256JWTStrategy) Validate(ctx context.Context, token string) (string, error) {
	if err := j.refresh(ctx); err != nil {
		return "", err
	}

	return j.ES256JWTStrategy.Validate(ctx, token)
}

func (j *ES256JWTStrategy) Decode(ctx context.Context, token string) (*jwt2.Token, error) {
	if err := j.refresh(ctx); err != nil {
		return nil, err
	}

	return j.ES256JWTStrategy.Decode(ctx, token)
}

func (j *ES256JWTStrategy) GetPublicKeyID(ctx context.Context) (string, error) {
	if err := j.refresh(ctx); err != nil {
		return "", err
	}

	return j.publicKeyID, nil
}

func (j *ES256JWTStrategy) refresh(ctx context.Context) error {
	keys, err := j.Manager.GetKeySet(ctx, j.Set)
	if err != nil {
		return err
	}

	public, err := FindKeyByPrefix(keys, "public")
	if err != nil {
		return err
	}

	private, err := FindKeyByPrefix(keys, "private")
	if err != nil {
		return err
	}

	if strings.Replace(public.KeyID, "public:", "", 1) != strings.Replace(private.KeyID, "private:", "", 1) {
		return errors.New("public and private key pair kids do not match")
	}

	if k, ok := private.Key.(*ecdsa.PrivateKey); !ok {
		return errors.New("unable to type assert key to *ecdsa.PublicKey")
	} else {
		j.privateKey = k
		j.ES256JWTStrategy.PrivateKey = k
	}

	if k, ok := public.Key.(*ecdsa.PublicKey); !ok {
		return errors.New("unable to type assert key to *ecdsa.PublicKey")
	} else {
		j.publicKey = k
		j.publicKeyID = public.KeyID
	}

	a, ok := x509.MarshalPKIXPublicKey(&j.privateKey.PublicKey)
	if ok != nil {
		return errors.New("unable to marshal *ecdsa.PublicKey to PKIX")
	}
	b, ok := x509.MarshalPKIXPublicKey(j.publicKey)
	if ok != nil {
		return errors.New("unable to marshal *ecdsa.PublicKey to PKIX")
	}
	if !bytes.Equal(a, b) {
		return errors.New("public and private key pair fetched from store does not match")
	}

	return nil
}
