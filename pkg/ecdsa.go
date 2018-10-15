package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func MustECDSAKEYFORTEST() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}
