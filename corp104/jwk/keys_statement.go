package jwk

import (
	"github.com/ory/hydra/pkg"
)

type KeysMetadata struct {
	Set  string            `json:"set" validate:"required"`
	JWKS pkg.JSONWebKeySet `json:"jwks,omitempty" validate:"required"`
}

type KeysStatement struct {
	Audience       string                 `json:"aud"`
	IssuedAt       int64                  `json:"iat"`
	Authentication *pkg.ADUserCredentials `json:"authentication,omitempty"`
	Metadata       KeysMetadata           `json:"keys_metadata"`
}

type CommitResponse struct {
	Location                string `json:"location"`
}
