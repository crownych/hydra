package jwk

import (
	"github.com/go-playground/validator"
	"github.com/ory/hydra/pkg"
)

type Validator struct {
	validate *validator.Validate
}

func NewValidator() *Validator {
	return &Validator{
		validate: validator.New(),
	}
}

func (v *Validator) Validate(r *KeysMetadata) error {
	err := v.validate.Struct(r)
	if err != nil {
		return pkg.NewBadRequestError(err.Error())
	}

	if len(r.JWKS.Keys) == 0 {
		return pkg.NewBadRequestError("Key: 'KeysMetadata.Keys' Error:must be set")
	}

	return nil
}
