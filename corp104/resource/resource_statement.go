package resource

import "github.com/ory/hydra/pkg"

type ResourceStatement struct {
	Audience       string                 `json:"aud"`
	IssuedAt       int64                  `json:"iat"`
	Authentication *pkg.ADUserCredentials `json:"authentication,omitempty"`
	Resource       Resource               `json:"resource_metadata"`
}
