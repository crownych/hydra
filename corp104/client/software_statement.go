package client

import "github.com/ory/hydra/pkg"

type SoftwareStatement struct {
	Audience       string                 `json:"aud"`
	IssuedAt       int64                  `json:"iat"`
	Authentication *pkg.ADUserCredentials `json:"authentication,omitempty"`
	Client         Client                 `json:"client_metadata"`
}
