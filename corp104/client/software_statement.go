package client

type SoftwareStatement struct {
	Audience       string          `json:"aud"`
	IssuedAt       int64           `json:"iat"`
	Authentication *Authentication `json:"authentication,omitempty"`
	Client         Client          `json:"client_metadata"`
}

type Authentication struct {
	User string `json:"ad_user,omitempty"`
	Pwd  string `json:"ad_pwd,omitempty"`
}
