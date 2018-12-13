package swagger

type CommitClientResponse struct {
	SignedClientCredentials string `json:"signed_client_credentials"`
	Location                string `json:location,omitempty`
}
