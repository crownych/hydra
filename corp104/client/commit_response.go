package client

type CommitResponse struct {
	Location                string `json:"location"`
	SignedClientCredentials string `json:"signed_client_credentials"`
}
