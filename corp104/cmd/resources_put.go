package cmd

import (
	"github.com/spf13/cobra"
)

// putCmd represents the put command
var resourcesPutCmd = &cobra.Command{
	Use:   "put",
	Short: "Put an OAuth 2.0 Resource",
	Long: `This command creates or updates an OAuth 2.0 Resource.

Example:
  
  hydra resources put \
     --endpoint "http://localhost:4444" \
     --resource-metadata '{"uri":"https://v3ms.104.com.tw/resume","name":"resume","scope_auth_type":"company","grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],"scopes":[{"name":"resume:v1.0:semi-read","scope_auth_type":"","description":"讀半顯履歷資料"},{"name":"resume:v1.0:read","scope_auth_type":"","description":"讀履歷資料"}],"paths":[{"name":"/{resume_id}","methods":[{"name":"GET","description":"取得 resume 資料","scopes":["resume:v1.0:semi-read","resume:v1.0:read"]}]},{"name":"/","methods":[{"name":"GET","description":"取得 resume 列表","scopes":["resume:v1.0:semi-read","resume:v1.0:read"]}]}],"version":"1.0","contacts":["some.one@104.com.tw"],"description":"履歷資料API"}' \
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}' \ 
     --auth-public-jwk '{"use":"sig","kty":"EC","kid":"public:7d59b645-94e7-48c5-9f73-695b19294737","crv":"P-256","alg":"ES256","x":"zrt4vi0eIGY6iqAzpmrBqth33xl2D8R0kkp7laLqzYQ","y":"wbKUX4uBMidl840SANrfWPoTNU6YmYgYh-Aj51TrrWI"}' \ 
     --user foo.bar \
	 --pwd secret
`,
	Run: cmdHandler.Resources.PutResource,
}

func init() {
	resourcesCmd.AddCommand(resourcesPutCmd)
	resourcesPutCmd.Flags().String("resource-metadata", "", "Give the resource metadata")
	resourcesPutCmd.Flags().String("signing-jwk", "", "Client's JSON Web Key document representing the client's private key used to sign the software statement")
	resourcesPutCmd.Flags().String("auth-public-jwk", "", "Give the public key of the Auth Service")
	resourcesPutCmd.Flags().String("user", "", "Give the AD account")
	resourcesPutCmd.Flags().String("pwd", "", "Give the AD account password")
	// Mark required flags
	resourcesPutCmd.MarkFlagRequired("resource-metadata")
	resourcesPutCmd.MarkFlagRequired("signing-jwk")
	resourcesPutCmd.MarkFlagRequired("auth-public-jwk")
	resourcesPutCmd.MarkFlagRequired("user")
	resourcesPutCmd.MarkFlagRequired("pwd")
}
