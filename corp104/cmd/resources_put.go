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
  
  # Restful
  hydra resources put \
     --endpoint "http://localhost:4444" \
     --resource-metadata '{"uri":"https://v3ms.104.com.tw/jobs","name":"jobs","type":"rest","auth_service":"https://v3auth.104.com.tw","default_scope_auth_type":"company","grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer","client_credentials"],"scopes":[{"name":"rest:jobs:read","scope_auth_type":"","description":"關於rest:jobs:read"},{"name":"rest:jobs:write","scope_auth_type":"","description":"關於rest:jobs:write"}],"paths":[{"name":"/","methods":[{"name":"GET","description":"取得 job 列表","scopes":["rest:jobs:read","rest:jobs:write"]}]},{"name":"/","methods":[{"name":"POST","description":"取得 job 列表","scopes":["rest:jobs:write"]}]},{"name":"/{jobNo}","methods":[{"name":"GET","description":"取得 job 資料","scopes":["rest:jobs:read","rest:jobs:write"]}]},{"name":"/{jobNo}","methods":[{"name":"DELETE","description":"刪除 job 資料","scopes":["rest:jobs:write"]}]},{"name":"/{jobNo}","methods":[{"name":"PATCH","description":"修改 job 資料","scopes":["rest:jobs:write"]}]}],"contacts":["someone@104.com.tw"],"description":"公司資料"}' \
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}' \ 
     --auth-public-jwk '{"use":"sig","kty":"EC","kid":"public:7d59b645-94e7-48c5-9f73-695b19294737","crv":"P-256","alg":"ES256","x":"zrt4vi0eIGY6iqAzpmrBqth33xl2D8R0kkp7laLqzYQ","y":"wbKUX4uBMidl840SANrfWPoTNU6YmYgYh-Aj51TrrWI"}' \ 
     --user foo.bar \
	 --pwd secret

  # GraphQL
  hydra resources put \
     --endpoint "http://localhost:4444" \
     --resource-metadata '{"uri":"https://v3ms.104.com.tw/graphql","name":"resumes","type":"graphql","auth_service":"https://v3auth.104.com.tw","default_scope_auth_type":"company","grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer"],"scopes":[{"name":"graphql:resumes:read","scope_auth_type":"","description":"關於rest:jobs:read"},{"name":"graphql:resumes:edu:read","scope_auth_type":"","description":"關於rest:jobs:edu:read"},{"name":"graphql:resumes:write","scope_auth_type":"","description":"關於rest:jobs:write"}],"graphql_operations":[{"name":"resumes","type":"query","scopes":["graphql:resumes:read","graphql:resumes:write"],"description":"查詢履歷"},{"name":"resumes/edu","type":"query","scopes":["graphql:resumes:edu:read","graphql:resumes:write"],"description":"查詢履歷的教育程度"},{"name":"createResume","type":"mutation","scopes":["graphql:resumes:write"],"description":"新增履歷"},{"name":"deleteResume","type":"mutation","scopes":["graphql:resumes:write"],"description":"刪除履歷"}],"contacts":["someone@104.com.tw"],"description":"歷履表"}' \
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
	resourcesPutCmd.MarkFlagRequired("auth-public-jwk")
	resourcesPutCmd.MarkFlagRequired("user")
	resourcesPutCmd.MarkFlagRequired("pwd")
}
