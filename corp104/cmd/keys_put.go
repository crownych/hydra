package cmd

import (
	"github.com/spf13/cobra"
)

// keysPutCmd represents the put command
var keysPutCmd = &cobra.Command{
	Use:   "put <set>",
	Short: "Put a JSON Web Key Set",
	Long: `This command creates or updates a JSON Web Key Set.

Example:
  hydra keys put my-set \
     --endpoint "http://localhost:4444" \
     --jwks '{"keys":[{"alg":"ES256","crv":"P-256","kid":"public:123456","kty":"EC","use":"sig","x":"1ZWO7twIWsGNYEnb8DXzFst02_oibc7zkVY5GNHYPI0","y":"4ZxzYZeTowbOjsZRK3GlJUHBD2ufewq4PDyBbpFFJAA"},{"alg":"ES256","crv":"P-256","d":"T8klJ70zcr3nS2ooQnD4I7-x3MQDvtsgQF7BO-7dEh0","kid":"private:123456","kty":"EC","use":"sig","x":"1ZWO7twIWsGNYEnb8DXzFst02_oibc7zkVY5GNHYPI0","y":"4ZxzYZeTowbOjsZRK3GlJUHBD2ufewq4PDyBbpFFJAA"}]}' \
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}' \
     --auth-public-jwk '{"use":"sig","kty":"EC","kid":"public:7d59b645-94e7-48c5-9f73-695b19294737","crv":"P-256","alg":"ES256","x":"zrt4vi0eIGY6iqAzpmrBqth33xl2D8R0kkp7laLqzYQ","y":"wbKUX4uBMidl840SANrfWPoTNU6YmYgYh-Aj51TrrWI"}' \
     --user auth.admin \
     --pwd secret
`,
	Run: cmdHandler.Keys.PutKeys,
}

func init() {
	keysCmd.AddCommand(keysPutCmd)
	keysPutCmd.Flags().String("jwks", "", "Give the JSON Web Key Set")
	keysPutCmd.Flags().String("signing-jwk", "", "Client's JSON Web Key document representing the client's private key used to sign the keys statement")
	keysPutCmd.Flags().String("auth-public-jwk", "", "Give the public key of the Auth Service")
	keysPutCmd.Flags().String("user", "", "Give the AD account")
	keysPutCmd.Flags().String("pwd", "", "Give the AD account password")
	// Mark required flags
	keysPutCmd.MarkFlagRequired("jwks")
	keysPutCmd.MarkFlagRequired("auth-public-jwk")
	keysPutCmd.MarkFlagRequired("user")
	keysPutCmd.MarkFlagRequired("pwd")
}
