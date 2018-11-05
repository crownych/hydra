package cmd

import (
	"github.com/spf13/cobra"
)

// clientsSaveCmd represents the save command
var clientsSaveCmd = &cobra.Command{
	Use:   "save <id>",
	Short: "Save an OAuth 2.0 Client",
	Long: `This command save OAuth 2.0 Client.

Example:
  hydra clients save \
	--endpoint "http://localhost:4444" \
	--id ga3030d2-9e16-4b7d-b27f-381e840175cb \
	--user user1 \
	--pwd secret \
	--signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}'
`,
	Run: cmdHandler.Clients.SaveClient,
}

func init() {
	clientsCmd.AddCommand(clientsSaveCmd)
	clientsSaveCmd.Flags().String("id", "", "Give the Client ID")
	clientsSaveCmd.Flags().String("user", "", "Give the AD account")
	clientsSaveCmd.Flags().String("pwd", "", "Give the AD account password")
	clientsSaveCmd.Flags().String("signing-jwk", "", "Client's JSON Web Key document representing the client's private key used to sign the software statement")
	clientsSaveCmd.Flags().String("save", "false", "Save the client")

	// Mark required flags
	clientsSaveCmd.MarkFlagRequired("id")
	clientsSaveCmd.MarkFlagRequired("user")
	clientsSaveCmd.MarkFlagRequired("pwd")
	clientsSaveCmd.MarkFlagRequired("signing-jwk")
}
