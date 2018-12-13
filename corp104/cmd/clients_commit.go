package cmd

import (
	"github.com/spf13/cobra"
)

// clientsCommitCmd represents the commit command
var clientsCommitCmd = &cobra.Command{
	Use:   "commit <id>",
	Short: "Commit an OAuth 2.0 Confidential Client",
	Long: `This command commit an OAuth 2.0 Confidential Client.

Example:
  hydra clients commit \
	--endpoint "http://localhost:4444" \
	--id ga3030d2-9e16-4b7d-b27f-381e840175cb \
	--commit-code 7a5e421f-d826-455b-bd5e-5457750d4daa \
	--signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}'
`,
	Run: cmdHandler.Clients.CommitClient,
}

func init() {
	clientsCmd.AddCommand(clientsCommitCmd)
	clientsCommitCmd.Flags().String("id", "", "Give the Client ID")
	clientsCommitCmd.Flags().String("commit-code", "", "Give the commit code")
	// Mark required flags
	clientsCommitCmd.MarkFlagRequired("id")
	clientsCommitCmd.MarkFlagRequired("commit-code")
}
