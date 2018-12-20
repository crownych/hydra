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
	--commit-code 7a5e421f-d826-455b-bd5e-5457750d4daa
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
