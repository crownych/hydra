package cmd

import (
	"github.com/spf13/cobra"
)

// keysCommitCmd represents the commit command
var keysCommitCmd = &cobra.Command{
	Use:   "commit <id>",
	Short: "Commit a JSON Web Key Set",
	Long: `This command commit a JSON Web Key Set.

Example:

  hydra keys commit my-set \
	--endpoint "http://localhost:4444" \
	--commit-code 7a5e421f-d826-455b-bd5e-5457750d4daa
`,
	Run: cmdHandler.Keys.CommitKeys,
}

func init() {
	keysCmd.AddCommand(keysCommitCmd)
	keysCommitCmd.Flags().String("commit-code", "", "Give the commit code")
	// Mark required flags
	keysCommitCmd.MarkFlagRequired("commit-code")
}
