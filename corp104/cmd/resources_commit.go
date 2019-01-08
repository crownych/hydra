package cmd

import (
	"github.com/spf13/cobra"
)

// resourcesCommitCmd represents the commit command
var resourcesCommitCmd = &cobra.Command{
	Use:   "commit <id>",
	Short: "Commit an OAuth 2.0 Confidential Resource",
	Long: `This command commit an OAuth 2.0 Resource.

Example:
  hydra resource commit \
	--endpoint "http://localhost:4444" \
	--urn  "urn:104:v3:job:v1.0" \
	--commit-code 7a5e421f-d826-455b-bd5e-5457750d4daa
`,
	Run: cmdHandler.Resources.CommitResource,
}

func init() {
	resourcesCmd.AddCommand(resourcesCommitCmd)
	resourcesCommitCmd.Flags().String("urn", "", "Give the Resource URN")
	resourcesCommitCmd.Flags().String("commit-code", "", "Give the commit code")
	// Mark required flags
	resourcesCommitCmd.MarkFlagRequired("urn")
	resourcesCommitCmd.MarkFlagRequired("commit-code")
}
