package cmd

import (
	"github.com/spf13/cobra"
)

var resourcesGetCmd = &cobra.Command{
	Use:   "get <urn>",
	Short: "Get an OAuth 2.0 Resource",
	Long: `This command retrieves an OAuth 2.0 Resource by its URN.

Example:
  hydra resources get "urn:104:v3:resource:rest:jobs"`,
	Run: cmdHandler.Resources.GetResource,
}

func init() {
	resourcesCmd.AddCommand(resourcesGetCmd)
}
