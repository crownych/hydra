package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// resourcesCmd represents the resources command
var resourcesCmd = &cobra.Command{
	Use:   "resources <command>",
	Short: "Manage OAuth 2.0 Resources",
}

func init() {
	RootCmd.AddCommand(resourcesCmd)
	//resourcesCmd.PersistentFlags().Bool("dry", false, "do not execute the command but show the corresponding curl command instead")
	resourcesCmd.PersistentFlags().Bool("fake-tls-termination", false, `Fake tls termination by adding "X-Forwarded-Proto: https" to http headers`)
	resourcesCmd.PersistentFlags().String("access-token", os.Getenv("OAUTH2_ACCESS_TOKEN"), "Set an access token to be used in the Authorization header, defaults to environment variable ACCESS_TOKEN")
	resourcesCmd.PersistentFlags().String("endpoint", os.Getenv("HYDRA_ADMIN_URL"), "Set the URL where ORY Hydra is hosted, defaults to environment variable HYDRA_ADMIN_URL")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// resourcesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// resourcesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
