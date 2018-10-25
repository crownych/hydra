package cmd

import (
	"github.com/spf13/cobra"
)

// urlCmd represents the url command
var urlCmd = &cobra.Command{
	Use:   "url",
	Short: "Generate URL",
}

func init() {
	RootCmd.AddCommand(urlCmd)
}
