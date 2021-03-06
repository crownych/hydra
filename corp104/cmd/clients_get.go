/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var clientsGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get an OAuth 2.0 Client",
	Long: `This command retrieves an OAuth 2.0 Client by its ID.

Example:
  hydra clients get client-1 --secret secret`,
	Run: cmdHandler.Clients.GetClient,
}

func init() {
	clientsCmd.AddCommand(clientsGetCmd)
	clientsGetCmd.Flags().String("secret", os.Getenv("OAUTH2_CLIENT_SECRET"), "Use the provided OAuth 2.0 Client Secret, defaults to environment variable OAUTH2_CLIENT_SECRET")
	clientsGetCmd.MarkFlagRequired("secret")
}
