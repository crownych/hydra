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
)

// getCmd represents the get command
var keysGetCmd = &cobra.Command{
	Use:   "get <set> <key>",
	Short: "Get a JSON Web Key Set or a JSON Web Key",
	Long: `This command retrieves a JSON Web Key Set or a JSON Web Key.

Example:

  # get a JSON Web Key Set
  hydra keys get my-set \
     --endpoint "http://localhost:4444" \
     --user auth.admin \
     --pwd secret

  # get a JSON Web Key
  hydra keys get my-set public:123456 \
     --endpoint "http://localhost:4444" \
     --user auth.admin \
     --pwd secret
`,
	Run:   cmdHandler.Keys.GetKeys,
}

func init() {
	keysCmd.AddCommand(keysGetCmd)
	keysGetCmd.Flags().String("user", "", "Give the AD account")
	keysGetCmd.Flags().String("pwd", "", "Give the AD account password")
	keysGetCmd.MarkFlagRequired("user")
	keysGetCmd.MarkFlagRequired("pwd")
}
