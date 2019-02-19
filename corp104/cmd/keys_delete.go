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

// deleteCmd represents the delete command
var keysDeleteCmd = &cobra.Command{
	Use:   "delete <set> <key>",
	Short: "Delete a JSON Web Key Set or a JSON Web Key pair",
	Long: `This command delete a JSON Web Key Set or a JSON Web Key pair.
	
Examples:

  # delete a JSON Web Key Set
    hydra keys delete openid.id-token \
     --endpoint "http://localhost:4445" \
     --user auth.admin \
     --pwd secret

  # delete a JSON Web Key pair by key id (without "private:" or "public:" prefix)
    hydra keys delete openid.id-token 4cd83e5a-51f7-4b99-99fa-1fdaff1a18a1 \
     --endpoint "http://localhost:4445" \
     --user auth.admin \
     --pwd secret
`,
	Run:   cmdHandler.Keys.DeleteKeys,
}

func init() {
	keysCmd.AddCommand(keysDeleteCmd)
	keysDeleteCmd.Flags().String("user", "", "Give the AD account")
	keysDeleteCmd.Flags().String("pwd", "", "Give the AD account password")
	keysDeleteCmd.MarkFlagRequired("user")
	keysDeleteCmd.MarkFlagRequired("pwd")
}
