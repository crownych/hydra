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

var clientsImportCmd = &cobra.Command{
	Use:   "import <path/to/file.json> [<path/to/other/file.json>...]",
	Short: "Import OAuth 2.0 Clients from one or more JSON files",
	Long: `This command reads in each listed JSON file and imports their contents as OAuth 2.0 Clients.

The format for the JSON file is:

{
  "client_id": "...",
  "client_secret": "...",
  // ... all other fields of the OAuth 2.0 Client model are allowed here
}

Please be aware that this command does not update existing clients. If the client exists already, this command will fail.

Example:
	hydra clients import client-1.json --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}'
`,
	Run: cmdHandler.Clients.ImportClients,
}

func init() {
	clientsCmd.AddCommand(clientsImportCmd)
	clientsImportCmd.Flags().String("signing-jwk", "", "REQUIRED. Client's JSON Web Key document representing the client's private key used to sign the software statement")
}
