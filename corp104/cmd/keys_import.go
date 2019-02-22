// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/spf13/cobra"
)

// keysImportCmd represents the import command
var keysImportCmd = &cobra.Command{
	Use:   "import <set> <file-1> [<file-2> [<file-3 [<...>]]]",
	Short: "Imports cryptographic keys of any format to the JSON Web Key Store",
	Long: `This command allows you to import cryptographic keys to the JSON Web Key Store.

Currently supported formats are raw JSON Web Keys or PEM/DER encoded data. If the JSON Web Key Set exists already,
the imported keys will be added to that set. Otherwise, a new set will be created.

Please be aware that importing a private key does not automatically import its public key as well.

Example:

  hydra keys import my-set ./path/to/jwk.json ./path/to/jwk-2.json \
     --endpoint "http://localhost:4444" \
     --use sig \
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}' \
     --auth-public-jwk '{"use":"sig","kty":"EC","kid":"public:7d59b645-94e7-48c5-9f73-695b19294737","crv":"P-256","alg":"ES256","x":"zrt4vi0eIGY6iqAzpmrBqth33xl2D8R0kkp7laLqzYQ","y":"wbKUX4uBMidl840SANrfWPoTNU6YmYgYh-Aj51TrrWI"}' \
     --user auth.admin \
     --pwd secret
`,
	Run: cmdHandler.Keys.ImportKeys,
}

func init() {
	keysCmd.AddCommand(keysImportCmd)
	keysImportCmd.Flags().String("use", "sig", "Sets the \"use\" value of the JSON Web Key if not \"use\" value was defined by the key itself")
	keysImportCmd.Flags().String("signing-jwk", "", "Client's JSON Web Key document representing the client's private key used to sign the keys statement")
	keysImportCmd.Flags().String("auth-public-jwk", "", "Give the public key of the Auth Service")
	keysImportCmd.Flags().String("user", "", "Give the AD account")
	keysImportCmd.Flags().String("pwd", "", "Give the AD account password")
	// Mark required flags
	keysImportCmd.MarkFlagRequired("auth-public-jwk")
	keysImportCmd.MarkFlagRequired("user")
	keysImportCmd.MarkFlagRequired("pwd")
}
