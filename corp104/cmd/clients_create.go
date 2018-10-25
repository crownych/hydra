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

// createCmd represents the create command
var clientsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new OAuth 2.0 Client",
	Long: `This command creates an OAuth 2.0 Client which can be used to perform various OAuth 2.0 Flows like
the Authorize Code, Implicit, Refresh flow.

ORY Hydra implements the OpenID Connect Dynamic Client registration specification. Most flags are supported by this command
as well.

Example:
  
  # Public Client
  hydra clients create \
     --endpoint "http://localhost:4445" \
     --id "a3a89ca9-c54c-4731-8494-6c057a16a14c" \
     --name "my-app" \
     --grant-types "implicit" \
     --client-uri "http://myapp.com" \
	 --contacts "admin@myapp.com" \
	 --software-id "4d51529c-37cd-424c-ba19-cba742d60903" \
	 --software-version "0.0.1" \
     --callbacks "http://myapp.com/oauth/callback" \
     --response-types "token" \
     --response-types "id_token" \
     --id-token-signed-response-alg "ES256" \
     --request-object-signing-alg "ES256" \
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}'

  # Confidential Client
  hydra clients create \
     --endpoint "http://localhost:4445" \
     --id "fa3030d2-9e16-4b7d-b27f-381e840175cb" \
     --name "my-app" \
     --grant-types "urn:ietf:params:oauth:grant-type:token-exchange" \
     --client-uri "http://myapp.com" \
	 --contacts "admin@myapp.com" \
	 --software-id "4d51529c-37cd-424c-ba19-cba742d60903" \
	 --software-version "0.0.1" \
     --token-endpoint-auth-method "private_key_jwt" \
	 --jwks '[{"use":"sig","kty":"EC","kid":"public:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg"}]' \ 
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}'
`,
	Run: cmdHandler.Clients.CreateClient,
}

func init() {
	clientsCmd.AddCommand(clientsCreateCmd)
	// Options for all types of client
	clientsCreateCmd.Flags().String("id", "", "REQUIRED. Give the client this id")
	clientsCreateCmd.Flags().StringP("name", "n", "", "The client's name")
	clientsCreateCmd.Flags().StringSliceP("grant-types", "g", []string{""}, "REQUIRED. A list of allowed grant types. Public client should be \"implicit\"; confidential client should be \"urn:ietf:params:oauth:grant-type:token-exchange\"")
	clientsCreateCmd.Flags().String("client-uri", "", "A URL string of a web page providing information about the client")
	clientsCreateCmd.Flags().StringSlice("contacts", []string{}, "REQUIRED. A list of people responsible for this client")
	clientsCreateCmd.Flags().String("software-id", "", "REQUIRED. A unique identifier string to identify the client software to be dynamically registered")
	clientsCreateCmd.Flags().String("software-version", "", "REQUIRED. A version identifier string for the client software identified by “software_id”.")
	clientsCreateCmd.Flags().StringSlice("resource-sets", []string{""}, "The resource sets the client is allowed to request")
	clientsCreateCmd.Flags().String("signing-jwk", "", "REQUIRED. Client's JSON Web Key document representing the client's private key used to sign the software statement")
	clientsCreateCmd.Flags().String("token-endpoint-auth-method", "none", "Define which authentication method the client may use at the Token Endpoint. Valid values are \"private_key_jwt\" (confidential client), and \"none\" (public client)")
	// Options for public client
	clientsCreateCmd.Flags().StringSliceP("callbacks", "c", []string{""}, "REQUIRED if client is public. A list of allowed callback URLs")
	clientsCreateCmd.Flags().StringSliceP("response-types", "r", []string{""}, "REQUIRED if client is public. A list of allowed response types, should be \"token\" and \"id_token\"")
	clientsCreateCmd.Flags().String("id-token-signed-response-alg", "ES256", "JWS \"alg\" algorithm for signing the ID Token issued to the client, the default value is \"ES256\"")
	clientsCreateCmd.Flags().String("request-object-signing-alg", "ES256", " JWS \"alg\" algorithm that used for signing Request Objects sent to the OP, the default value is \"ES256\"")
	// Options for confidential client
	clientsCreateCmd.Flags().String("jwks", "", "REQUIRED if client is confidential. Client's JSON Web Key Set document representing the client's public keys")
}
