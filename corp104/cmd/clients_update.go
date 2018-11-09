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

// createCmd represents the update command
var clientsUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an OAuth 2.0 Client",
	Long: `This command updates an OAuth 2.0 Client which can be used to perform various OAuth 2.0 Flows like
the Authorize Code, Implicit, Refresh flow.

ORY Hydra implements the OpenID Connect Dynamic Client registration specification. Most flags are supported by this command
as well.

Example:
  
  hydra clients update \
     --endpoint "http://localhost:4444" \
     --id "fa3030d2-9e16-4b7d-b27f-381e840175cb" \
	 --secret "fa3030d2-9e16-4b7d-b27f-381e840175cb" \
     --name "my-app" \
     --grant-types "urn:ietf:params:oauth:grant-type:token-exchange" \
     --client-uri "http://myapp.com" \
	 --contacts "admin@myapp.com" \
	 --software-id "4d51529c-37cd-424c-ba19-cba742d60903" \
	 --software-version "0.0.1" \
     --token-endpoint-auth-method "private_key_jwt" \
	 --jwks '{"keys":[{"use":"sig","kty":"EC","kid":"public:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg"}]}' \ 
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}'
`,
	Run: cmdHandler.Clients.UpdateClient,
}

func init() {
	clientsCmd.AddCommand(clientsUpdateCmd)
	clientsUpdateCmd.Flags().String("id", "", "Give the client this id")
	clientsUpdateCmd.Flags().String("secret", "", "Provide the client's secret")
	clientsUpdateCmd.Flags().String("new-secret", "", "Provide the client's new secret")
	clientsUpdateCmd.Flags().StringSliceP("callbacks", "c", []string{""}, "REQUIRED list of allowed callback URLs")
	clientsUpdateCmd.Flags().StringSliceP("grant-types", "g", []string{""}, "A list of allowed grant types")
	clientsUpdateCmd.Flags().StringSliceP("response-types", "r", []string{""}, "A list of allowed response types")
	clientsUpdateCmd.Flags().StringSliceP("scope", "a", []string{""}, "The scope the client is allowed to request")
	clientsUpdateCmd.Flags().String("token-endpoint-auth-method", "none", "Define which authentication method the client may use at the Token Endpoint. Valid values are \"private_key_jwt\" and \"none\"")
	//clientsUpdateCmd.Flags().String("jwks-uri", "", "Define the URL where the JSON Web Key Set should be fetched from when performing the \"private_key_jwt\" client authentication method")
	clientsUpdateCmd.Flags().String("policy-uri", "", "A URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data")
	clientsUpdateCmd.Flags().String("tos-uri", "", "A URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client")
	clientsUpdateCmd.Flags().String("client-uri", "", "A URL string of a web page providing information about the client")
	clientsUpdateCmd.Flags().String("logo-uri", "", "A URL string that references a logo for the client")
	clientsUpdateCmd.Flags().String("subject-type", "public", "A URL string that references a logo for the client")
	//clientsUpdateCmd.Flags().String("secret", "", "Provide the client's secret")
	clientsUpdateCmd.Flags().StringP("name", "n", "", "The client's name")
	clientsUpdateCmd.Flags().StringSlice("contacts", []string{}, "A list of people responsible for this client")
	clientsUpdateCmd.Flags().String("software-id", "", "A unique identifier string to identify the client software to be dynamically registered")
	clientsUpdateCmd.Flags().String("software-version", "", "A version identifier string for the client software identified by “software_id”.")
	clientsUpdateCmd.Flags().StringSlice("resource-sets", []string{""}, "The resource sets the client is allowed to request")
	clientsUpdateCmd.Flags().String("signing-jwk", "", "Client's JSON Web Key document representing the client's private key used to sign the software statement")
	clientsUpdateCmd.Flags().String("jwks", "", "Client's JSON Web Key Set document representing the client's public keys")
	clientsUpdateCmd.Flags().String("id-token-signed-response-alg", "ES256", "JWS \"alg\" algorithm for signing the ID Token issued to the client, the default value is \"ES256\"")
	clientsUpdateCmd.Flags().String("request-object-signing-alg", "ES256", " JWS \"alg\" algorithm that used for signing Request Objects sent to the OP, the default value is \"ES256\"")
	// Mark required flags
	clientsUpdateCmd.MarkFlagRequired("id")
	clientsUpdateCmd.MarkFlagRequired("secret")
	clientsUpdateCmd.MarkFlagRequired("name")
	clientsUpdateCmd.MarkFlagRequired("grant-types")
	clientsUpdateCmd.MarkFlagRequired("client-uri")
	clientsUpdateCmd.MarkFlagRequired("contacts")
	clientsUpdateCmd.MarkFlagRequired("software-id")
	clientsUpdateCmd.MarkFlagRequired("software-version")
	clientsUpdateCmd.MarkFlagRequired("signing-jwk")
}
