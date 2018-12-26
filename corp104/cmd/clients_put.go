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

// putCmd represents the put command
var clientsPutCmd = &cobra.Command{
	Use:   "put",
	Short: "Put an OAuth 2.0 Client",
	Long: `This command creates or updates an OAuth 2.0 Client which can be used to perform various OAuth 2.0 Flows like
the Authorize Code, Implicit, Refresh flow.

ORY Hydra implements the OpenID Connect Dynamic Client registration specification. Most flags are supported by this command
as well.

Example:
  
  # Public Client
  hydra clients put \
     --endpoint "http://localhost:4444" \
     --id "a3a89ca9-c54c-4731-8494-6c057a16a14c" \
     --name "my-app" \
     --grant-types "implicit" \
     --grant-types "urn:ietf:params:oauth:grant-type:jwt-bearer" \
     --client-uri "http://myapp.com" \
	 --contacts "admin@myapp.com" \
	 --software-id "4d51529c-37cd-424c-ba19-cba742d60903" \
	 --software-version "0.0.1" \
     --callbacks "http://myapp.com/oauth/callback" \
     --response-types "token" \
     --response-types "id_token" \
     --scope "openid" \
     --id-token-signed-response-alg "ES256" \
     --request-object-signing-alg "ES256" \
	 --token-endpoint-auth-method "private_key_jwt+session" \
     --jwks '{"keys":[{"use":"sig","kty":"EC","kid":"public:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg"}]}' \
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}' \
     --auth-public-jwk '{"use":"sig","kty":"EC","kid":"public:7d59b645-94e7-48c5-9f73-695b19294737","crv":"P-256","alg":"ES256","x":"zrt4vi0eIGY6iqAzpmrBqth33xl2D8R0kkp7laLqzYQ","y":"wbKUX4uBMidl840SANrfWPoTNU6YmYgYh-Aj51TrrWI"}'

  # Confidential Client
  hydra clients put \
     --endpoint "http://localhost:4444" \
     --id "fa3030d2-9e16-4b7d-b27f-381e840175cb" \
     --name "my-app" \
     --grant-types "urn:ietf:params:oauth:grant-type:jwt-bearer" \
     --client-uri "http://myapp.com" \
	 --contacts "admin@myapp.com" \
	 --software-id "4d51529c-37cd-424c-ba19-cba742d60903" \
	 --software-version "0.0.1" \
     --token-endpoint-auth-method "private_key_jwt" \
	 --jwks '{"keys":[{"use":"sig","kty":"EC","kid":"public:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg"}]}' \ 
     --signing-jwk '{"use":"sig","kty":"EC","kid":"private:89b940e8-a16f-48ce-a238-b52d7e252634","crv":"P-256","alg":"ES256","x":"6yi0V0cyxGVc5fEiu2U2PuZr4TxavTguccdcco1XyuA","y":"kX_biw0hYHyt1qaVP4EbP7WScIu9QyPK0Aj3fXpBRCg","d":"G4ExPHksANQZgLJzElHUGL43The7h0AKJE69qrgcZRo"}' \ 
     --auth-public-jwk '{"use":"sig","kty":"EC","kid":"public:7d59b645-94e7-48c5-9f73-695b19294737","crv":"P-256","alg":"ES256","x":"zrt4vi0eIGY6iqAzpmrBqth33xl2D8R0kkp7laLqzYQ","y":"wbKUX4uBMidl840SANrfWPoTNU6YmYgYh-Aj51TrrWI"}' \ 
     --user foo.bar \
	 --pwd secret


`,
	Run: cmdHandler.Clients.PutClient,
}

func init() {
	clientsCmd.AddCommand(clientsPutCmd)
	clientsPutCmd.Flags().String("id", "", "Give the client this id")
	clientsPutCmd.Flags().String("secret", "", "Provide the client's secret")
	clientsPutCmd.Flags().StringSliceP("callbacks", "c", []string{""}, "REQUIRED list of allowed callback URLs")
	clientsPutCmd.Flags().StringSliceP("grant-types", "g", []string{""}, "A list of allowed grant types")
	clientsPutCmd.Flags().StringSliceP("response-types", "r", []string{""}, "A list of allowed response types")
	clientsPutCmd.Flags().StringSliceP("scope", "a", []string{""}, "The scope the client is allowed to request")
	clientsPutCmd.Flags().String("token-endpoint-auth-method", "private_key_jwt", "Define which authentication method the client may use at the Token Endpoint. Valid values are \"private_key_jwt\" and \"session\"")
	//clientsPutCmd.Flags().String("jwks-uri", "", "Define the URL where the JSON Web Key Set should be fetched from when performing the \"private_key_jwt\" client authentication method")
	clientsPutCmd.Flags().String("policy-uri", "", "A URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data")
	clientsPutCmd.Flags().String("tos-uri", "", "A URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client")
	clientsPutCmd.Flags().String("client-uri", "", "A URL string of a web page providing information about the client")
	clientsPutCmd.Flags().String("logo-uri", "", "A URL string that references a logo for the client")
	clientsPutCmd.Flags().String("subject-type", "public", "A URL string that references a logo for the client")
	//clientsPutCmd.Flags().String("secret", "", "Provide the client's secret")
	clientsPutCmd.Flags().StringP("name", "n", "", "The client's name")
	clientsPutCmd.Flags().StringSlice("contacts", []string{}, "A list of people responsible for this client")
	clientsPutCmd.Flags().String("software-id", "", "A unique identifier string to identify the client software to be dynamically registered")
	clientsPutCmd.Flags().String("software-version", "", "A version identifier string for the client software identified by “software_id”.")
	clientsPutCmd.Flags().String("signing-jwk", "", "Client's JSON Web Key document representing the client's private key used to sign the software statement")
	clientsPutCmd.Flags().String("jwks", "", "Client's JSON Web Key Set document representing the client's public keys")
	clientsPutCmd.Flags().String("id-token-signed-response-alg", "ES256", "JWS \"alg\" algorithm for signing the ID Token issued to the client, the default value is \"ES256\"")
	clientsPutCmd.Flags().String("request-object-signing-alg", "ES256", " JWS \"alg\" algorithm that used for signing Request Objects sent to the OP, the default value is \"ES256\"")
	clientsPutCmd.Flags().String("auth-public-jwk", "", "Give the public key of the Auth Service")
	clientsPutCmd.Flags().String("user", "", "Give the AD account")
	clientsPutCmd.Flags().String("pwd", "", "Give the AD account password")
	// Mark required flags
	clientsPutCmd.MarkFlagRequired("id")
	clientsPutCmd.MarkFlagRequired("name")
	clientsPutCmd.MarkFlagRequired("grant-types")
	clientsPutCmd.MarkFlagRequired("client-uri")
	clientsPutCmd.MarkFlagRequired("contacts")
	clientsPutCmd.MarkFlagRequired("software-id")
	clientsPutCmd.MarkFlagRequired("software-version")
	clientsPutCmd.MarkFlagRequired("signing-jwk")
	clientsPutCmd.MarkFlagRequired("auth-public-jwk")
	clientsPutCmd.MarkFlagRequired("token-endpoint-auth-method")
}
