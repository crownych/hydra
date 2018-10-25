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

package cli

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/ory/hydra/corp104/config"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/ory/hydra/pkg"
	"github.com/spf13/cobra"
	"net/http"
	"os"
)

type ClientHandler struct {
	Config *config.Config
}

func newClientHandler(c *config.Config) *ClientHandler {
	return &ClientHandler{
		Config: c,
	}
}

func (h *ClientHandler) newClientManager(cmd *cobra.Command) *hydra.OAuth2Api {
	c := hydra.NewOAuth2ApiWithBasePath(h.Config.GetClusterURLWithoutTailingSlashOrFail(cmd))

	fakeTlsTermination, _ := cmd.Flags().GetBool("skip-tls-verify")
	c.Configuration.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: fakeTlsTermination},
	}

	if term, _ := cmd.Flags().GetBool("fake-tls-termination"); term {
		c.Configuration.DefaultHeader["X-Forwarded-Proto"] = "https"
	}

	if token, _ := cmd.Flags().GetString("access-token"); token != "" {
		c.Configuration.DefaultHeader["Authorization"] = "Bearer " + token
	}

	return c
}

func (h *ClientHandler) ImportClients(cmd *cobra.Command, args []string) {
	m := h.newClientManager(cmd)

	if len(args) == 0 {
		fmt.Print(cmd.UsageString())
		return
	}

	signingJwkJSON, err := cmd.Flags().GetString("signing-jwk")
	if err != nil {
		pkg.Must(err, "Please provide client's JSON Web Key document representing signing private key using flag --signing-jwk.")
	}
	var signingJwk *hydra.JsonWebKey
	err = json.Unmarshal([]byte(signingJwkJSON), &signingJwk)
	if err != nil {
		fmt.Println("Invalid signing jwk:", err.Error())
		return
	}

	for _, path := range args {
		reader, err := os.Open(path)
		pkg.Must(err, "Could not open file %s: %s", path, err)
		var c hydra.OAuth2Client
		err = json.NewDecoder(reader).Decode(&c)
		pkg.Must(err, "Could not parse JSON: %s", err)

		result, response, err := m.CreateOAuth2Client(c, signingJwk)
		checkResponse(response, err, http.StatusCreated)

		/*
		if c.ClientSecret == "" {
			fmt.Printf("Imported OAuth 2.0 Client %s:%s from %s.\n", result.ClientId, result.ClientSecret, path)
		} else {
			fmt.Printf("Imported OAuth 2.0 Client %s from %s.\n", result.ClientId, path)
		}
		*/
		fmt.Printf("Imported OAuth 2.0 Client %s from %s.\n", result.SignedClientId, path)
	}
}

func (h *ClientHandler) CreateClient(cmd *cobra.Command, args []string) {
	var err error
	m := h.newClientManager(cmd)
	// Options for all client types
	id, err := cmd.Flags().GetString("id")
	if err!= nil {
		pkg.Must(err, "Please provide the client's id using flag --id.")
	}

	name, err := cmd.Flags().GetString("name")
	if err!= nil {
		pkg.Must(err, "Please provide the client's name using flag --name.")
	}

	grantTypes, err := cmd.Flags().GetStringSlice("grant-types")
	if err != nil {
		pkg.Must(err, "Please provide a list of allowed grant types using flag --grant-types.")
	}

	clientUri, err := cmd.Flags().GetString("client-uri")
	if err != nil {
		pkg.Must(err, "Please provide a URL string of a web page providing information about the client using flag --client-uri.")
	}

	contacts, err := cmd.Flags().GetStringSlice("contacts")
	if err != nil {
		pkg.Must(err, "Please provide a list of people responsible for the client using flag --contacts.")
	}

	softwareId, err := cmd.Flags().GetString("software-id")
	if err != nil {
		pkg.Must(err, "Please provide client's JSON Web Key Set document representing public keys using flag --software-id.")
	}

	softwareVersion, err := cmd.Flags().GetString("software-version")
	if err != nil {
		pkg.Must(err, "Please provide client's JSON Web Key Set document representing public keys using flag  --software-version.")
	}

	resourceSets, _ := cmd.Flags().GetStringSlice("resource-sets")

	jwksJSON, err := cmd.Flags().GetString("jwks")
	if err != nil {
		pkg.Must(err, "Please provide client's JSON Web Key Set document representing public keys using flag --jwks.")
	}

	signingJwkJSON, err := cmd.Flags().GetString("signing-jwk")
	if err != nil {
		pkg.Must(err, "Please provide client's JSON Web Key document representing signing private key using flag --signing-jwk.")
	}

	// Options for public client
	callbacks, _ := cmd.Flags().GetStringSlice("callbacks")
	responseTypes, _ := cmd.Flags().GetStringSlice("response-types")
	idTokenSignedResponseAlg, _ := cmd.Flags().GetString("id-token-signed-response-alg")
	requestObjectSigningAlg, _ := cmd.Flags().GetString("request-object-signing-alg")

	// Options for confidential client
	tokenEndpointAuthMethod, _ := cmd.Flags().GetString("token-endpoint-auth-method")

	cc := hydra.OAuth2Client{
		ClientId:                 id,
		ClientName:               name,
		GrantTypes:               grantTypes,
		ClientUri:                clientUri,
		Contacts:				  contacts,
		SoftwareId:               softwareId,
		SoftwareVersion:          softwareVersion,
		ResourceSets:             resourceSets,
		RedirectUris:             callbacks,
		ResponseTypes:            responseTypes,
		IdTokenSignedResponseAlg: idTokenSignedResponseAlg,
		RequestObjectSigningAlg:  requestObjectSigningAlg,
		TokenEndpointAuthMethod:  tokenEndpointAuthMethod,
	}

	if jwksJSON != "" {
		var jwks []hydra.JsonWebKey
		err = json.Unmarshal([]byte(jwksJSON), &jwks)
		if err != nil {
			fmt.Println("Invalid jwks:", err.Error())
			return
		}
		cc.Jwks = &hydra.JsonWebKeySet{Keys: jwks}
	}

	var signingJwk *hydra.JsonWebKey
	err = json.Unmarshal([]byte(signingJwkJSON), &signingJwk)
	if err != nil {
		fmt.Println("Invalid signing jwk:", err.Error())
		return
	}

	result, response, err := m.CreateOAuth2Client(cc, signingJwk)
	checkResponse(response, err, http.StatusCreated)

	fmt.Printf("OAuth 2.0 Signed Client ID: %s\n", result.SignedClientId)
}

func (h *ClientHandler) DeleteClient(cmd *cobra.Command, args []string) {
	m := h.newClientManager(cmd)

	if len(args) == 0 {
		fmt.Print(cmd.UsageString())
		return
	}

	for _, c := range args {
		response, err := m.DeleteOAuth2Client(c)
		checkResponse(response, err, http.StatusNoContent)
	}

	fmt.Println("OAuth2 client(s) deleted.")
}

func (h *ClientHandler) GetClient(cmd *cobra.Command, args []string) {
	m := h.newClientManager(cmd)

	if len(args) == 0 {
		fmt.Print(cmd.UsageString())
		return
	}

	cl, response, err := m.GetOAuth2Client(args[0])
	checkResponse(response, err, http.StatusOK)
	fmt.Printf("%s\n", formatResponse(cl))
}
