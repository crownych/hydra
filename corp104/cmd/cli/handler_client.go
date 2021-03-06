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
	"errors"
	"fmt"
	"github.com/ory/hydra/corp104/config"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/ory/hydra/pkg"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"strings"
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

	m.Configuration.PrivateJWK = getSigningJWKFromCmd(cmd)

	for _, path := range args {
		reader, err := os.Open(path)
		pkg.Must(err, "Could not open file %s: %s", path, err)
		var c hydra.OAuth2Client
		err = json.NewDecoder(reader).Decode(&c)
		pkg.Must(err, "Could not parse JSON: %s", err)
		m.Configuration.AuthSvcOfflinePublicJWK = getAuthServicePublicJWK(cmd)
		result, response, err := m.PutOAuth2Client(c)
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

func (h *ClientHandler) PutClient(cmd *cobra.Command, args []string) {
	var err error
	m := h.newClientManager(cmd)
	secret, _ := cmd.Flags().GetString("secret")

	endpoint, _ := cmd.Flags().GetString("endpoint")
	cc := h.getClientFromPutCmd(cmd)
	signingJwk := getSigningJWKFromCmd(cmd)
	if secret != "" {
		cc.ClientSecret = secret
	}

	if !cc.IsPublic() {
		// authentication
		user, _ := cmd.Flags().GetString("user")
		pwd, _ := cmd.Flags().GetString("pwd")
		if user == "" || pwd == "" {
			err := errors.New("AD user credentials required")
			pkg.Must(err, "Error: Required flag(s) \"user\" or \"pwd\" have/has not been set")
		}
		m.Configuration.ADUsername = user
		m.Configuration.ADPassword = pwd
	}

	if getAuthServicePublicJWK(cmd) != nil {
		m.Configuration.AuthSvcOfflinePublicJWK = getAuthServicePublicJWK(cmd)
	}
	m.Configuration.PrivateJWK = signingJwk
	result, response, err := m.PutOAuth2Client(cc)
	if err != nil {
		pkg.Must(err, "Error: "+err.Error())
	}
	fmt.Printf("OAuth 2.0 Signed Client ID: %s\n", result.SignedClientId)

	if cc.IsPublic() {
		checkResponse(response, err, http.StatusCreated)
	} else {
		checkResponse(response, err, http.StatusAccepted)
		storeCookies(cc.ClientId, response.Cookies(), getEndpointHostname(h.Config.GetClusterURLWithoutTailingSlashOrFail(cmd)))
		fmt.Printf("\nRun \"hydra clients commit --endpoint %s --id %s --commit-code <COMMIT_CODE>\" to complete client registration\n", endpoint, cc.ClientId)
	}
}

func (h *ClientHandler) CommitClient(cmd *cobra.Command, args []string) {
	var err error
	m := h.newClientManager(cmd)
	id, _ := cmd.Flags().GetString("id")
	commitCode, _ := cmd.Flags().GetString("commit-code")
	result, response, err := m.CommitOAuth2Client(getStoredCookies(id), commitCode)
	checkResponse(response, err, http.StatusOK)

	fmt.Printf("OAuth 2.0 Signed Client Credentials: %s\n", result.SignedClientCredentials)
	deleteCookies(id)
}

func (h *ClientHandler) DeleteClient(cmd *cobra.Command, args []string) {
	m := h.newClientManager(cmd)

	if len(args) == 0 {
		fmt.Print(cmd.UsageString())
		return
	}

	response, err := m.DeleteOAuth2Client(args[0])
	checkResponse(response, err, http.StatusNoContent)
	fmt.Println("OAuth2 client deleted.")
}

func (h *ClientHandler) GetClient(cmd *cobra.Command, args []string) {
	m := h.newClientManager(cmd)

	if len(args) == 0 {
		fmt.Print(cmd.UsageString())
		return
	}

	clientSecret, _ := cmd.Flags().GetString("secret")

	cl, response, err := m.GetOAuth2Client(args[0], clientSecret)
	checkResponse(response, err, http.StatusOK)
	fmt.Printf("%s\n", formatResponse(cl))
}

func (h *ClientHandler) getClientFromPutCmd(cmd *cobra.Command) hydra.OAuth2Client {
	responseTypes, _ := cmd.Flags().GetStringSlice("response-types")
	grantTypes, _ := cmd.Flags().GetStringSlice("grant-types")
	allowedScopes, _ := cmd.Flags().GetStringSlice("scope")
	callbacks, _ := cmd.Flags().GetStringSlice("callbacks")
	name, _ := cmd.Flags().GetString("name")
	id, _ := cmd.Flags().GetString("id")
	tokenEndpointAuthMethod, _ := cmd.Flags().GetString("token-endpoint-auth-method")
	//jwksUri, _ := cmd.Flags().GetString("jwks-uri")
	tosUri, _ := cmd.Flags().GetString("tos-uri")
	policyUri, _ := cmd.Flags().GetString("policy-uri")
	logoUri, _ := cmd.Flags().GetString("logo-uri")
	clientUri, _ := cmd.Flags().GetString("client-uri")
	subjectType, _ := cmd.Flags().GetString("subject-type")
	contacts, _ := cmd.Flags().GetStringSlice("contacts")
	softwareId, _ := cmd.Flags().GetString("software-id")
	softwareVersion, _ := cmd.Flags().GetString("software-version")
	idTokenSignedResponseAlg, _ := cmd.Flags().GetString("id-token-signed-response-alg")
	requestObjectSigningAlg, _ := cmd.Flags().GetString("request-object-signing-alg")
	clientProfile, _ := cmd.Flags().GetString("client-profile")

	cc := hydra.OAuth2Client{
		ClientId:                id,
		ResponseTypes:           responseTypes,
		GrantTypes:              grantTypes,
		RedirectUris:            callbacks,
		Scope:                   strings.Join(allowedScopes, " "),
		ClientName:              name,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		//JwksUri:                  jwksUri,
		TosUri:                   tosUri,
		PolicyUri:                policyUri,
		LogoUri:                  logoUri,
		ClientUri:                clientUri,
		SubjectType:              subjectType,
		Contacts:                 contacts,
		SoftwareId:               softwareId,
		SoftwareVersion:          softwareVersion,
		IdTokenSignedResponseAlg: idTokenSignedResponseAlg,
		RequestObjectSigningAlg:  requestObjectSigningAlg,
		ClientProfile:			  clientProfile,
	}

	cc.Jwks = getJWKSFromCmd(cmd)

	return cc
}
