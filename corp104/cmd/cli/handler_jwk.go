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
	"errors"
	"fmt"
	"github.com/mendsley/gojwk"
	"github.com/ory/hydra/corp104/config"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/ory/hydra/pkg"
	"github.com/pborman/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type JWKHandler struct {
	Config *config.Config
}

func (h *JWKHandler) newJwkManager(cmd *cobra.Command) *hydra.JsonWebKeyApi {
	c := hydra.NewJsonWebKeyApiWithBasePath(h.Config.GetClusterURLWithoutTailingSlashOrFail(cmd))

	skipTLSTermination, _ := cmd.Flags().GetBool("skip-tls-verify")
	c.Configuration.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLSTermination},
	}

	if term, _ := cmd.Flags().GetBool("fake-tls-termination"); term {
		c.Configuration.DefaultHeader["X-Forwarded-Proto"] = "https"
	}

	if token, _ := cmd.Flags().GetString("access-token"); token != "" {
		c.Configuration.DefaultHeader["Authorization"] = "Bearer " + token
	}

	return c
}

func newJWKHandler(c *config.Config) *JWKHandler {
	return &JWKHandler{Config: c}
}

func toSDKFriendlyJSONWebKey(key interface{}, kid string, use string, nbf, exp *int64, public bool) hydra.JsonWebKey {
	if jwk, ok := key.(*pkg.JSONWebKey); ok {
		key = jwk.Key
		if jwk.KeyID != "" {
			kid = jwk.KeyID
		}
		if jwk.Use != "" {
			use = jwk.Use
		}
		nbf = jwk.NotBefore
		exp = jwk.ExpiresAt
	}

	var err error
	var jwk *gojwk.Key
	if public {
		jwk, err = gojwk.PublicKey(key)
		pkg.Must(err, "Unable to convert public key to JSON Web Key because %s", err)
	} else {
		jwk, err = gojwk.PrivateKey(key)
		pkg.Must(err, "Unable to convert private key to JSON Web Key because %s", err)
	}

	pkgJwk := pkg.JSONWebKey{
		JSONWebKey: jose.JSONWebKey{
			KeyID:     kid,
			Use:       use,
			Algorithm: jwk.Alg,
			Key:       key,
		},
		NotBefore: nbf,
		ExpiresAt: exp,
	}

	return hydraJsonWebKeyFromPkgJSONWebKey(pkgJwk)
}

func (h *JWKHandler) ImportKeys(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		fmt.Println(cmd.UsageString())
		return
	}

	id := args[0]
	use, _ := cmd.Flags().GetString("use")

	m := h.newJwkManager(cmd)
	h.setADCredentials(cmd, m)
	set, response, err := m.GetJsonWebKeySet(id)
	pkg.Must(err, "Unable to fetch data from auth service because %s", err)
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotFound {
		fmt.Printf("Expected status code 200 or 404 but got %d while fetching data from auth service.\n", response.StatusCode)
		os.Exit(1)
	}

	if set == nil {
		set = &hydra.JsonWebKeySet{}
	}

	for _, path := range args[1:] {
		file, err := ioutil.ReadFile(path)
		pkg.Must(err, "Unable to read file %s", path)

		var hydraJWK hydra.JsonWebKey
		if key, privateErr := pkg.LoadPrivateKey(file); privateErr != nil {
			key, publicErr := pkg.LoadPublicKey(file)
			if publicErr != nil {
				fmt.Printf("Unable to read key from file %s. Decoding file to private key failed with reason \"%s\" and decoding it to public key failed with reason \"%s\".\n", path, privateErr, publicErr)
				os.Exit(1)
			}

			hydraJWK = toSDKFriendlyJSONWebKey(key, "public:"+uuid.New(), use, nil, nil, true)
		} else {
			hydraJWK = toSDKFriendlyJSONWebKey(key, "private:"+uuid.New(), use, nil, nil, false)
		}

		keyExists := false
		for idx, key := range set.Keys {
			if key.Kid == hydraJWK.Kid {
				keyExists = true
				set.Keys[idx] = hydraJWK
				break
			}
		}
		if !keyExists {
			set.Keys = append(set.Keys, hydraJWK)
		}

		fmt.Printf("Successfully loaded key from file %s\n", path)
	}

	//_, response, err = m.UpdateJsonWebKeySet(id, *set)
	//checkResponse(response, err, http.StatusOK)
	//
	//fmt.Println("Keys successfully imported!")

	signingJwk := getSigningJWKFromCmd(cmd)

	m.Configuration.AuthSvcOfflinePublicJWK = getAuthServicePublicJWK(cmd)
	m.Configuration.PrivateJWK = signingJwk
	h.putKeys(m, id, set)
}

func (h *JWKHandler) GetKeys(cmd *cobra.Command, args []string) {
	if len(args) < 1 || len(args) > 2 {
		fmt.Println(cmd.UsageString())
		return
	}

	m := h.newJwkManager(cmd)
	h.setADCredentials(cmd, m)

	if len(args) == 1 {
		keys, response, err := m.GetJsonWebKeySet(args[0])
		checkResponse(response, err, http.StatusOK)
		fmt.Printf("%s\n", formatResponse(keys))
	} else {
		key, response, err := m.GetJsonWebKey(args[1], args[0])
		checkResponse(response, err, http.StatusOK)
		fmt.Printf("%s\n", formatResponse(key))
	}
}

func (h *JWKHandler) DeleteKeys(cmd *cobra.Command, args []string) {
	if len(args) < 1 || len(args) > 2 {
		fmt.Println(cmd.UsageString())
		return
	}

	m := h.newJwkManager(cmd)
	h.setADCredentials(cmd, m)

	if len(args) == 1 {
		// delete a JSON Web Key Set
		response, err := m.DeleteJsonWebKeySet(args[0])
		checkResponse(response, err, http.StatusNoContent)
		fmt.Printf("Key set %s deleted.\n", args[0])
	} else {
		// delete a JSON Web Key pair
		if strings.HasPrefix(args[1], "public:") || strings.HasPrefix(args[1], "private:") {
			fmt.Println(cmd.Long)
			return
		}
		response, err := m.DeleteJsonWebKey("public:"+args[1], args[0])
		checkResponse(response, err, http.StatusNoContent)
		response, err = m.DeleteJsonWebKey("private:"+args[1], args[0])
		checkResponse(response, err, http.StatusNoContent)
		fmt.Printf("Key pair %s deleted.\n", args[1])
	}
}

func (h *JWKHandler) PutKeys(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println(cmd.UsageString())
		return
	}

	set := args[0]

	m := h.newJwkManager(cmd)

	h.setADCredentials(cmd, m)
	m.Configuration.AuthSvcOfflinePublicJWK = getAuthServicePublicJWK(cmd)
	m.Configuration.PrivateJWK = getSigningJWKFromCmd(cmd)
	h.putKeys(m, set, getJWKSFromCmd(cmd))
}

func (h *JWKHandler) putKeys(m *hydra.JsonWebKeyApi, set string, jwks *hydra.JsonWebKeySet) {
	endpoint := m.Configuration.BasePath
	result, response, err := m.PutJsonWebKeySet(set, *jwks)
	if err != nil {
		pkg.Must(err, "Error: "+err.Error())
	}
	fmt.Printf("Signed Keys: %s\n", result.SignedKeys)

	checkResponse(response, err, http.StatusAccepted)
	storeCookies(set, response.Cookies(), getEndpointHostname(endpoint))
	fmt.Printf("\nRun \"hydra keys commit %s --endpoint %s --commit-code <COMMIT_CODE>\" to commit JSON Web Key Set\n", set, endpoint)
}

func (h *JWKHandler) CommitKeys(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println(cmd.UsageString())
		return
	}

	set := args[0]

	var err error
	m := h.newJwkManager(cmd)
	commitCode, _ := cmd.Flags().GetString("commit-code")
	result, response, err := m.CommitJsonWebKeySet(getStoredCookies(set), commitCode)
	checkResponse(response, err, http.StatusOK)

	fmt.Printf("JSON Web Key Set location: %s\n", result.Location)
	deleteCookies(set)
}

func (h *JWKHandler) setADCredentials(cmd *cobra.Command, m *hydra.JsonWebKeyApi) {
	user, _ := cmd.Flags().GetString("user")
	pwd, _ := cmd.Flags().GetString("pwd")
	if user == "" || pwd == "" {
		err := errors.New("AD user credentials required")
		pkg.Must(err, "Error: Required flag(s) \"user\" or \"pwd\" have/has not been set")
	}
	m.Configuration.ADUsername = user
	m.Configuration.ADPassword = pwd
}