package cli

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator"
	"github.com/ory/hydra/corp104/config"
	hydra "github.com/ory/hydra/corp104/sdk/go/corp104/swagger"
	"github.com/ory/hydra/pkg"
	"github.com/spf13/cobra"
	"net/http"
	"strings"
)

type ResourceHandler struct {
	Config *config.Config
}

func newResourceHandler(c *config.Config) *ResourceHandler {
	return &ResourceHandler{
		Config: c,
	}
}

func (h *ResourceHandler) newResourceManager(cmd *cobra.Command) *hydra.OAuth2Api {
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

func (h *ResourceHandler) PutResource(cmd *cobra.Command, args []string) {
	var err error
	m := h.newResourceManager(cmd)

	endpoint, _ := cmd.Flags().GetString("endpoint")
	cc, signingJwk := h.getResourceFromPutCmd(cmd)

	// authentication
	user, _ := cmd.Flags().GetString("user")
	pwd, _ := cmd.Flags().GetString("pwd")
	if user == "" || pwd == "" {
		err := errors.New("AD user credentials required")
		pkg.Must(err, "Error: Required flag(s) \"user\" or \"pwd\" have/has not been set")
	}
	m.Configuration.ADUsername = user
	m.Configuration.ADPassword = pwd
	m.Configuration.AuthSvcOfflinePublicJwk = getAuthServicePublicJWK(cmd)
	m.Configuration.PrivateJWK = signingJwk
	result, response, err := m.PutOAuth2Resource(cc)
	if err != nil {
		pkg.Must(err, "Error: "+err.Error())
	}
	fmt.Printf("OAuth 2.0 Signed Resource URN: %s\n", result.SignedResourceUrn)

	checkResponse(response, err, http.StatusAccepted)
	storeCookies(h.getCookieFileName(cc.GetUrn()), response.Cookies(), getEndpointHostname(h.Config.GetClusterURLWithoutTailingSlashOrFail(cmd)))
	fmt.Printf("\nRun \"hydra resources commit --endpoint %s --urn %s --commit-code <COMMIT_CODE>\" to complete resource registration\n", endpoint, cc.GetUrn())
}

func (h *ResourceHandler) CommitResource(cmd *cobra.Command, args []string) {
	var err error
	m := h.newResourceManager(cmd)
	urn, _ := cmd.Flags().GetString("urn")
	commitCode, _ := cmd.Flags().GetString("commit-code")
	cookieFileName := h.getCookieFileName(urn)
	result, response, err := m.CommitOAuth2Resource(getStoredCookies(cookieFileName), commitCode)
	checkResponse(response, err, http.StatusOK)

	fmt.Printf("OAuth 2.0 resource location: %s\n", result.Location)
	deleteCookies(cookieFileName)
}

func (h *ResourceHandler) DeleteResource(cmd *cobra.Command, args []string) {
	m := h.newResourceManager(cmd)

	if len(args) == 0 {
		fmt.Print(cmd.UsageString())
		return
	}

	response, err := m.DeleteOAuth2Resource(args[0])
	checkResponse(response, err, http.StatusNoContent)
	fmt.Println("OAuth2 resource deleted.")
}

func (h *ResourceHandler) GetResource(cmd *cobra.Command, args []string) {
	m := h.newResourceManager(cmd)

	if len(args) == 0 {
		fmt.Print(cmd.UsageString())
		return
	}

	resource, response, err := m.GetOAuth2Resource(args[0])
	checkResponse(response, err, http.StatusOK)
	fmt.Printf("%s\n", formatResponse(resource))
}

func (h *ResourceHandler) getResourceFromPutCmd(cmd *cobra.Command) (hydra.OAuth2Resource, *hydra.JsonWebKey) {
	resourceMetadata, _ := cmd.Flags().GetString("resource-metadata")
	signingJwkJSON, _ := cmd.Flags().GetString("signing-jwk")

	var cc hydra.OAuth2Resource

	err := json.Unmarshal([]byte(resourceMetadata), &cc)
	if err != nil {
		pkg.Must(err, "Error: "+err.Error())
	}

	err = validator.New().Struct(&cc)
	if err != nil {
		pkg.Must(err, "Error: "+err.Error())
	}

	signingJwk := hydra.LoadJsonWebKey([]byte(signingJwkJSON))

	return cc, signingJwk
}

func (h *ResourceHandler) getCookieFileName(urn string) string {
	return strings.Replace(urn, ":", "#", -1)
}
