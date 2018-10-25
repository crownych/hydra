package cmd

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/hydra/pkg"
	"github.com/ory/hydra/rand/sequence"
	"github.com/spf13/cobra"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	goauth2 "golang.org/x/oauth2"
)

// tokenUserCmd represents the token command
var urlImplicitCmd = &cobra.Command{
	Use:   "implicit",
	Short: "Initiates OIDC implicit requests",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		scopes, _ := cmd.Flags().GetStringSlice("scope")
		prompt, _ := cmd.Flags().GetStringSlice("prompt")
		maxAge, _ := cmd.Flags().GetInt("max-age")
		redirectUrl, _ := cmd.Flags().GetString("redirect")
		authURL, _ := cmd.Flags().GetString("auth-url")

		clientID, _ := cmd.Flags().GetString("client-id")
		if clientID == "" {
			fmt.Print(cmd.UsageString())
			fmt.Println("Please provide a Client ID using flags --client-id, or environment variables OAUTH2_CLIENT_ID.")
			return
		}
		signingJwk, _ := cmd.Flags().GetString("signing-jwk")

		if !stringslice.Has(scopes, "openid") {
			scopes = append(scopes, "openid")
		}

		config := goauth2.Config{
			ClientID:     clientID,
			Endpoint:     goauth2.Endpoint{
				TokenURL: "",
				AuthURL:  authURL,
			},
			RedirectURL:  redirectUrl,
			Scopes:       scopes,
		}

		state, err := sequence.RuneSequence(24, sequence.AlphaLower)
		pkg.Must(err, "Could not generate random state: %s", err)

		nonce, err := sequence.RuneSequence(24, sequence.AlphaLower)
		pkg.Must(err, "Could not generate random state: %s", err)

		authCodeURL := config.AuthCodeURL(string(state)) + "&nonce=" + string(nonce) + "&prompt=" + strings.Join(prompt, "+") + "&max_age=" + strconv.Itoa(maxAge)
		authCodeURL = strings.Replace(authCodeURL, "response_type=code", "response_type=id_token", 1)

		u, err := url.Parse(c.GetClusterURLWithoutTailingSlashOrFail(cmd))
		if err != nil {
			panic(err.Error())
		}

		t := jwt.New()
		t.Set(jwt.IssuerKey, clientID)
		t.Set(jwt.AudienceKey, u.String())
		t.Set(jwt.IssuedAtKey, time.Now())
		t.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(30) * time.Minute))
		t.Set("client_id", clientID)
		t.Set("redirect_uri", redirectUrl)
		t.Set("scope", "openid")
		t.Set("state", string(state))
		t.Set("nonce", string(nonce))
		t.Set("max_age", strconv.Itoa(maxAge))
		t.Set("response_type", "id_token")
		t.Set("prompt", strings.Join(prompt, "+"))
		buf, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			panic(err.Error())
		}

		kid, privateKey := extractECDSAPrivateKey([]byte(signingJwk))
		header := buildHeader(kid)
		signedBuf, err := jws.Sign(buf, jwa.ES256, privateKey, jws.WithHeaders(&header))
		if err != nil {
			panic(err.Error())
		}
		authCodeURL = authCodeURL + "&request=" + string(signedBuf)
		fmt.Printf("Copy the following url to browser: \n%s\n", authCodeURL)
	},
}

func init() {
	urlCmd.AddCommand(urlImplicitCmd)
	urlImplicitCmd.Flags().StringSlice("scope", []string{"openid"}, "Request OAuth2 scope")
	urlImplicitCmd.Flags().StringSlice("prompt", []string{}, "Set the OpenID Connect prompt parameter")
	urlImplicitCmd.Flags().Int("max-age", 0, "Set the OpenID Connect max_age parameter")

	urlImplicitCmd.Flags().String("client-id", os.Getenv("OAUTH2_CLIENT_ID"), "Use the provided OAuth 2.0 Client ID, defaults to environment variable OAUTH2_CLIENT_ID")
	urlImplicitCmd.Flags().String("signing-jwk", "", "Client's JSON Web Key document representing the client's private key used to sign the software statement")

	urlImplicitCmd.Flags().String("redirect", "", "Force a redirect url")
	urlImplicitCmd.Flags().String("auth-url", "", "Usually it is enough to specify the `endpoint` flag, but if you want to force the authorization url, use this flag")
	urlImplicitCmd.PersistentFlags().String("endpoint", os.Getenv("HYDRA_URL"), "Set the URL where ORY Hydra is hosted, defaults to environment variable HYDRA_URL")
}

func extractECDSAPrivateKey(jwks []byte) (string, *ecdsa.PrivateKey) {
	j, err := jwk.Parse(jwks)
	if err != nil {
		panic(err.Error())
	}

	for _, keys := range j.Keys {
		key, err := keys.Materialize()
		if err != nil {
			panic(err.Error())
		}
		if v, ok := key.(*ecdsa.PrivateKey); ok {
			return keys.KeyID(), v
		}
	}
	return "", nil
}

func buildHeader(kid string) (jws.StandardHeaders) {
	var header jws.StandardHeaders
	header.Set(`typ`, "JWT")
	header.Set("kid", strings.Replace(kid, "private", "public", 1))
	return header
}
