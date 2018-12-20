package pkg

import (
	"fmt"
	"github.com/go-resty/resty"
	"github.com/spf13/viper"
	"net/http"
	"strings"
)

type ADUserCredentials struct {
	User string `json:"ad_user,omitempty"`
	Pwd  string `json:"ad_pwd,omitempty"`
}

func ValidateADUser(credentials *ADUserCredentials) error {
	if credentials == nil {
		return NewBadRequestError("AD user credentials required.")
	}

	user := credentials.User
	pwd := credentials.Pwd
	if user == "" || pwd == "" {
		return NewBadRequestError("invalid signed user credentials")
	}

	adLoginURL := viper.GetString("AD_LOGIN_URL")
	if adLoginURL == "" {
		return NewError(http.StatusInternalServerError, "no AD login url")
	}

	resp, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(fmt.Sprintf("id=%s&pwd=%s&nat=1", user, pwd)).
		Post(adLoginURL)
	if err != nil {
		return err
	}
	body := string(resp.Body())
	if resp.StatusCode() != http.StatusOK || !strings.HasPrefix(body, "@") {
		return ErrUnauthorized
	}
	return nil
}
