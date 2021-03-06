package pkg

import (
	"encoding/json"
	"github.com/go-resty/resty"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const sender = "jobbank@104.com.tw"

func SendTextMail(recipient string, subject string, body string) (bool, error) {
	return sendMail(recipient, subject, "text", body)
}

func SendHTMLMail(recipient string, subject string, body string) (bool, error) {
	return sendMail(recipient, subject, "html", body)
}

func sendMail(recipient string, subject string, bodyType string, body string) (bool, error) {
	emailServiceUrl := viper.GetString("EMAIL_SERVICE_URL")
	if emailServiceUrl == "" {
		return false, errors.New("No email service url")
	}

	payload := `{"sender":"` + sender + `","recipient":"` + recipient + `","subject":"` + subject + `","body": {"` + bodyType + `":"` + body + `"}}`

	resp, err := resty.R().SetHeader("Content-Type", "application/json").SetBody(payload).Post(emailServiceUrl + "/sendEmail")
	if err != nil {
		return false, err
	}

	responseMap := make(map[string]interface{})
	if err := json.Unmarshal(resp.Body(), &responseMap); err != nil {
		return false, err
	}

	return true, nil
}
