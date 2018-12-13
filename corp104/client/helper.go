package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty"
	"github.com/goincremental/negroni-sessions"
	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/hydra/pkg"
	"log"
	"net/http"
	"strings"
)

func hasStrings(s1 []string, s2 ...string) bool {
	if len(s2) == 0 {
		return false
	}
	for _, needle := range s2 {
		if !stringslice.Has(s1, needle) {
			return false
		}
	}
	return true
}

func validateADUser(adLoginURL, id, pwd string) error {
	if adLoginURL == "" {
		return errors.New("no AD login url")
	}
	log.Println("AD_LOGIN_URL:", adLoginURL)
	resp, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(fmt.Sprintf("id=%s&pwd=%s&nat=1", id, pwd)).
		Post(adLoginURL)
	if err != nil {
		return err
	}
	body := string(resp.Body())
	if resp.StatusCode() != http.StatusOK || !strings.HasPrefix(body, "@") {
		return pkg.ErrUnauthorized
	}
	return nil
}

func saveSessionValue(r *http.Request, key string, value string) {
	session := sessions.GetSession(r)
	session.Set(key, value)
}

func getSessionValue(r *http.Request, key string) string {
	session := sessions.GetSession(r)
	data := session.Get(key)
	if data == nil {
		return ""
	}
	return data.(string)
}

func removeSessionValue(r *http.Request, key string) {
	session := sessions.GetSession(r)
	session.Delete(key)
}

func convertJsonBodyToMap(r *http.Request) map[string]string {
	bodyMap := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&bodyMap)
	return bodyMap
}
