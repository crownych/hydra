package client

import (
	"errors"
	"github.com/ory/go-convenience/stringslice"
)

func hasStrings(s1 []string, s2... string) bool {
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
	// TODO: connect to AD server and validate credentials, return error if validation fail

	return nil
}
