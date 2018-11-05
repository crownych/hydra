package client

import (
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

func validateADUser(endpoint, id, pwd string) error {
	// TODO: connect to AD server and validate credentials, return error if validation fail
	return nil
}