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
