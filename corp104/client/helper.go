package client

import (
	"encoding/base64"
	"encoding/json"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/ory/go-convenience/stringslice"
	"strings"
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

func getHeadersFromJws(compactJws string) (map[string]interface{}, error) {
	compactHeader, _, _, err := jws.SplitCompact(strings.NewReader(compactJws))
	if err != nil {
		return nil, err
	}
	headerJson, err := base64.RawURLEncoding.DecodeString(string(compactHeader))
	if err != nil {
		return nil, err
	}
	headers := make(map[string]interface{})
	err = json.Unmarshal(headerJson, &headers)
	if err != nil {
		return nil, err
	}
	return headers, nil
}
