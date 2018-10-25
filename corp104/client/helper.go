package client

import (
	"encoding/base64"
	"encoding/json"
	"github.com/lestrrat-go/jwx/jws"
	"strings"
)

func contains(sl []interface{}, v interface{}) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}

func containsStrings(sl []string, s2... string) bool {
	founds := 0
	for _, vv := range sl {
		for _, v := range s2 {
			if vv == v {
				founds++
				break
			}
		}
	}
	if founds == len(s2) {
		return true
	}
	return false
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
