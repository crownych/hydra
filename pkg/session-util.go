package pkg

import (
	"github.com/goincremental/negroni-sessions"
	"net/http"
)

func SaveSessionValue(r *http.Request, key string, value string) {
	session := sessions.GetSession(r)
	session.Set(key, value)
}

func GetSessionValue(r *http.Request, key string) string {
	session := sessions.GetSession(r)
	data := session.Get(key)
	if data == nil {
		return ""
	}
	return data.(string)
}

func RemoveSessionValue(r *http.Request, key string) {
	session := sessions.GetSession(r)
	session.Delete(key)
}
