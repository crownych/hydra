package config

import (
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
)

type WebSession struct {
	Store sessions.Store
}

func NewWebSession(c *Config) (session *WebSession) {
	store := cookiestore.New(c.GetCookieSecret())
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   0,
		Secure:   false,
		HTTPOnly: true,
	})
	return &WebSession{
		Store: store,
	}
}
