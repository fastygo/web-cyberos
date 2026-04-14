package main

import (
	"context"
	"net/http"
)

type contextKey string

const userEmailKey contextKey = "user_email"

func authMiddleware(sp *SAMLSPConfig, sessionKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := getSiteSession(r, sessionKey)
		if sess == nil {
			redirectURL, err := sp.BuildAuthnRequestRedirectURL(r.URL.Path)
			if err != nil {
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), userEmailKey, sess.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getUserEmail(r *http.Request) string {
	email, _ := r.Context().Value(userEmailKey).(string)
	return email
}
