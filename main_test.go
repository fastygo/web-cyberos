package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSiteSessionRoundtrip(t *testing.T) {
	key := "test-site-session-key-12345678"

	rr := httptest.NewRecorder()
	createSiteSession(rr, "admin@test.local", key)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies set")
	}

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	sess := getSiteSession(req, key)
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.Email != "admin@test.local" {
		t.Fatalf("email = %q", sess.Email)
	}

	sess2 := getSiteSession(req, "wrong-key")
	if sess2 != nil {
		t.Fatal("session should be nil with wrong key")
	}
}

func TestAuthMiddlewareRedirects(t *testing.T) {
	sp := &SAMLSPConfig{
		EntityID:  "https://test.local",
		IDPSSOURL: "https://idp.test.local/sso",
		ACSUrl:    "https://test.local/saml/acs",
	}
	sessionKey := "test-key-for-middleware-check!"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("protected"))
	})

	handler := authMiddleware(sp, sessionKey, inner)

	// No session -> should redirect
	req := httptest.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatal("no Location header")
	}
	if len(location) < 30 {
		t.Fatalf("redirect URL too short: %s", location)
	}
}

func TestAuthnRequestURL(t *testing.T) {
	sp := &SAMLSPConfig{
		EntityID:  "https://sp.test.local",
		IDPSSOURL: "https://idp.test.local/sso",
		ACSUrl:    "https://sp.test.local/saml/acs",
	}

	url, err := sp.BuildAuthnRequestRedirectURL("/dashboard")
	if err != nil {
		t.Fatalf("build URL: %v", err)
	}
	if url == "" {
		t.Fatal("empty URL")
	}
	if len(url) < 50 {
		t.Fatalf("URL too short: %s", url)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
