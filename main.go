package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	sessionKey := envSessionKey()
	listenAddr := envOrDefault("LISTEN_ADDR", ":80")

	sp := &SAMLSPConfig{
		EntityID:    envOrDefault("SP_ENTITY_ID", "https://sp.example.com"),
		IDPSSOURL:   envOrDefault("IDP_SSO_URL", "https://idp.example.com/sso"),
		IDPCertPath: envOrDefault("IDP_CERT_PATH", "idp_cert.pem"),
		ACSUrl:      envOrDefault("SP_ACS_URL", "https://sp.example.com/saml/acs"),
	}

	if err := sp.LoadCert(); err != nil {
		log.Fatalf("Failed to load IdP certificate: %v", err)
	}
	log.Printf("IdP certificate loaded from %s", sp.IDPCertPath)

	handlers := NewSiteHandlers()

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("GET /", handlers.handleHome)
	mux.HandleFunc("GET /logout", handlers.handleLogout)

	// SAML ACS endpoint (receives POST from IdP)
	mux.HandleFunc("POST /saml/acs", sp.HandleACS(sessionKey))

	// Protected routes (require SSO session)
	protected := http.NewServeMux()
	protected.HandleFunc("GET /dashboard", handlers.handleDashboard)
	mux.Handle("GET /dashboard", authMiddleware(sp, sessionKey, protected))

	log.Printf("Website starting on %s", listenAddr)
	log.Printf("SP Entity ID: %s", sp.EntityID)
	log.Printf("IdP SSO URL: %s", sp.IDPSSOURL)

	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func envOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// envSessionKey reads SESSION_KEY, or SITE_SESSION_KEY (used in .env.example), or default.
func envSessionKey() string {
	if v := os.Getenv("SESSION_KEY"); v != "" {
		return v
	}
	if v := os.Getenv("SITE_SESSION_KEY"); v != "" {
		return v
	}
	return "CHANGE-ME-TO-A-RANDOM-32-BYTE-KEY"
}
