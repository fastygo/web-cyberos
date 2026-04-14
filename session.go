package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	siteSessionCookie = "cyberos_session"
	siteSessionTTL    = 8 * time.Hour
)

type SiteSession struct {
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
}

func createSiteSession(w http.ResponseWriter, email, sessionKey string) {
	sess := SiteSession{
		Email:     email,
		ExpiresAt: time.Now().Add(siteSessionTTL).Unix(),
	}
	val := siteSignedEncode(sess, sessionKey)
	http.SetCookie(w, &http.Cookie{
		Name:     siteSessionCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(siteSessionTTL.Seconds()),
	})
}

func getSiteSession(r *http.Request, sessionKey string) *SiteSession {
	cookie, err := r.Cookie(siteSessionCookie)
	if err != nil {
		return nil
	}
	var sess SiteSession
	if err := siteSignedDecode(cookie.Value, sessionKey, &sess); err != nil {
		return nil
	}
	if time.Now().Unix() > sess.ExpiresAt {
		return nil
	}
	return &sess
}

func clearSiteSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     siteSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func siteSignedEncode(data any, key string) string {
	payload, _ := json.Marshal(data)
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := siteComputeHMAC(b64, key)
	return b64 + "." + mac
}

func siteSignedDecode(value, key string, dst any) error {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format")
	}
	expected := siteComputeHMAC(parts[0], key)
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return fmt.Errorf("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, dst)
}

func siteComputeHMAC(data, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
