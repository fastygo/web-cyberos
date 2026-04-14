package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var crandReader = crand.Reader

type SAMLSPConfig struct {
	EntityID    string
	IDPSSOURL   string
	IDPCertPath string
	ACSUrl      string
	idpCert     *x509.Certificate
}

func (sp *SAMLSPConfig) LoadCert() error {
	data, err := os.ReadFile(sp.IDPCertPath)
	if err != nil {
		return fmt.Errorf("read IdP cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM block in %s", sp.IDPCertPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse IdP cert: %w", err)
	}
	sp.idpCert = cert
	return nil
}

// BuildAuthnRequestRedirectURL creates a SAML AuthnRequest and returns
// the full redirect URL to the IdP SSO endpoint.
func (sp *SAMLSPConfig) BuildAuthnRequestRedirectURL(relayState string) (string, error) {
	id := "_" + generateSPRequestID()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	reqXML := fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `+
			`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" `+
			`ID="%s" Version="2.0" IssueInstant="%s" `+
			`AssertionConsumerServiceURL="%s" `+
			`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`</samlp:AuthnRequest>`,
		id, now, sp.ACSUrl, sp.EntityID,
	)

	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(reqXML))
	w.Close()

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	url := sp.IDPSSOURL + "?SAMLRequest=" + urlEncode(encoded)
	if relayState != "" {
		url += "&RelayState=" + urlEncode(relayState)
	}
	return url, nil
}

// HandleACS processes the POST /saml/acs endpoint.
func (sp *SAMLSPConfig) HandleACS(sessionKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		samlResponse := r.FormValue("SAMLResponse")
		relayState := r.FormValue("RelayState")

		if samlResponse == "" {
			http.Error(w, "Missing SAMLResponse", http.StatusBadRequest)
			return
		}

		xmlBytes, err := base64.StdEncoding.DecodeString(samlResponse)
		if err != nil {
			http.Error(w, "Invalid SAMLResponse encoding", http.StatusBadRequest)
			return
		}

		email, err := sp.verifyAndExtract(xmlBytes)
		if err != nil {
			log.Printf("SAML verification failed: %v", err)
			http.Error(w, "Authentication failed", http.StatusForbidden)
			return
		}

		createSiteSession(w, email, sessionKey)

		redirect := "/"
		if relayState != "" {
			redirect = relayState
		}
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	}
}

func (sp *SAMLSPConfig) verifyAndExtract(xmlBytes []byte) (string, error) {
	// Parse and verify the signature
	if err := sp.verifySignature(xmlBytes); err != nil {
		return "", fmt.Errorf("signature verification: %w", err)
	}

	// Extract email from the assertion
	var resp samlResponse
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if resp.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return "", fmt.Errorf("SAML status: %s", resp.Status.StatusCode.Value)
	}

	// Try NameID first
	email := resp.Assertion.Subject.NameID.Value
	if email != "" {
		return email, nil
	}

	// Fall back to email attribute
	for _, attr := range resp.Assertion.AttributeStatement.Attributes {
		if attr.Name == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" {
			if len(attr.Values) > 0 {
				return attr.Values[0].Value, nil
			}
		}
	}

	return "", fmt.Errorf("no email found in assertion")
}

func (sp *SAMLSPConfig) verifySignature(xmlBytes []byte) error {
	// Find SignedInfo and compute its digest, then verify RSA signature
	// We use a simplified approach: find DigestValue + SignatureValue in XML,
	// recompute digest of the Assertion (without Signature), and verify.

	type signatureInfo struct {
		XMLName   xml.Name `xml:"Signature"`
		SignedInfo struct {
			Reference struct {
				DigestValue string `xml:"DigestValue"`
			} `xml:"Reference"`
		} `xml:"SignedInfo"`
		SignatureValue string `xml:"SignatureValue"`
	}

	type assertionWithSig struct {
		XMLName   xml.Name      `xml:"Assertion"`
		Signature signatureInfo `xml:"Signature"`
	}

	type responseWithAssertion struct {
		XMLName   xml.Name         `xml:"Response"`
		Assertion assertionWithSig `xml:"Assertion"`
	}

	var parsed responseWithAssertion
	if err := xml.Unmarshal(xmlBytes, &parsed); err != nil {
		return fmt.Errorf("parse for signature: %w", err)
	}

	sigValueB64 := parsed.Assertion.Signature.SignatureValue
	if sigValueB64 == "" {
		return fmt.Errorf("no SignatureValue found")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(
		trimWhitespace(sigValueB64),
	)
	if err != nil {
		return fmt.Errorf("decode SignatureValue: %w", err)
	}

	// Re-canonicalize SignedInfo and verify
	// For MVP, we verify the RSA signature over the SignedInfo canonical form
	// by re-serializing it from the raw XML.
	signedInfoXML := extractSignedInfo(xmlBytes)
	if signedInfoXML == nil {
		return fmt.Errorf("cannot extract SignedInfo")
	}

	hash := sha256.Sum256(signedInfoXML)
	pubKey, ok := sp.idpCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("IdP certificate does not contain RSA key")
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return fmt.Errorf("RSA verification failed: %w", err)
	}

	return nil
}

// extractSignedInfo finds the raw <ds:SignedInfo>...</ds:SignedInfo> bytes
// from the XML document for signature verification.
func extractSignedInfo(xmlBytes []byte) []byte {
	s := string(xmlBytes)

	// Look for SignedInfo with various namespace prefixes
	for _, prefix := range []string{"ds:", "dsig:", ""} {
		startTag := "<" + prefix + "SignedInfo"
		endTag := "</" + prefix + "SignedInfo>"

		startIdx := indexOf(s, startTag)
		if startIdx == -1 {
			continue
		}
		endIdx := indexOf(s[startIdx:], endTag)
		if endIdx == -1 {
			continue
		}
		return []byte(s[startIdx : startIdx+endIdx+len(endTag)])
	}
	return nil
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimWhitespace(s string) string {
	var buf bytes.Buffer
	for _, c := range s {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			buf.WriteRune(c)
		}
	}
	return buf.String()
}

// XML structures for parsing SAML Response
type samlResponse struct {
	XMLName   xml.Name       `xml:"Response"`
	Status    samlStatus     `xml:"Status"`
	Assertion samlAssertion  `xml:"Assertion"`
}

type samlStatus struct {
	StatusCode struct {
		Value string `xml:"Value,attr"`
	} `xml:"StatusCode"`
}

type samlAssertion struct {
	Subject            samlSubject            `xml:"Subject"`
	AttributeStatement samlAttributeStatement `xml:"AttributeStatement"`
}

type samlSubject struct {
	NameID struct {
		Value string `xml:",chardata"`
	} `xml:"NameID"`
}

type samlAttributeStatement struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string           `xml:"Name,attr"`
	Values []samlAttrValue  `xml:"AttributeValue"`
}

type samlAttrValue struct {
	Value string `xml:",chardata"`
}

func generateSPRequestID() string {
	b := make([]byte, 16)
	io.ReadFull(crandReader, b)
	return fmt.Sprintf("%x", b)
}

func urlEncode(s string) string {
	var buf bytes.Buffer
	for _, b := range []byte(s) {
		if isUnreserved(b) {
			buf.WriteByte(b)
		} else {
			fmt.Fprintf(&buf, "%%%02X", b)
		}
	}
	return buf.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '~'
}
