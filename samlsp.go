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
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
)

var crandReader = crand.Reader

type SAMLSPConfig struct {
	EntityID    string
	IDPSSOURL   string
	IDPCertPath string
	ACSUrl      string
	idpCert     *x509.Certificate
}

func (sp *SAMLSPConfig) LogoutURL(returnTo string) string {
	base := strings.TrimRight(sp.IDPSSOURL, "/")
	if strings.HasSuffix(base, "/sso") {
		base = strings.TrimSuffix(base, "/sso")
	}
	logoutURL := base + "/logout"
	if returnTo == "" {
		return logoutURL
	}
	return logoutURL + "?return_to=" + url.QueryEscape(returnTo)
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
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return fmt.Errorf("parse XML: %w", err)
	}

	assertion := doc.FindElement("//Assertion")
	if assertion == nil {
		return fmt.Errorf("no Assertion found")
	}

	signature := assertion.FindElement("./Signature")
	if signature == nil {
		return fmt.Errorf("no Signature found in Assertion")
	}

	signedInfo := signature.FindElement("./SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("no SignedInfo found")
	}

	signatureValue := signature.FindElement("./SignatureValue")
	if signatureValue == nil || strings.TrimSpace(signatureValue.Text()) == "" {
		return fmt.Errorf("no SignatureValue found")
	}

	digestValue := signature.FindElement("./SignedInfo/Reference/DigestValue")
	if digestValue == nil || strings.TrimSpace(digestValue.Text()) == "" {
		return fmt.Errorf("no DigestValue found")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(trimWhitespace(signatureValue.Text()))
	if err != nil {
		return fmt.Errorf("decode SignatureValue: %w", err)
	}

	assertionCopy := assertion.Copy()
	if sigCopy := assertionCopy.FindElement("./Signature"); sigCopy != nil {
		assertionCopy.RemoveChild(sigCopy)
	}
	assertionC14N, err := canonicalize(assertionCopy)
	if err != nil {
		return fmt.Errorf("canonicalize Assertion: %w", err)
	}
	assertionDigest := sha256.Sum256([]byte(assertionC14N))
	expectedDigest := base64.StdEncoding.EncodeToString(assertionDigest[:])
	if trimWhitespace(digestValue.Text()) != expectedDigest {
		return fmt.Errorf("digest mismatch")
	}

	signedInfoC14N, err := canonicalize(signedInfo)
	if err != nil {
		return fmt.Errorf("canonicalize SignedInfo: %w", err)
	}
	hash := sha256.Sum256([]byte(signedInfoC14N))

	pubKey, ok := sp.idpCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("IdP certificate does not contain RSA key")
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return fmt.Errorf("RSA verification failed: %w", err)
	}

	return nil
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

func canonicalize(el *etree.Element) (string, error) {
	var buf strings.Builder
	if err := c14nElement(&buf, el, nil); err != nil {
		return "", err
	}
	return buf.String(), nil
}

type nsEntry struct {
	Prefix string
	URI    string
}

func c14nElement(buf *strings.Builder, el *etree.Element, parentNS []nsEntry) error {
	visibleNS := collectVisibleNS(el, parentNS)

	buf.WriteByte('<')
	if el.Space != "" {
		buf.WriteString(el.Space)
		buf.WriteByte(':')
	}
	buf.WriteString(el.Tag)

	sort.Slice(visibleNS, func(i, j int) bool {
		return visibleNS[i].Prefix < visibleNS[j].Prefix
	})
	for _, ns := range visibleNS {
		buf.WriteByte(' ')
		if ns.Prefix == "" {
			buf.WriteString("xmlns=\"")
		} else {
			buf.WriteString("xmlns:")
			buf.WriteString(ns.Prefix)
			buf.WriteString("=\"")
		}
		buf.WriteString(ns.URI)
		buf.WriteByte('"')
	}

	attrs := make([]etree.Attr, len(el.Attr))
	copy(attrs, el.Attr)
	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].Space == "xmlns" || attrs[i].Key == "xmlns" {
			return false
		}
		if attrs[j].Space == "xmlns" || attrs[j].Key == "xmlns" {
			return false
		}
		if attrs[i].Space != attrs[j].Space {
			return attrs[i].Space < attrs[j].Space
		}
		return attrs[i].Key < attrs[j].Key
	})
	for _, attr := range attrs {
		if attr.Space == "xmlns" || attr.Key == "xmlns" {
			continue
		}
		buf.WriteByte(' ')
		if attr.Space != "" {
			buf.WriteString(attr.Space)
			buf.WriteByte(':')
		}
		buf.WriteString(attr.Key)
		buf.WriteString("=\"")
		buf.WriteString(escapeAttrValue(attr.Value))
		buf.WriteByte('"')
	}

	buf.WriteByte('>')

	mergedNS := mergeNS(parentNS, visibleNS)
	for _, tok := range el.Child {
		switch t := tok.(type) {
		case *etree.Element:
			if err := c14nElement(buf, t, mergedNS); err != nil {
				return err
			}
		case *etree.CharData:
			buf.WriteString(escapeText(t.Data))
		}
	}

	buf.WriteString("</")
	if el.Space != "" {
		buf.WriteString(el.Space)
		buf.WriteByte(':')
	}
	buf.WriteString(el.Tag)
	buf.WriteByte('>')

	return nil
}

func collectVisibleNS(el *etree.Element, parentNS []nsEntry) []nsEntry {
	needed := make(map[string]string)

	if el.Space != "" {
		if uri := findNSURI(el, el.Space); uri != "" {
			needed[el.Space] = uri
		}
	} else {
		if uri := findDefaultNSURI(el); uri != "" {
			needed[""] = uri
		}
	}

	for _, attr := range el.Attr {
		if attr.Space == "xmlns" || attr.Key == "xmlns" {
			continue
		}
		if attr.Space != "" {
			if uri := findNSURI(el, attr.Space); uri != "" {
				needed[attr.Space] = uri
			}
		}
	}

	var result []nsEntry
	for prefix, uri := range needed {
		alreadyDeclared := false
		for _, pns := range parentNS {
			if pns.Prefix == prefix && pns.URI == uri {
				alreadyDeclared = true
				break
			}
		}
		if !alreadyDeclared {
			result = append(result, nsEntry{Prefix: prefix, URI: uri})
		}
	}

	return result
}

func findNSURI(el *etree.Element, prefix string) string {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, attr := range cur.Attr {
			if attr.Space == "xmlns" && attr.Key == prefix {
				return attr.Value
			}
		}
	}
	return ""
}

func findDefaultNSURI(el *etree.Element) string {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, attr := range cur.Attr {
			if attr.Key == "xmlns" && attr.Space == "" {
				return attr.Value
			}
		}
	}
	return ""
}

func mergeNS(parent []nsEntry, added []nsEntry) []nsEntry {
	merged := make([]nsEntry, len(parent))
	copy(merged, parent)
	for _, a := range added {
		found := false
		for i, m := range merged {
			if m.Prefix == a.Prefix {
				merged[i].URI = a.URI
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, a)
		}
	}
	return merged
}

func escapeAttrValue(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "\t", "&#x9;")
	s = strings.ReplaceAll(s, "\n", "&#xA;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}

func escapeText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}

// XML structures for parsing SAML Response
type samlResponse struct {
	XMLName   xml.Name      `xml:"Response"`
	Status    samlStatus    `xml:"Status"`
	Assertion samlAssertion `xml:"Assertion"`
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
	Name   string          `xml:"Name,attr"`
	Values []samlAttrValue `xml:"AttributeValue"`
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
