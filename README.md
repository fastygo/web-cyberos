# Website (SAML Service Provider)

This repository contains a small **Go HTTP server** that serves a public site and a **protected area** (e.g. `/dashboard`). Authentication uses **SAML 2.0** as a **Service Provider (SP)**:

1. Unauthenticated users hitting a protected route are redirected to the **SAML IdP** (`@SSO`) with a signed `AuthnRequest`.
2. After login at the IdP, a **SAML Response** is POSTed to `POST /saml/acs`.
3. The SP verifies the IdP signature, reads the user email from the assertion, and sets a **signed session cookie**.

**License:** [MIT](LICENSE)

---

## Requirements

- Go **1.22+** (see `go.mod`)
- The IdP’s **public X.509 certificate** (PEM) as `certs/idp.crt` (see below)
- Optional: Docker / Docker Compose

---

## Configuration (environment variables)

| Variable | Description | Default |
|----------|-------------|---------|
| `SITE_SESSION_KEY` or `SESSION_KEY` | HMAC secret for website session cookies | development placeholder |
| `LISTEN_ADDR` | HTTP listen address | `:80` |
| `SP_ENTITY_ID` | SAML SP Entity ID (often the site origin) | `https://sp.example.com` |
| `SP_ACS_URL` | Assertion Consumer Service URL | `https://sp.example.com/saml/acs` |
| `IDP_SSO_URL` | IdP single sign-on URL | `https://idp.example.com/sso` |
| `IDP_CERT_PATH` | Filesystem path to IdP **public** certificate (PEM) | `idp_cert.pem` |

`SITE_SESSION_KEY` is the name used in `.env.example`; if `SESSION_KEY` is set, it takes precedence.

---

## IdP certificate

The SP must trust the IdP signing key **out of band**:

1. Run the IdP (`@SSO`) once so it generates `keys/idp.crt` (or export from the Docker volume).
2. Copy the public certificate to this repo:

   ```bash
   mkdir -p certs
   cp /path/to/idp.crt certs/idp.crt
   ```

3. With Docker Compose, `./certs` is mounted at `/app/certs` and `IDP_CERT_PATH` defaults to `/app/certs/idp.crt` in `docker-compose.yml`.

---

## Build and run (local)

```bash
cd /path/to/this-repo
export SITE_SESSION_KEY="$(openssl rand -base64 32)"
# Place certs/idp.crt next to the binary or set IDP_CERT_PATH
go build -o website .
./website
```

Open `http://localhost/` (adjust `LISTEN_ADDR` if port 80 is not available).

---

## Docker Compose (this repo only)

1. Copy `.env.example` to `.env` and set `SITE_SESSION_KEY` and URL variables for your domain.

2. Add the IdP public certificate:

   ```bash
   mkdir -p certs
   cp /path/to/idp.crt certs/idp.crt
   ```

3. Run:

   ```bash
   docker compose build
   docker compose up -d
   ```

The site listens on **port 80** (see `docker-compose.yml`). Adjust host port mapping if needed.

---

## Production deployment

1. **HTTPS**: Terminate TLS at a reverse proxy; set `SP_ENTITY_ID`, `SP_ACS_URL`, and `IDP_SSO_URL` to **https** URLs.
2. **Secrets**: Use a strong `SITE_SESSION_KEY`; store it in your secrets manager or `.env` (never commit).
3. **Full stack**: Deploy the IdP (`@SSO`) and Hanko (`@OIDC`) separately; align Entity IDs and ACS URL with the IdP’s `service_providers` in that repo’s `config.yaml`.

---

## Testing

```bash
go test ./...
```

---

## Related repositories

| Repository | Role |
|------------|------|
| `@SSO` | SAML Identity Provider |
| `@OIDC` | Hanko API (credentials + JWT for IdP login UI) |

---

## Project layout (high level)

| Path | Purpose |
|------|---------|
| `main.go` | Routes, env wiring |
| `samlsp.go` | SAML AuthnRequest redirect, ACS handler, signature verification |
| `session.go` | Signed session cookie |
| `middleware.go` | Protects `/dashboard` |
| `handlers.go` | HTML handlers |
| `templates/` | Page templates |
| `certs/` | Place `idp.crt` here (not committed if you prefer) |
