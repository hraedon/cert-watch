# cert-watch

Track expirations of TLS certificates from scanned hosts and uploaded files, with a web dashboard, REST API, and alerting.

Supports PEM, DER, CER, CRT, PKCS#12 (`.pfx`/`.p12`), PKCS#7 (`.p7b`/`.p7c`), and multi-cert chain bundles.

## Features

- **Host scanning** — TLS handshake to extract leaf + chain certificates from any host
- **Certificate upload** — PEM, DER, PKCS#12, PKCS#7 with automatic chain extraction
- **Web dashboard** — color-coded expiry status (red/yellow/green), chain visualization, host management
- **REST API** — JSON endpoints for certificates, hosts, and alerts with pagination
- **Alerting** — email (SMTP) and webhook notifications with configurable per-host thresholds
- **Scheduled scans** — daily automatic re-scan of all tracked hosts
- **Certificate Transparency** — lookup certificates via crt.sh
- **Bulk import** — CSV upload for adding many hosts at once
- **Prometheus metrics** — `/metrics` endpoint for monitoring integration
- **Renewal tracking** — links renewed certificates to their predecessors
- **Authentication** — LDAP/AD and OAuth/OIDC (Microsoft Entra, Google, etc.)

## Stack

- Python 3.12+ / FastAPI / Jinja2 / `cryptography`
- SQLite (single-file, WAL mode)
- Optional: `ldap3` (LDAP auth), `authlib` (OAuth auth)
- Docker image published to GHCR (multi-arch: amd64 + arm64)
- Deploy: Kubernetes (Argo CD GitOps), Docker Compose, Linux + systemd, or Windows + IIS

## Quick start (local)

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/python -m cert_watch        # serves http://localhost:8000
.venv/bin/pytest -q                    # run tests
```

## Docker

```bash
docker build -t cert-watch:dev .
docker run --rm -p 8000:8000 -v cert-watch-data:/var/lib/cert-watch cert-watch:dev
```

Or with compose:

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

## Kubernetes (Argo CD)

The cluster pulls from this repo; CI bumps the image tag on `main`. One-time bootstrap:

```bash
kubectl apply -f deploy/argocd/application.yaml
```

After that, every merge to `main` builds + pushes a new image and commits a tag bump to `deploy/k8s/kustomization.yaml`; Argo CD syncs within a minute.

Direct apply (no Argo CD):

```bash
kubectl apply -k deploy/k8s
```

## Linux / systemd

```bash
sudo ./scripts/install-linux.sh   # installs to /opt/cert-watch, enables cert-watch.service
```

See `deploy/systemd/cert-watch.service`.

## Windows / IIS

cert-watch runs on Windows with no code changes — IIS fronts the uvicorn
process, either via the **HttpPlatformHandler** module (recommended; IIS
supervises the process, no third-party service) or as a **reverse proxy** to a
Windows service. Bootstrap with:

```powershell
.\scripts\install-windows.ps1   # venv + data dir + persistent signing keys
```

Then configure the IIS site — see [`deploy/iis/README.md`](deploy/iis/README.md).
Set `CERT_WATCH_TRUST_PROXY=1` so client IP and scheme come from IIS's forwarded
headers.

## Configuration

All configuration is via environment variables.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_DATA_DIR` | `/var/lib/cert-watch` (POSIX), `%PROGRAMDATA%\cert-watch` (Windows) | Directory for SQLite database |
| `CERT_WATCH_HOST` | `0.0.0.0` | Listen address |
| `CERT_WATCH_PORT` | `8000` | Listen port |
| `CERT_WATCH_SCHED_HOUR` | `6` | Hour to run daily scan (UTC) |
| `CERT_WATCH_SCHED_MIN` | `0` | Minute to run daily scan |
| `CERT_WATCH_TLS_VERIFY` | `0` | Set `1` to verify TLS certificates when scanning |
| `CERT_WATCH_AUDIT_RETENTION_DAYS` | `90` | Days of audit log to keep; purged at startup + daily. `0` disables purging |
| `CERT_WATCH_ALLOW_PRIVATE_IPS` | `1` | Set `1` to allow scanning private IP addresses (RFC 1918 / ULA) |

### Alerts (SMTP)

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | — | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USER` | — | SMTP username (optional) |
| `SMTP_PASSWORD` | — | SMTP password (optional) |
| `ALERT_FROM` | — | Sender email address |
| `ALERT_RECIPIENTS` | — | Comma-separated recipient addresses |

### Alerts (Webhook)

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERT_WEBHOOK_URL` | — | Webhook URL for JSON POST alerts |
| `ALERT_WEBHOOK_HEADERS` | — | JSON object of extra HTTP headers |

### Authentication

Authentication is disabled by default. Set `AUTH_PROVIDER` to enable.

#### LDAP / Active Directory

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PROVIDER` | — | Set to `ldap` |
| `LDAP_SERVER` | — | LDAP server URL(s), comma-separated for DC failover (e.g. `ldap://dc1.example.com,ldap://dc2.example.com`) |
| `LDAP_BASE_DN` | — | Base DN for user search |
| `LDAP_BIND_DN` | — | Service account DN for search phase |
| `LDAP_BIND_PASSWORD` | — | Service account password |
| `LDAP_USER_FILTER` | `(sAMAccountName={username})` | Search filter; `{username}` is replaced |
| `LDAP_START_TLS` | `0` | Set `1` to use StartTLS |
| `LDAP_CA_CERT` | — | CA cert for LDAPS (file path or PEM data, `LDAP_CA_CERT_FILE` supported) |
| `LDAP_REQUIRED_GROUPS` | — | Comma-separated group DNs; transitive membership check |
| `LDAP_CONNECT_TIMEOUT` | `5` | LDAP connection timeout (seconds) |

Requires: `pip install cert-watch[auth-ldap]`

#### OAuth / OIDC (Microsoft Entra, Google, etc.)

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PROVIDER` | — | Set to `oauth`, `entra`, `azure`, or `oidc` |
| `OAUTH_CLIENT_ID` | — | OAuth application client ID |
| `OAUTH_CLIENT_SECRET` | — | OAuth application client secret |
| `OAUTH_ISSUER_URL` | — | OIDC issuer URL (e.g. `https://login.microsoftonline.com/{tenant}/v2.0`) |
| `OAUTH_SCOPE` | `openid profile email` | OAuth scopes |
| `OAUTH_AUTHORIZATION_ENDPOINT` | — | Override (skip discovery) |
| `OAUTH_TOKEN_ENDPOINT` | — | Override (skip discovery) |
| `OAUTH_USERINFO_ENDPOINT` | — | Override (skip discovery) |

Requires: `pip install cert-watch[auth-oauth]`

### CSRF

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_CSRF_SECRET` | random | HMAC key for CSRF tokens |
| `CERT_WATCH_CSRF_DISABLED` | `0` | Set `1` to disable CSRF (testing only) |

## API endpoints

All JSON endpoints are at `/api/` and support `?page=` and `?limit=` pagination.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web dashboard |
| `GET` | `/healthz` | Health check (DB, scheduler, cert counts) |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/api/certificates` | List certificates (paginated) |
| `GET` | `/api/certificates/{id}` | Certificate detail (includes `tags` + `effective_tags`) |
| `GET` | `/api/tags` | Distinct tags across hosts + certs |
| `PUT` | `/api/certificates/{id}/tags` | Set a cert's tags (`{"tags": [...]}` or csv) |
| `PUT` | `/api/hosts/{id}/tags` | Set a host's tags |
| `GET` | `/api/hosts` | List tracked hosts |
| `GET` | `/api/alerts` | List alerts |
| `GET` | `/ct-lookup/{domain}` | Certificate Transparency lookup |
| `GET` | `/api/ct/reconciliation?domain=` | CT reconciliation (coverage gaps) |
| `POST` | `/hosts` | Add host (form) |
| `POST` | `/hosts/import` | Bulk import CSV |
| `POST` | `/hosts/{id}/scan` | Trigger immediate scan |
| `POST` | `/hosts/{id}/delete` | Delete host |
| `POST` | `/upload` | Upload certificate file |
| `POST` | `/certificates/{id}/delete` | Delete certificate |
| `GET` | `/login` | Login page |
| `POST` | `/login` | LDAP form login |
| `GET` | `/auth/login` | Start OAuth flow |
| `GET` | `/auth/callback` | OAuth callback |
| `GET` | `/auth/logout` | Logout (clears session) |

## Project layout

```
src/cert_watch/
  app.py               FastAPI app, routes, middleware
  auth.py              Authentication (LDAP, OAuth, sessions)
  alerts.py            Email + webhook alerting
  certificate_model.py X.509 certificate parsing
  cert_chain.py        Chain extraction and validation
  config.py            Environment-based settings
  ct_lookup.py         Certificate Transparency lookups
  database.py          SQLite persistence layer
  scan.py              TLS scanning
  scheduler.py         Daily scan scheduler
  upload.py            Certificate file upload/parse
  templates/           Jinja2 HTML templates
  static/              CSS
tests/                 pytest suite (368 tests)
docs/spec/             Work-item specs (one per FR)
deploy/
  k8s/                 Kustomize manifests
  compose/             Docker Compose
  systemd/             Systemd unit file
  iis/                 IIS web.config(s) + Windows runbook
  argocd/              Argo CD Application CR
.github/workflows/     CI, E2E, image build
```

## License

MIT
