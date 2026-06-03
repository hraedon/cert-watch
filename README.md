# cert-watch

[![CI](https://github.com/hraedon/cert-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/hraedon/cert-watch/actions/workflows/ci.yml)

All-in-one observability for the **certificate lifecycle** — built for small and
mid-sized businesses that need one self-hosted place to see every TLS
certificate they depend on. Live host scanning **and** offline file upload feed a
web dashboard, REST API, and alerting; signature-verified chain validation, TLS
posture grading, and Certificate Transparency reconciliation turn "is it
expiring?" into "is the whole estate healthy?"

Supports PEM, DER, CER, CRT, PKCS#12 (`.pfx`/`.p12`), PKCS#7 (`.p7b`/`.p7c`), and multi-cert chain bundles.

## Features

- **Host scanning** — TLS handshake to extract leaf + chain certificates from any host
- **Certificate upload** — PEM, DER, PKCS#12, PKCS#7 with automatic chain extraction
- **Web dashboard** — color-coded expiry status (red/yellow/green), chain visualization, host management
- **REST API** — JSON endpoints for certificates, hosts, and alerts with pagination
- **Alerting** — email (SMTP), generic webhook, and first-class **Microsoft Teams / Discord / PagerDuty** channels, with configurable per-host thresholds
- **Renewal-stall alert** — flags a certificate inside its renewal window with no successor yet (a broken Certbot / cert-manager / ACME job) before the expiry alarm
- **SIEM / log export** — ship the audit log to **syslog**, **Splunk HEC**, or the **Windows Event Log** (fail-open; never blocks an audited action)
- **Scheduled scans** — daily automatic re-scan of all tracked hosts
- **Certificate Transparency** — lookup certificates via crt.sh
- **Insights** — expiration calendar plus fleet TLS-version and posture-grade trends over time
- **Discover** — CT-based coverage reconciliation: surfaces hostnames seen in CT but not tracked, plus a private-CA inventory
- **Bulk import** — CSV upload for adding many hosts at once
- **Prometheus metrics** — `/metrics` endpoint for monitoring integration (optionally bearer-token gated)
- **Renewal tracking** — links renewed certificates to their predecessors
- **Certificate history** — per-scan snapshots with configurable retention; fleet TLS version and posture grade trends
- **Audit log** — append-only record of mutations and logins, with configurable retention
- **Compliance report** — one-click, point-in-time posture report for SOC 2 / ISO 27001 / PCI-DSS auditors (print-to-PDF HTML + signed JSON/CSV), with a `cert-watch verify-report` tamper-evidence check
- **Authentication** — LDAP/AD and OAuth/OIDC (Microsoft Entra, Google, etc.)

## Stack

- Python 3.12+ / FastAPI / Jinja2 / `cryptography` / `dnspython` (CAA + custom-nameserver resolution)
- SQLite (single-file, WAL mode)
- Optional: `ldap3` (LDAP auth), `authlib` (OAuth auth)
- Docker image published to GHCR (multi-arch: amd64 + arm64)
- Deploy: Kubernetes (Argo CD GitOps), Docker Compose, Linux + systemd, or Windows + IIS

## Quick start (local)

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/python -m cert_watch --host 127.0.0.1   # serves http://localhost:8000
.venv/bin/pytest -q                                # run tests
```

> The loopback bind matters: a bare loopback instance (no proxy) serves open and
> sends you to the `/setup` wizard — exactly what you want for local dev. A
> *network-exposed* instance instead comes up with an auto-provisioned admin (see
> [First run](#first-run)).

## First run

On a fresh install with no hosts and no auth configured, cert-watch redirects
you to `/setup` to create a local admin account. After creating the admin you
can log in and use the dashboard.

To skip the wizard (for local dev or air-gapped environments):

```bash
CERT_WATCH_ALLOW_UNAUTH=1 .venv/bin/python -m cert_watch
```

> **Secure by default — never open on a network by accident.** What happens with
> no auth configured depends on whether the instance is *network-exposed*:
>
> | Situation | Behaviour |
> |-----------|-----------|
> | Bare loopback (`127.0.0.1`, no proxy) | Serves open, redirects to `/setup` |
> | Routable bind (`0.0.0.0`) **or** loopback + `CERT_WATCH_TRUST_PROXY=1` (IIS/nginx) | **Auto-provisions** a local `admin` with a generated password — comes up *authenticated* |
> | Any bind + `CERT_WATCH_ALLOW_UNAUTH=1` | Serves open (explicit opt-out; dev / air-gapped only) |
>
> When it auto-provisions, the one-time password is written to
> `${CERT_WATCH_DATA_DIR}/initial-admin-password` (mode 0600) and logged. Log in,
> then configure `AUTH_PROVIDER` (LDAP/OAuth) **or** pin a password via
> `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` (generate with `cert-watch hash-password`),
> and delete the file. A network-exposed instance therefore comes up working
> *and* authenticated — it never serves anonymously unless you ask it to.

### Settings page

Once the app is running, click **Settings** in the top-right to configure:

- **Auth** — switch between local admin, LDAP/AD, or OAuth/OIDC without
  restarting. Env vars always override GUI values (escape hatch).
- **SMTP** — alert email server with a "Send test email" button.
- **Alerts** — webhook URL, recipients, and digest mode.

### Setup wizard

The wizard runs automatically on first launch. It creates a local admin
account and optionally walks through SMTP and first-host configuration. Set
`CERT_WATCH_ALLOW_UNAUTH=1` to suppress the redirect.

## Docker

The container binds `0.0.0.0`, so on first run it auto-provisions an `admin`
(see [First run](#first-run)) and comes up authenticated:

```bash
docker build -t cert-watch:dev .
docker run --rm -p 8000:8000 -v cert-watch-data:/var/lib/cert-watch cert-watch:dev
docker logs <container>     # grab the one-time admin password (also in the data volume)
```

For production, configure `AUTH_PROVIDER` (LDAP/OAuth) or pin `CERT_WATCH_LOCAL_ADMIN_*`
instead of relying on the generated password. Or with compose:

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
Set `CERT_WATCH_TRUST_PROXY=1` so the client IP (for rate limiting and the audit
log) is read from IIS's forwarded headers rather than the loopback connection.

To land audit events in the **Windows Event Log** (Application log, where AMA /
SIEM agents collect them), install the extra and enable the sink:

```powershell
uv pip install -e ".[windows]"   # pywin32
$env:CERT_WATCH_EVENTLOG = "1"
```

## Configuration

All configuration is via environment variables.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_DATA_DIR` | `/var/lib/cert-watch` (POSIX), `%PROGRAMDATA%\cert-watch` (Windows) | Directory for SQLite database |
| `CERT_WATCH_HOST` | `0.0.0.0` | Listen address. Also overridable with `--host`; the entrypoint normalizes the two so the secure-by-default check sees the real bind |
| `CERT_WATCH_PORT` | `8000` | Listen port (also `--port`) |
| `CERT_WATCH_SCHED_HOUR` | `6` | Hour to run daily scan (UTC) |
| `CERT_WATCH_SCHED_MIN` | `0` | Minute to run daily scan |
| `CERT_WATCH_TLS_VERIFY` | `0` | Set `1` to verify TLS certificates when scanning |
| `CERT_WATCH_LOG_FORMAT` | `text` | Log output format; set `json` for structured logs |
| `CERT_WATCH_AUDIT_RETENTION_DAYS` | `90` | Days of audit log to keep; purged at startup + daily. `0` disables purging |
| `CERT_WATCH_HISTORY_RETENTION_DAYS` | `365` | Days of per-scan certificate history to keep; purged at startup + daily. `0` disables purging |
| `CERT_WATCH_ALERT_RETENTION_DAYS` | `90` | Days of alert records to keep; purged at startup + daily. `0` disables purging |
| `CERT_WATCH_DRIFT_ALERTS` | `1` | Set `0` to disable drift alerts (issuer change, key-size drop, SHA-1 downgrade, posture/TLS downgrade) |
| `CERT_WATCH_RENEWAL_WINDOW_DAYS` | `30` | Window for the renewal-stall alert: a leaf cert this many days from expiry with no successor certificate raises a `renewal_stalled` alert. `0` disables it |
| `CERT_WATCH_CT_LOG_URL` | `https://crt.sh` | CT log base URL for Discover/CT lookups; point at a private CT log if needed (validated http/https) |
| `CERT_WATCH_CHECK_REVOCATION` | `0` | Set `1` to probe OCSP/CRL reachability during posture grading (findings are warnings, not penalties) |
| `CERT_WATCH_RELOAD` | `0` | Set `1` to enable uvicorn auto-reload on code changes (development only) |
| `CERT_WATCH_DNS_SERVERS` | — | Comma-separated DNS server IPs for hostname resolution during scans (e.g. internal DCs). Falls back to the system resolver |
| `CERT_WATCH_ALLOW_PRIVATE_IPS` | `1` | Set `1` to allow scanning private IP addresses (RFC 1918 / ULA) |
| `CERT_WATCH_ALLOWED_SUBNETS` | — | Comma-separated CIDR allowlist scoping which **private** ranges may be scanned (e.g. `10.0.0.0/8,192.168.0.0/16`). When set, a private target is allowed only if it falls inside one of these ranges; public hosts stay scannable and loopback/link-local (incl. cloud metadata) stay blocked. Makes internal scanning an explicit, auditable capability. |

### Scanning & SSRF policy

cert-watch scans hosts you add to it (a TLS handshake to read the certificate),
so the set of addresses it may reach is a security boundary. The defaults suit
the primary use case — monitoring internal certificates in a self-hosted, AD
shop — but should be tightened for sensitive environments:

- **Loopback, link-local, and the cloud metadata endpoint (`169.254.169.254`)
  are always blocked**, regardless of configuration.
- **Public hosts are always scannable** (reading a public cert is the baseline
  function).
- **Private ranges** (RFC 1918 / ULA) are governed by policy:
  - Default (`CERT_WATCH_ALLOW_PRIVATE_IPS=1`, no allowlist): all private ranges
    are scannable.
  - **Recommended for sensitive deployments:** set `CERT_WATCH_ALLOWED_SUBNETS`
    to exactly the internal ranges you intend to monitor. Anything outside them
    is refused. The first-run setup wizard prompts for these ranges.
  - `CERT_WATCH_ALLOW_PRIVATE_IPS=0` blocks all private scanning.
- For defence-in-depth, also constrain egress at the network layer (k8s
  `NetworkPolicy`, an egress proxy, or a dedicated network segment). The shipped
  `deploy/k8s/networkpolicy.yaml` is permissive toward internal ranges by
  default to match the app default — tighten it alongside the allowlist.

### Alerts (SMTP)

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | — | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USER` | — | SMTP username (optional) |
| `SMTP_PASSWORD` | — | SMTP password (optional; `SMTP_PASSWORD_FILE` supported) |
| `ALERT_FROM` | — | Sender email address |
| `ALERT_RECIPIENTS` | — | Comma-separated recipient addresses |
| `ALERT_DIGEST_ONLY` | `0` | Set `1` to batch alerts into a single digest rather than one message per certificate |

### Alerts (Webhook)

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERT_WEBHOOK_URL` | — | Webhook URL for JSON POST alerts (also the incoming-webhook URL for Teams / Discord) |
| `ALERT_WEBHOOK_HEADERS` | — | JSON object of extra HTTP headers |
| `ALERT_WEBHOOK_TEMPLATE` | — | Optional payload template (generic kind only); when unset a default JSON body is sent |
| `ALERT_WEBHOOK_KIND` | `generic` | `generic`, `teams` (Adaptive Card via Workflows), `discord`, or `pagerduty` — selects the payload format |
| `ALERT_PAGERDUTY_ROUTING_KEY` | — | PagerDuty Events API v2 routing key (triggers an incident; auto-resolves on renewal). `*_FILE` supported |

All webhook delivery — including the Teams/Discord/PagerDuty channels — is routed
through an **SSRF-guarded HTTP opener** that resolves and re-checks every redirect
hop against the scan blocklist (see [Scanning & SSRF policy](#scanning--ssrf-policy)).

### SIEM / log export

Ship the structured audit log (`ts, actor, action, target_type, target_id,
detail, source_ip`) to a SIEM. Each sink is enabled only when configured, and all
are **fail-open** — a down or slow SIEM never blocks or breaks an audited action.
With nothing configured the audit write path is unchanged.

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_SYSLOG_HOST` | — | Syslog server host; enables the syslog sink. Serves any SIEM (QRadar, Sentinel via AMA, Splunk via UF) |
| `CERT_WATCH_SYSLOG_PORT` | `514` | Syslog port |
| `CERT_WATCH_SYSLOG_PROTO` | `udp` | `udp` or `tcp` |
| `CERT_WATCH_HEC_URL` | — | Splunk HTTP Event Collector URL; enables the HEC sink (delivered through the SSRF-safe opener on a background pool) |
| `CERT_WATCH_HEC_TOKEN` | — | Splunk HEC token (required for HEC). `*_FILE` supported |
| `CERT_WATCH_HEC_INDEX` | — | Optional Splunk index |
| `CERT_WATCH_HEC_SOURCETYPE` | `cert_watch` | Splunk sourcetype |
| `CERT_WATCH_EVENTLOG` | `0` | Set `1` to write to the **Windows Event Log** (Application log). Windows only; install the `cert-watch[windows]` extra (pywin32) |
| `CERT_WATCH_EVENTLOG_SOURCE` | `cert-watch` | Event source name for the Windows Event Log sink |
| `CERT_WATCH_INSTANCE_ID` | hostname | Instance identifier stamped on exported events |

### Authentication

No authentication *provider* is configured by default — set `AUTH_PROVIDER` to
enable LDAP or OAuth/OIDC. cert-watch is nonetheless **secure by default**: a
network-exposed instance with no provider configured **auto-provisions a local
admin** on first run rather than serving open (see [First run](#first-run) for
the full behaviour matrix and where the generated password lands). To run open
anyway (dev / air-gapped), set `CERT_WATCH_ALLOW_UNAUTH=1`.

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
| `CERT_WATCH_JWKS_CACHE_TTL` | `86400` | Seconds to cache the issuer's JWKS for ID-token verification |

Requires: `pip install cert-watch[auth-oauth]`

> **`CERT_WATCH_BASE_URL` is required for OAuth.** The OAuth redirect URI is built
> from this value and is **not** derived from the request `Host` header (that
> would let a Host-injection attack steer the IdP's callback). Set it to your
> external URL, e.g. `https://certs.example.com`. OAuth login refuses to proceed
> until it is set.

When behind a reverse proxy/TLS terminator, also set `CERT_WATCH_BASE_URL` (see
below) so the OAuth redirect URI is built with your public host.

#### Authorization

Once a provider authenticates a user, these optional gates decide what they can
do. All are comma-separated and unset by default (any authenticated user gets
full access).

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_ALLOWED_GROUPS` | — | Directory group DNs/names; users outside them are denied |
| `CERT_WATCH_ALLOWED_ROLES` | — | OAuth/OIDC roles required for access |
| `CERT_WATCH_ADMINS` | — | Usernames allowed to reach `/settings` |
| `CERT_WATCH_WRITE_USERS` | — | Usernames allowed to mutate data; when set, everyone else is read-only (admins always write) |
| `CERT_WATCH_LOCAL_ADMIN_USER` | — | Break-glass local admin username (works even when the directory is down) |
| `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` | — | scrypt hash for the break-glass admin; generate with `cert-watch hash-password` (`*_FILE` supported) |

### Secrets, sessions & CSRF

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_AUTH_SECRET` | persisted | HMAC key for session cookies. If unset, a key is generated and persisted to `${DATA_DIR}/.auth_secret` so sessions survive restarts. `*_FILE` supported. Set explicitly in production (or use the file the installers write) |
| `CERT_WATCH_CSRF_SECRET` | persisted | HMAC key for CSRF tokens; same persistence behaviour as `CERT_WATCH_AUTH_SECRET`. `*_FILE` supported |
| `CERT_WATCH_COOKIE_SECURE` | `1` | Cookies are `Secure`-flagged by default. Set `0` only for plain-HTTP local dev |
| `CERT_WATCH_CSRF_DISABLED` | `0` | Set `1` to disable CSRF (testing only) |

> Rotating `CERT_WATCH_AUTH_SECRET` invalidates existing sessions and requires
> re-encrypting stored secrets — run `cert-watch re-encrypt <old_key>` after
> changing it.

### Reverse proxy / TLS termination

Set these when IIS, nginx, or an ingress terminates TLS and forwards to
cert-watch (see [`deploy/iis/README.md`](deploy/iis/README.md)).

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_TRUST_PROXY` | `0` | Set `1` to read the client IP from `X-Forwarded-For` / `X-Real-IP` (for rate limiting + audit log) instead of the proxy's connection IP |
| `CERT_WATCH_TRUSTED_PROXIES` | — | Comma-separated proxy IPs to trust for the above; restricts which sources may set forwarded headers |
| `CERT_WATCH_BASE_URL` | — | Public base URL (e.g. `https://certs.example.com`). Builds the OAuth redirect URI from a trusted value rather than the request `Host` header. **Required when OAuth/OIDC is enabled** |
| `CERT_WATCH_METRICS_TOKEN` | — | When set, `/metrics` requires `Authorization: Bearer <token>` |
| `CERT_WATCH_ALLOW_UNAUTH` | `0` | Set `1` to allow running with no auth provider on a non-loopback bind (suppresses the secure-by-default refusal and the `/setup` redirect) |

## CLI commands

The `cert-watch` entrypoint supports several subcommands:

```bash
cert-watch                  # Start the web server (default)
cert-watch backup <path>    # Create a WAL-safe SQLite backup
cert-watch hash-password    # Generate a scrypt password hash (interactive)
cert-watch re-encrypt <key> # Re-encrypt kv_store after .auth_secret rotation
cert-watch verify-report <file.json>  # Verify a signed compliance report
```

### `cert-watch backup <path>`

Creates a consistent snapshot of the SQLite database using the Online Backup
API (safe to run while the server is running):

```bash
cert-watch backup /backups/cert-watch-$(date +%F).sqlite3
```

### `cert-watch hash-password`

Interactive prompt to generate a scrypt hash suitable for
`CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH`:

```bash
cert-watch hash-password
# Password: ********
# Confirm:  ********
# $scrypt$N=...  (paste into CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH)
```

### `cert-watch re-encrypt <old_key>`

After rotating `CERT_WATCH_AUTH_SECRET`, re-encrypts any secrets stored in the
`kv_store` table with the new key. Pass the old key as an argument (or set
`CERT_WATCH_AUTH_SECRET` to the old value and pass the new key):

```bash
cert-watch re-encrypt <old-signing-key>
```

### `cert-watch verify-report <file.json>`

Verifies a signed compliance report exported from `/api/reports/compliance.json`.
Recomputes the content hash and HMAC signature using `CERT_WATCH_AUTH_SECRET` and
prints `PASS`/`FAIL` (non-zero exit on failure):

```bash
cert-watch verify-report compliance-report.json
```

> **What the signature proves — and what it doesn't.** The report is
> *tamper-evident*: the HMAC-SHA256 over the report's canonical JSON detects any
> edit to a downloaded report by anyone **without** `CERT_WATCH_AUTH_SECRET`. It
> is **not non-repudiable** — the instance holds the signing key, so an operator
> with the key could produce a differently-signed report. For a self-hosted,
> point-in-time auditor export this is the appropriate guarantee; treat the
> signature as "this came from this instance and wasn't altered afterward," not
> as independent third-party attestation. The CSV export carries the same hash
> and signature for cross-checking, but `verify-report` reads the **JSON** export
> (the signature covers the canonical JSON, not the CSV bytes). Rotating
> `CERT_WATCH_AUTH_SECRET` invalidates verification of previously-issued reports.
>
> The **CAA** compliance metric currently shows **"Not collected"**: CAA is an
> on-demand lookup (`/caa-check`), not yet stored per scan, so it is reported
> honestly rather than estimated. Per-scan CAA storage is a planned follow-on.

## Endpoints

JSON endpoints are at `/api/` and support `?page=` and `?limit=` pagination.

### Web pages (HTML)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard |
| `GET` | `/alerts` | Alerts view |
| `GET` | `/scan-history` | Per-scan history |
| `GET` | `/insights` | Expiration calendar + TLS/grade trends |
| `GET` | `/discover` | CT coverage reconciliation + private-CA inventory |
| `GET` | `/audit` | Audit log |
| `GET` | `/reports/compliance` | Compliance report (print-to-PDF; `?tag=` to scope) |
| `GET` | `/settings` | Settings (admin) |
| `GET` | `/setup` | First-run setup wizard |

### JSON / operational

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check (DB, scheduler, cert counts) |
| `GET` | `/api/health` | Health check (JSON) |
| `GET` | `/metrics` | Prometheus metrics (bearer-gated when `CERT_WATCH_METRICS_TOKEN` set) |
| `GET` | `/api/certificates` | List certificates (paginated) |
| `GET` | `/api/certificates/{id}` | Certificate detail (includes `tags` + `effective_tags`) |
| `GET` | `/api/tags` | Distinct tags across hosts + certs |
| `PUT` | `/api/certificates/{id}/tags` | Set a cert's tags (`{"tags": [...]}` or csv) |
| `PUT` | `/api/hosts/{id}/tags` | Set a host's tags |
| `GET` | `/api/hosts` | List tracked hosts |
| `GET` | `/api/alerts` | List alerts |
| `GET` | `/ct-lookup/{domain}` | Certificate Transparency lookup |
| `GET` | `/caa-check/{domain}` | CAA record lookup |
| `GET` | `/api/ct/reconciliation?domain=` | CT reconciliation (coverage gaps) |
| `GET` | `/api/reports/compliance.json` | Signed compliance report (JSON; `?tag=` to scope) |
| `GET` | `/api/reports/compliance.csv` | Signed compliance report (CSV) |
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
  app.py               FastAPI app factory + lifespan
  routes/              HTTP route handlers (api, views, hosts, certificates, …)
  middleware.py        Security middleware + FastAPI deps (auth, CSRF, rate limit, CSP)
  auth/                Authentication package (session, LDAP, OAuth, local admin, factory)
  alerts.py            Email + webhook alerting
  certificate_model.py X.509 certificate parsing
  cert_chain.py        Chain extraction and validation
  config.py            Environment-based settings
  ct_lookup.py         Certificate Transparency lookups
  posture.py           TLS posture grading
  database/            SQLite persistence layer (repositories, queries, migrations)
  scan.py              TLS scanning
  scheduler.py         Daily scan scheduler
  upload.py            Certificate file upload/parse
  templates/           Jinja2 HTML templates
  static/              CSS
tests/                 pytest suite (715 unit tests)
docs/spec/             Work-item specs (one per FR)
deploy/
  k8s/                 Kustomize manifests
  compose/             Docker Compose
  systemd/             Systemd unit file
  iis/                 IIS web.config(s) + Windows runbook
  argocd/              Argo CD Application CR
.github/workflows/     CI, E2E, image build
```

## Prior art & positioning

cert-watch is not the first TLS-certificate monitor, and it doesn't pretend to
be. Its niche is being the **all-in-one** certificate-observability tool a small
or mid-sized business can self-host: deep, read-only insight into the whole
certificate estate in one unit, rather than stitching several single-purpose
tools together. For simple "tell me before a cert expires," tools like **Uptime
Kuma** are an excellent fit; for pure CT watch, **SSLMate Cert Spotter**; for
ACME issuance/renewal, **Certimate**.

cert-watch's value is the bundle an SMB otherwise has to assemble piecemeal,
delivered as one self-contained unit: live scan **+** offline upload,
signature-verified chain validation, TLS posture grading, CT reconciliation,
directory auth (LDAP/Entra), and an audit log. (It also began life as a
hand-built comparison point for
[software-factory-2](https://github.com/hraedon/software-factory-2); that origin
is documented in the positioning notes but is no longer what the tool is for.)

See [`docs/positioning.md`](docs/positioning.md) for the full landscape table,
an honest account of where the alternatives are better, and how this shapes the
roadmap.

## License

MIT
