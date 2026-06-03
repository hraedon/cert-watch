# Changelog

All notable changes to cert-watch are documented in this file.

## [0.5.0] — 2026-06-03

Hardens the integration edges (LDAP, outbound HTTP) and leans into the
regulated-SMB observability story: first-class alert channels and an
auditor-facing compliance report. SIEM/log export (Splunk HEC, syslog) and the
ACME renewal-window alert were scoped (Plan 023 §E/§F) but deferred to a later
release.

### Added
- **Compliance / Auditor Report (Plan 025)** — a one-click, point-in-time
  posture report for SOC 2 / ISO 27001 / PCI-DSS auditors. `GET
  /reports/compliance` renders a print-optimized HTML page (browser "Save as
  PDF" → clean auditor PDF, zero new dependencies); `GET
  /api/reports/compliance.json` and `.csv` export the same data. Reports are
  **tamper-evident**: a canonical JSON of the report is HMAC-SHA256-signed with
  the app signing key, and `cert-watch verify-report <file.json>` re-checks the
  hash and signature (PASS/FAIL). Covers grade distribution, fleet grade, the
  compliance-metric checklist (no SHA-1, strong key, TLS ≥ 1.2, HSTS; CAA shown
  as "Not collected" pending per-scan storage), and a 7/30/90-day remediation
  schedule. Linked from the Insights page.
- **Alert channel adapters (Plan 022)** — Microsoft Teams (Adaptive Card via
  Workflows), Discord, and PagerDuty (Events API v2, trigger + resolve-on-renewal).
  All delivery routes through the SSRF-safe HTTP opener.
- **SSRF-guarded HTTP opener** (`http_client.ssrf_safe_urlopen`) — resolves and
  checks the initial URL and **every redirect hop** against the scan blocklist,
  enforces an `http(s)` scheme allowlist, and honours the configurable
  `allow_private` / `allowed_subnets` policy. Webhook (incl. digest) and
  OCSP/CRL revocation probes now flow through it. *(Documented residual: urllib
  re-resolves on connect, so this is a large improvement over unvalidated
  `urlopen`, not the airtight pinned-IP guarantee the TLS scanner has — see the
  `http_client` module docstring; **BC-116/BC-117**.)*
- **Configurable LDAP group filter (BC-118)** — `CERT_WATCH_LDAP_GROUP_FILTER`
  with a `{group}` placeholder (defaults to the AD transitive-membership OID),
  unblocking OpenLDAP/FreeIPA `LDAP_REQUIRED_GROUPS`.

### Fixed
- **LDAP authentication bypass (security, BC-115)** — the user-bind step ignored
  `ldap3.bind()`'s return value; ldap3 returns `False` on bad credentials rather
  than raising, so any password authenticated an existing user. The result is now
  checked and a failed bind is rejected. Regression test added.
- **Compliance "TLS ≥ 1.2" metric over-reported.** The check upper-cased the
  protocol string but compared it against mixed-case prefixes, so TLS 1.0/1.1
  were counted as compliant; it also missed the bare `"TLSv1"` string both scan
  paths actually emit for TLS 1.0. TLS-version classification is now a shared
  `posture.tls_version_meets_1_2` helper used by both the posture grade and the
  compliance metric, with the same blind spot fixed in the posture engine's own
  TLS finding.
- **Fleet grade rollup** in the compliance report no longer reports `A+` for an
  all-`A` fleet (grade severity collapsed `A+`/`A`); it now returns the worst
  actual grade present.

### Changed
- **Coverage gate raised to 88%** (Plan 024); suite at ~88.7%.
- Compliance export uses one batched posture query instead of an N+1 over the
  fleet.

## [0.4.0] — 2026-06-03

First all-in-one release: repositioned as certificate-lifecycle observability for
small and mid-sized businesses, with the DNS path, OAuth callback, and
first-run-posture hardening below. (The 0.4.0 version was bumped earlier without a
changelog entry; this is the complete, consolidated record.)

### Added
- **`/readyz` endpoint (BC-110)** — split from `/healthz` so k8s liveness and
  readiness probes can be distinguished.
- **`cert_scan_errors_total` counter (BC-109)** on `/metrics`.
- **Scan degradation signal (BC-108)** — `ScannedEntry.chain_incomplete`
  surfaces a degraded-scan reason in the UI; warnings logged on openssl fallback
  and degraded-scan storage.
- **Inline-style ratchet test** — `tests/test_no_inline_styles.py` tracks the
  remaining `style=` attributes that block full CSP tightening.
- **OAuth callback tests (BC-113)** — `tests/test_oauth_callback.py` covers every
  branch of `/auth/callback` (state forgery, state/cookie mismatch, missing
  code/cookie, token-exchange failure, authz denial, happy path), asserting no
  session is minted on any failure. `routes/auth.py` coverage 52% → 83%.

### Changed
- **Positioning** — reframed as an all-in-one certificate-lifecycle observability
  tool for small and mid-sized businesses (README, package description,
  `docs/positioning.md`). The software-factory-2 build-method origin is retained
  as history, not identity.
- **DNS resolution** — the custom-nameserver path (`CERT_WATCH_DNS_SERVERS`) now
  uses **dnspython** instead of a hand-rolled UDP packet parser. dnspython
  validates each response against the query and falls back to TCP on truncation
  (the old path was UDP-only with a fixed 4 KiB buffer and a retrofitted
  anti-spoof check — resolved BC-079). `dnspython` is now a **core** dependency
  (it already backed the CAA lookup), so the custom-DNS feature and CAA checks no
  longer depend on an optional, undocumented install. The unused `[dns]` extra was
  removed.
- **First-run posture decision refactor (BC-114)** — extracted the
  secure-by-default decision (serve open / auto-provision admin / fail closed) out
  of `app.lifespan` into pure functions in `cert_watch/firstrun.py`
  (`is_network_exposed`, `first_run_action` → `FirstRunPosture`). Behaviour is
  unchanged; the decision is now table-tested over all input combinations in
  `tests/test_firstrun_posture.py`.
- **`/metrics` now uses the `prometheus_client` library (BC-111)** instead of
  hand-built exposition.
- **Performance** — `_LOG_RECORD_KEYS` extracted to a module-level frozenset (no
  per-log-line `LogRecord` allocation); `check_rate_limit` guards schema init with
  a `_rate_db_initialized` flag.
- **Kubernetes polish** — added a `PodDisruptionBudget` (with the SQLite
  `Recreate`-strategy rationale) and secret-management reminders in the example
  manifests.

### Fixed
- **BC-106** — stale integration-test mock signatures for `_resolve_host`.
- **BC-107** — `asyncio.run()` event-loop conflicts in `test_bc083_081` and
  `test_middleware_deps`.
- **BC-112** — added a unit test for the `_rate_db_initialized` flag.

## [0.3.0] — 2026-06-03

### Added
- **Insights page** — expiration calendar plus TLS-version and posture-grade fleet trends
- **Discover page** — CT-based coverage reconciliation and private-CA inventory
- **Dashboard redesign** — chip-based filters, fingerprint grouping, SQL-paginated queries
- **Detail page** — per-certificate panel cards with chain visualization, drift history, posture breakdown
- **In-UI password rotation** — change local admin password from Settings (BC-102)
- **CSP nonces** — per-request `script-src` nonce; all inline `on*=` handlers converted to delegated listeners (BC-075)
- **Session revocation** — HMAC session tokens embed per-user version; logout/credential-change invalidates prior sessions (BC-081)
- **Secure-by-default auth** — network-exposed instances auto-provision a local admin on first run (BC-083)
- **Read-only / read-write role tier** — `CERT_WATCH_WRITE_USERS` gates mutation access (BC-086)
- **Scan allowlist** — `CERT_WATCH_ALLOWED_SUBNETS` CIDR list scopes which private ranges are scannable (BC-080)
- **Async scanner** — `scan_host_async()` / `store_scanned_async()` for non-blocking concurrent scans
- **Reusable retry policy** — `retry.backoff_range()` exponential/linear strategy
- **CLI subcommands** — `cert-watch backup`, `cert-watch hash-password`, `cert-watch re-encrypt`
- **Prometheus metrics** — `/metrics` endpoint with optional bearer-token gating
- **CT monitor** — periodic Certificate Transparency reconciliation
- **Bulk CSV import** — `/hosts/import` for adding many hosts at once
- **Alert groups** — group-based routing for alert recipients
- **Audit log** — append-only mutation/login record with configurable retention
- **E2E test suite** — Playwright-based auth, settings, dashboard, upload, and delete flows

### Changed
- Dashboard queries are now SQL-paginated (Plan 018 B2) — no more `sqlite3.Row` leaks into routes
- Auth module decomposed from `auth.py` monolith into `auth/` package (Plan 021)
- `SecurityContext` is an immutable dataclass on `app.state.security`; `create_app()` injects dependencies (Plan 018 B1)
- CSP `style-src` keeps `'unsafe-inline'` (inline `style=` custom properties)
- CSRF is double-submit cookie; token accepted via header/form only, never query string (BC-070)
- `CERT_WATCH_COOKIE_SECURE` defaults to `1`; set `0` only for plain-HTTP local dev

### Fixed
- BC-101: monthly trend chart bucketing with dynamic bar scaling
- BC-090: entrypoint normalizes `--host`/env so BC-083 check sees the real bind
- BC-084: A+ posture for non-443 ports
- BC-087/88/89: audit findings (credential sanitization, error messages)
- BC-071: OAuth ID-token verification fails rather than silently falling back to userinfo
- BC-073: OAuth nonce verification in ID-token claims
- BC-074: `create_app` factory pattern for test isolation
- Scheduler loop bug that could cause missed daily scans
- SMTP password leakage in error messages

## [0.2.0] — 2026-05-26

### Added
- PKCS#12 (`.pfx`/`.p12`) and PKCS#7 (`.p7b`/`.p7c`) upload support
- TLS posture grading (A+/A/B/C/F) with configurable checks
- Drift detection alerts (issuer change, key-size drop, SHA-1 downgrade, TLS/posture downgrade)
- Certificate history snapshots with configurable retention
- Renewal tracking (links renewed certs to predecessors)
- Per-host threshold overrides for alert timing
- CAA record lookup endpoint
- HSTS probe during scans
- Fleet posture lenses (by issuer, owner, renewal method)
- Tags for certificates and hosts
- KV store for persistent settings with encrypted secret storage
- Database migration framework (0001–0011)
- LDAP/AD authentication with STARTTLS and group membership checks
- OAuth/OIDC authentication (Microsoft Entra, Google) with JWKS-based ID-token verification
- Break-glass local admin with scrypt hashing
- Rate limiting (SQLite-backed, proxy-aware)
- Setup wizard for first-run configuration
- Settings page (Auth, SMTP, Alerts tabs)
- Systemd unit with security hardening
- Windows/IIS deployment support (HttpPlatformHandler + ARR reverse proxy)
- Docker Compose deployment
- Kubernetes manifests with Argo CD GitOps
- Multi-arch Docker image (amd64 + arm64)

## [0.1.0] — 2026-05-04

### Added
- Initial release
- Host scanning via TLS handshake
- Certificate upload (PEM, DER)
- Web dashboard with color-coded expiry status
- REST API with pagination
- Email (SMTP) and webhook alerting
- Daily scheduled scans
- Certificate Transparency lookups via crt.sh
- Prometheus metrics endpoint
