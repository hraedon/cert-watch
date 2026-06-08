# Changelog

All notable changes to cert-watch are documented in this file.

## [0.6.6] — 2026-06-08

Host-level notes for pending and unscanned hosts, plus privacy and test-maintenance cleanup.

### Added
- **Host-level notes (BC-020).** Pending and unscanned hosts now support a free-text `notes` field.
  - Schema: `notes` column on the `hosts` table (with migration for existing DBs).
  - API: `PATCH /api/hosts/{host_id}/notes` and form POST `/hosts/{host_id}/notes`.
  - Add host / bulk import: notes accepted via form field and CSV column.
  - Dashboard: note chip shown in expandable host rows and normal entries.
  - Certificate detail page: inline edit/save toggle for host notes.
  - CSV export: hosts export includes the `notes` column.
  - 16 new tests covering repository, API, form routes, CSV export, and UI rendering.

### Changed
- **Privacy:** Removed Google Fonts CDN dependency; fonts are now self-hosted / local.
- **Test maintenance:** Cleaned up inline `importlib.reload` patterns in ~13 test files.

### Resolved
- BC-131, BC-147, BC-118, BC-137 — stale breadcrumbs resolved in the BC-020 session.

## [0.6.5] — 2026-06-07

Truth-in-advertising hardening pass: fix a silently-inert RBAC path for AD,
remove misleading UI surfaces, and close performance / CI hygiene gaps.

### Fixed
- **BC-150 — RBAC group-DN shredding for LDAP/AD (security).** The session token
  used comma-join encoding for group lists, which shredded every Active Directory
  group DN (commas are separators) into fragments. The result: every AD user
  fell back to `viewer` regardless of `CERT_WATCH_ROLE_MAP`. Encoding is now
  lossless base64url(JSON). RBAC gating now works correctly for AD group DNs.
  Regression test: `tests/test_session_groups.py`.

### Changed
- **Discover honesty (BC-099 / BC-129).** The Discover page no longer shows the
  always-empty "Mis-issuance" stat or the blank Issuer / first-seen columns.
  CT mis-issuance detection and per-issuer first-seen are deferred to 1.1
  (BC-151).
- **Discover performance (BC-097).** The Discover view no longer blocks on live
  crt.sh calls; it renders from the reconciliation cache and warms stale data
  off-thread.
- **Compliance report performance (BC-120 / BC-122).** Replaced the unbounded
  `list_dashboard_rows` load with a dedicated, bounded SQL query that only
  fetches leaf certificates and applies tag filtering at the database. Removes
  the N+1 posture lookup and the memory overhead of materialising full chain
  children + anchor rows.
- **CI / release hygiene (BC-152 / BC-153).** Bumped `astral-sh/setup-uv`,
  `actions/upload-artifact`, and `actions/download-artifact` to Node-24-capable
  pins (GitHub removes Node-20 on 2026-06-16). Added `pip-audit` of the e2e
  extra dependency closure.

## [0.6.0] — 2026-06-06

Locks down role-based access control and machine-to-machine automation, proven
through a full end-to-end UI regression suite.

> **Upgrade note (RBAC is now enforced).** If you set `CERT_WATCH_ROLE_MAP`
> expecting role-based gating, it now **actually takes effect**: IdP groups/roles
> travel in the session token and decide write access on every request and
> form-POST (previously they never reached role resolution, so everyone
> collapsed to read-only or full-access depending on configuration — BC-145).
> Review your role map before upgrading. With **no** role map configured,
> behaviour is unchanged (authenticated users keep full access).

### Added
- **API-key / service-account authentication (Plan 039, BC-104)** — scoped
  bearer tokens for machine-to-machine access to `/api/*` without a browser
  session. Send `Authorization: Bearer cwk_…`. Scopes `read` / `write` / `admin`
  map onto the RBAC roles (viewer / operator / admin). Tokens are stored only as
  a SHA-256 hash (the raw `cwk_…` token is shown **once** at creation); keys are
  created, listed, and revoked from **Settings → API keys** or the admin-scoped
  `/api/api-keys` endpoints. Key creation/revocation and any state-changing call
  made with a key are recorded in the audit log under the key's name.

### Changed
- **RBAC is wired end-to-end (Plan 035 / BC-145).** Groups and roles are now
  carried in the signed session token and resolved against the role map on every
  request, so the dashboard and detail pages hide write controls from viewers,
  form-POST routes reject viewer writes, and the JSON API returns 403 — not just
  the API layer. A read-only dashboard now shows an explicit notice.
- **Dashboard performance (BC-139).** The grouped dashboard view no longer loads
  every certificate into memory; uploaded leaves and pending hosts are queried
  directly, so memory scales with what's shown rather than the whole table.
- **Alerts page (BC-130).** Delivery chips now reflect the channels you've
  actually configured (Email / Webhook) instead of always showing both, with a
  hint when none are set.
- **CI quality gates.** `mypy` is now gated in CI (source is at zero errors —
  BC-093 / BC-146). The Playwright suite is split into a required functional job
  and a non-blocking visual-regression job.

### Testing
- **Full E2E UI regression suite.** 35 functional Playwright tests (every page
  renders; upload/host/delete/settings/API-key flows) plus 8 masked
  visual-regression baselines, all on stable `data-testid` selectors (BC-132).
  RBAC admin-vs-viewer gating is asserted through the browser.

## [0.5.3] — 2026-06-05

Maintenance: CI and deploy-smoke fixes; private-CA LDAPS auth fixes found by the
live AD end-to-end runthrough; TOFU CA auto-provisioning and synthetic-LDAPS CI.

## [0.5.2] — 2026-06-04

Maintenance release: no user-facing behaviour change. Hardens the test suite and
speeds up CI.

### Changed
- **Test suite ~3× faster** (≈273s → ≈95s): parallel by default via pytest-xdist
  (`-n auto --dist loadscope`), `COVERAGE_CORE=sysmon` in CI, retry-backoff sleeps
  neutralized in unit tests, and the CT-reconciliation test mocked at the network
  boundary (was a real crt.sh call). E2E runs serial (`-n0`).
- **Test quality**: ~13 "test theater" cases that passed even with the feature
  broken now assert real behaviour. Coverage 88.9% → 90.1% (`certificates.py`
  70→85%, `routes/settings.py` 75→85%, `scheduler.py` 81→97%), with new
  SMTP-send / LDAP-connect tests.
- **Internal**: `scheduler` per-day work extracted to a module-level `_run_cycle`
  so its failure-isolation contract is unit-testable (no behaviour change).
- Docs: backlog now generated from the agent-notes DB (`OPEN_BREADCRUMBS.txt`)
  rather than hand-maintained.

## [0.5.0] — 2026-06-03

Hardens the integration edges (LDAP, outbound HTTP) and leans into the
regulated-SMB observability story: first-class alert channels, an auditor-facing
compliance report, an ACME renewal-stall alert, SIEM/log export, and a batch of
security-hardening fixes from two adversarial reviews.

> **Upgrade note (breaking, OAuth only):** OAuth login now **requires
> `CERT_WATCH_BASE_URL`**. The redirect URI is no longer derived from the
> request `Host` header (that allowed Host-injection of the OAuth callback —
> review #3). Set `CERT_WATCH_BASE_URL` to your external URL (e.g.
> `https://certs.example.com`) before upgrading if you use OAuth/OIDC.

### Added
- **ACME renewal-stall alert (Plan 027)** — a `renewal_stalled` alert fires when
  a leaf certificate is inside its renewal window
  (`CERT_WATCH_RENEWAL_WINDOW_DAYS`, default 30) and **no successor certificate
  has appeared**, flagging a broken Certbot / cert-manager / ACME job well before
  the generic expiry warning. Distinct signal, distinct remediation; delivered
  through the existing email/webhook/adapter channels. Set the window to `0` to
  disable.
- **SIEM / log export (Plan 028)** — make the audit log consumable by a SIEM.
  **Syslog** (`CERT_WATCH_SYSLOG_HOST`/`_PORT`/`_PROTO`, stdlib RFC-5424 handler,
  serves any SIEM and the Azure AMA path) and **Splunk HEC**
  (`CERT_WATCH_HEC_URL` + `CERT_WATCH_HEC_TOKEN`(`_FILE`), through the SSRF-safe
  opener, delivered on a bounded background pool), plus a **Windows Event Log**
  sink (`CERT_WATCH_EVENTLOG=1`, Application log via pywin32 — install the
  `cert-watch[windows]` extra; disables itself off-Windows). All sinks are
  **fail-open** — a down SIEM never blocks or breaks an audited action; with
  nothing configured the audit path is unchanged.
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

### Security (hardening from two adversarial reviews — Plan 029)
- **OAuth ID-token algorithm allowlist** — discovered `alg` values are now
  intersected with an asymmetric allowlist (RS/ES/PS); `none` and the symmetric
  `HS*` family (RS/HS key-confusion) can never be accepted, no matter what the
  IdP advertises. The authlib fallback decode is pinned to the same list.
- **OAuth redirect_uri no longer trusts the Host header** — requires
  `CERT_WATCH_BASE_URL` (see upgrade note above; review #3).
- **OAuth IdP fetches routed through the SSRF-safe opener** — discovery, JWKS,
  and userinfo requests honour the `allow_private`/`allowed_subnets` policy
  instead of fetching arbitrary IdP-supplied URLs (review #8).
- **Stored-XSS guard on `runbook_url`** — http(s) scheme only; a `javascript:`
  runbook link can no longer be planted and rendered on the cert detail page.
- **Login CSRF** — `POST /login` now enforces the double-submit token (review #19).
- **scrypt username-timing oracle fixed** — the username-mismatch dummy hash now
  uses the stored hash's cost parameters, so a custom-cost admin hash no longer
  makes the match path measurably slower than a mismatch (review F#1).
- **Proxy IP trust** — with `CERT_WATCH_TRUST_PROXY=1` and no
  `CERT_WATCH_TRUSTED_PROXIES`, the **rightmost** `X-Forwarded-For` entry is used
  (the hop the trusted proxy appended), not the spoofable leftmost one; a startup
  warning is logged.
- **Compliance report fails closed** (HTTP 503) rather than signing with an empty
  key when the app isn't fully initialized.
- `cw_sid` is now `HttpOnly`; added `Referrer-Policy`, `Permissions-Policy`, and
  `X-Permitted-Cross-Domain-Policies` response headers; `/healthz` no longer
  discloses version/commit.
- **First-run admin password** is no longer written to the log on a file-write
  failure; recovery instructions are logged instead.

### Changed
- **Coverage gate raised to 88%** (Plan 024); suite at ~88.7%.
- Compliance export uses one batched posture query instead of an N+1 over the
  fleet.
- **Configurable CT log** (`CERT_WATCH_CT_LOG_URL`) and a short-TTL cache on CT
  reconciliation; dedicated rate limit on `/api/ct/reconciliation`.
- **Supply chain:** CI pins actions by SHA and adds `pip-audit`; the Docker base
  image is pinned by digest; the example k8s `NetworkPolicy` restricts ingress to
  the ingress/monitoring namespaces (**verify the namespace names match your
  cluster before deploying**).

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
