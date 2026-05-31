# AGENTS.md

Conventions and quick reference for agents (and humans) working on cert-watch.

## Why this project exists

cert-watch is a "traditional"-build comparison point for [software-factory-2](https://github.com/hraedon/software-factory-2). Same MVP spec; hand-rolled (or single-shot agent-built) instead of factory-orchestrated. The repo at `hraedon/cert-watch-factory-failed` is the prior factory attempt — kept for comparison, not for reuse.

## Orient

1. **Read the spec.** `docs/spec/wi_*.md` — one file per FR or interface module, with explicit acceptance criteria. The spec is the contract.
2. **Read the scaffold.** `src/cert_watch/` — `app.py` (FastAPI), `templates/`, `static/`, plus feature modules: `certificate_model.py`, `cert_chain.py`, `database.py`, `scan.py`, `upload.py`, `alerts.py`, `scheduler.py`, `auth.py`, `ct_lookup.py`, `config.py`.
3. **Note the deploy story.** See `deploy/` (k8s + Argo CD, docker compose, systemd). Argo CD watches `deploy/k8s/`; CI bumps the image tag there on every merge to `main`. Do not commit changes to `deploy/k8s/kustomization.yaml` in feature PRs.

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q            # unit tests
.venv/bin/ruff check .         # lint

# Auth extras (optional — tests mock these, but needed for real usage):
uv pip install -e ".[auth-ldap]"   # LDAP/AD
uv pip install -e ".[auth-oauth]"  # OAuth/OIDC (Entra, Google)
uv pip install -e ".[auth]"        # both

# E2E:
uv pip install -e ".[e2e]" && .venv/bin/playwright install --with-deps chromium
.venv/bin/pytest -m e2e tests/e2e -q
```

E2E tests on the dev host need `libatk-1.0-0t64 libatk-bridge-2.0-0t64 libcups2t64 libxcomposite1 libxdamage1 libxrandr2 libgtk-3-0t64 libasound2t64` (one-time sudo install). CI handles this via `playwright install --with-deps`.

## Conventions

- **Single SQLite file** at `${CERT_WATCH_DATA_DIR}/cert-watch.sqlite3` (default `/var/lib/cert-watch`). Deployment is single-writer; `Recreate` rollout strategy in k8s. WAL mode enabled.
- **PKCS#12 (`.pfx`) and PKCS#7 (`.p7b`/`.p7c`) support extends the original spec.**
- **Auth is optional.** When `AUTH_PROVIDER` is unset, all routes are open (backward compat). Set to `ldap` or `oauth`/`entra` to enable. Auth deps (`ldap3`, `authlib`) are optional extras, not core requirements. Tests mock the import layer.
- **Empty-state must not error.** The dashboard renders an "empty state" message when no certificates exist.
- **Public paths are unauthenticated.** `/healthz`, `/metrics`, `/static`, and the login flow (`/login`, `/auth/*`) stay open when auth is enabled. **`/api/*` requires auth** — route-level checks in addition to middleware (BC-057). `/metrics` can be gated with `CERT_WATCH_METRICS_TOKEN` for bearer token auth (BC-056).
- **Environment-driven config.** All settings via env vars (see README). No config files.
- **`CERT_WATCH_ALLOW_PRIVATE_IPS`** — defaults to `1` (private IP scanning enabled). Set to `0` to block RFC 1918 / ULA hosts. Loopback and link-local remain blocked regardless.
- **`CERT_WATCH_DNS_SERVERS`** — comma-separated list of DNS server IPs for hostname resolution during scans. When set, queries are sent directly to these servers (UDP port 53, A/AAAA records) instead of using the system resolver. Falls back to system resolver if custom DNS returns no results. Useful for resolving internal hostnames via domain controllers.
- **`CERT_WATCH_TRUST_PROXY`** — set to `1` to extract client IP from `X-Forwarded-For` / `X-Real-IP` headers for rate limiting. Optionally configure `CERT_WATCH_TRUSTED_PROXIES` (comma-separated IPs) to trust specific proxy IPs.
- **`CERT_WATCH_METRICS_TOKEN`** — when set, `/metrics` requires `Authorization: Bearer <token>` header. Without this, `/metrics` is open (backward compat).
- **Spec acceptance criteria are the boundary.** Don't add features beyond the spec without a tracked breadcrumb or plan entry.

## Known issues (open breadcrumbs)

1 open breadcrumb: 0 critical, 0 high, 1 medium (deferred), 0 low.

- **BC-031** (medium, deferred) — Add PostgreSQL and MSSQL support alongside SQLite

### Recently resolved

- **BC-048** (medium) — Fleet pivot views load full inventory into memory (resolved: SQL-level GROUP BY aggregation for summaries; entries lazy-loaded via `/api/pivot/{pivot}/{key}` on expand; `get_pivot_group_entries()` helper)
- **BC-049** (medium) — In-memory rate limiting not shared across workers (resolved: SQLite-backed `rate_limits` table with JSON timestamps; `_init_rate_db()` at startup; graceful fallback to in-memory on DB errors)
- **BC-058** (medium) — OAuth userinfo fallback bypasses ID token verification (resolved: auth fails instead of silently falling back to userinfo when ID token verification fails)
- **BC-056** (medium) — /metrics endpoint exposes internal infrastructure without authentication (resolved: `CERT_WATCH_METRICS_TOKEN` gates with bearer token auth)
- **BC-055** (medium) — Rate limiter trusts X-Forwarded-For implicitly (resolved: `CERT_WATCH_TRUST_PROXY` + `CERT_WATCH_TRUSTED_PROXIES` env vars)
- **BC-054** (medium) — Empty string accepted as valid auth/CSRF secret (resolved: empty strings treated as unset)
- **BC-053** (medium) — DNS rebinding window between SSRF check and TLS connection (resolved: pinned IP from SSRF check passed through to scan)
- **BC-052** (medium) — /healthz loads full scan_history into memory (resolved: targeted SQL `ORDER BY scanned_at DESC LIMIT 1`)
- **BC-057** (low) — /api/audit endpoint has no route-level auth enforcement (resolved: all API read endpoints have route-level auth checks)
- **BC-050** (low) — /metrics endpoint loads full inventory into memory (resolved: targeted SQL queries for cert/host counts)
- **BC-051** (low) — A+ posture grade unreachable from scans (resolved: `_probe_hsts()` HTTP HEAD check on port 443)
- **BC-047** (medium) — Dashboard and healthz still load full inventory into memory (resolved: `healthz` uses targeted `COUNT(*)` queries; `list_unified_entries_page()` applies filtering/sorting/pagination so only the page slice is materialized; `grouped=0` fast path avoids loading full dataset)
- **BC-045** (low) — OAuth state smuggled in `AuthResult.error` field (resolved: dedicated `oauth_state` field; all callers updated)
- **BC-046** (low) — `init_schema` called redundantly on every repository instantiation (resolved: `SqliteHostRepository` and `SqliteCertificateRepository` no longer auto-call `init_schema`; callers/tests explicitly initialize)
- **BC-044** (medium) — Unbounded `scan_history` and `alerts` queries load all rows into memory (resolved: SQL-level pagination, `list_alerts_with_subject` and `list_scan_history` accept `page`/`limit`; total count helpers; HTML pagination controls)
- **BC-042** (medium) — posture.py test coverage and scan_posture wiring (resolved: 37 tests covering all grading rules, storage, tie-breaking; store_scanned() calls _evaluate_and_store_posture())
- **BC-039** (low) — Empty-state markup inconsistent across templates (resolved: standardized on .cw-panel.cw-empty-state pattern; fixed duplicate class attribute bug in scan_history.html)
- **BC-037** (low) — Dashboard inline styles unmaintainable (resolved: all static inline styles extracted to CSS classes in tokens.css; only dynamic CSS custom property bindings remain)
- **BC-041** (low) — Auth test _reload_app module state pollution (resolved: autouse fixture saves/restores config/auth/app module dicts; root cause was class-identity drift from importlib.reload)
- **BC-038** (low) — Every Jinja2 template duplicates the 30-line svg_icon macro (resolved: extracted to `macros/icons.html`, all 4 templates use `{% import %}`)
- **BC-035** (medium) — database.py monolith decomposed into database/ package (resolved: schema.py + repo.py + queries.py + connection.py + migration runner)
- **BC-040** (medium) — Working tree uncommitted database.py decomposition (resolved: already committed in prior session)
- **FEAT-006** (low) — Database migration tooling (resolved: Plan 009 — minimal in-repo migration runner instead of Alembic)
- **BC-033** (low) — Dashboard grouping by cert fingerprint with per-host status (resolved: fingerprint-based grouping with expand/collapse, host count badge, status summary)
- **BC-036** (medium) — No integration test for openssl s_client scan path (resolved: 3 integration tests with real TLS server + openssl subprocess)

- **BC-016** (high) — Deploy lag: code current, ops push needed for CI
- **BC-017** (medium) — E2E test now asserts host row + scan-history failure
- **BC-027** (low) — openssl s_client fallback opens second TLS connection per scan (resolved: single-connection strategy)
- **BC-028** (low) — duplicate of BC-027
- **BC-029** (low) — REST API pagination lacks HATEOAS navigation links (resolved: added self/next/prev links)
- **BC-030** (low) — app.py decomposition (resolved: already complete at ~121 lines)
- **BC-032** (low) — Structured JSON logging for observability integration (resolved: `CERT_WATCH_LOG_FORMAT=json`)
- **BC-034** (low) — Owner/contact field with alert routing and renewal status (resolved: schema + API + alerts + dashboard)
- **BC-023** (low) — DER-based issuer/subject comparison in validate_chain_order
- **BC-024** (low) — Trust anchor CA validation (BasicConstraints check)
- **BC-025** (low) — Private IP rejection includes CERT_WATCH_ALLOW_PRIVATE_IPS hint

### Recently implemented features

- **HSTS probe during scans (BC-051)** — `scan_host()` now makes an HTTP HEAD request on port 443 to detect `Strict-Transport-Security` header via `_probe_hsts()`. HSTS result passed to `evaluate_posture()`. A+ posture grade now achievable from scans.
- **DNS rebinding prevention (BC-053)** — `_is_blocked_host_check()` returns a pinned IP from SSRF check. `scan_host()` accepts `pinned_ip` parameter, passing it through to `_open_tls_connection()` and `_scan_via_openssl()`. Both add-host and CSV import flows pin the resolved IP.
- **Proxy-aware rate limiting (BC-055)** — `CERT_WATCH_TRUST_PROXY=1` enables X-Forwarded-For extraction for rate limiting. `CERT_WATCH_TRUSTED_PROXIES` limits which proxy IPs to trust. `_extract_client_ip()` in middleware.py.
- **Metrics bearer token auth (BC-056)** — `CERT_WATCH_METRICS_TOKEN` env var gates `/metrics` with `Authorization: Bearer <token>`. Backward compatible: unset = open. `check_metrics_token()` helper in middleware.py.
- **Route-level API auth (BC-057)** — All API read endpoints (`/api/certificates`, `/api/hosts`, `/api/alerts`, `/api/audit`, `/api/export/*`) have route-level auth checks via `_require_api_auth()`. Defense-in-depth on top of middleware.
- **Targeted /healthz query (BC-052)** — `/healthz` now uses `SELECT scanned_at, status FROM scan_history ORDER BY scanned_at DESC LIMIT 1` instead of `list_scan_history()`. Uses cached `_connect()` instead of throwaway connection.
- **Targeted /metrics query (BC-050)** — `/metrics` now iterates a cursor over leaf certificates instead of calling `list_dashboard_rows()`. Host/cert/expired counts via targeted SQL.
- **Empty secret rejection (BC-054)** — `CERT_WATCH_AUTH_SECRET` and `CERT_WATCH_CSRF_SECRET` treat empty strings as unset, falling back to `secrets.token_hex(32)`.
- **OAuth ID token enforcement (BC-058)** — When an ID token is present but verification fails, authentication is rejected rather than silently falling back to the userinfo endpoint. Userinfo is only used when no ID token was returned.
- **Fingerprint grouping (BC-033)** — Dashboard groups hosts sharing the same leaf certificate fingerprint into expandable rows with host count badge and status summary. Toggle with `grouped=0` query param.
- **Scan retry** — `scan_host()` retries transient failures (connection refused, timeout) up to 2 times with exponential backoff.
- **Fast scheduler retry** — When hosts have no successful scan yet, the scheduler retries every hour instead of waiting for the daily cycle.
- **Scan result diffing** — On renewal (fingerprint change), `replace_scanned()` logs what changed (expiry shift, SAN changes, issuer change).
- **Confirmation dialogs** — Destructive actions ("Clear results", "Delete host", "Remove trust anchor") require `confirm()` before submitting.
- **Rate limit headers** — API responses include `X-RateLimit-Remaining`, `X-RateLimit-Limit`, and `Retry-After` (on 429).
- **Single-connection TLS scan** — On Python < 3.13, `scan_host()` uses a single `openssl s_client` call for both leaf and chain (instead of opening a second connection). Falls back to Python TLS for leaf-only if openssl is unavailable.
- **System CA chain validation** — `chain_status()` checks the system trust store, so LE and other public CA chains show as "public" even when the root is omitted.
- **Scan failure UX** — Scan failures show as yellow warnings (not red errors) with human-friendly messages.
- **Rate limit enforcement** — API middleware returns 429 on rate limit exceeded (not just headers).
- **app.py decomposition** — Split ~1500-line monolith into `middleware.py`, `filters.py`, and `routes/` modules.
- **Host tags** — `tags` column on hosts for categorization and filtering.
- **Per-host scan scheduling** — `scan_interval_hours` column allows different scan frequencies per host.
- **Webhook test endpoint** — `POST /api/webhook/test` sends a test payload to verify webhook config.
- **Expiry digest mode** — `ALERT_DIGEST_ONLY=1` sends a single daily summary instead of per-cert alerts.
- **SQLite rate limiting (BC-049)** — `rate_limits` table stores sliding-window timestamps as JSON. `_init_rate_db()` at startup configures DB path. `check_rate_limit()` uses SQLite for cross-worker sharing with graceful in-memory fallback on DB errors. Migration 0003.
- **Fleet pivot lazy loading (BC-048)** — `list_fleet_pivot()` uses SQL-level GROUP BY for summaries (count, worst urgency, earliest expiry). Entries loaded on demand via `GET /api/pivot/{pivot}/{key}`. Dashboard template fetches group entries via AJAX on expand.
- **Webhook retry** — `process_pending()` retries failed alerts up to 3 times with exponential backoff.
- **Host export CSV** — `GET /api/export/hosts.csv` for bulk host list export.
- **SQL-level pagination** — `list_dashboard_rows()` accepts sort/pagination params for efficient queries.
- **HATEOAS pagination links** — All paginated API endpoints (`/api/certificates`, `/api/hosts`, `/api/alerts`) now include `self`, `next`, `prev` links.
- **Owner/contact and renewal status** — `hosts` table has `owner_name`, `owner_email`, `owner_slack`, `renewal_status`. Alerts route to owners. `PATCH /api/hosts/{id}/owner` to update. Dashboard shows owner chip and renewal status.
- **Structured JSON logging** — `CERT_WATCH_LOG_FORMAT=json` env var switches from text to JSON logs with `timestamp`, `level`, `logger`, `message` fields.
- **Authorization gate (Plan 010 Slice 1)** — `CERT_WATCH_ALLOWED_GROUPS` and `CERT_WATCH_ALLOWED_ROLES` env vars restrict access to members of specified groups/roles when auth is enabled. `AuthResult` carries `groups` and `roles`. `read_secret()` helper supports Docker/K8s `*_FILE` secret convention. `check_authz()` enforces the gate at login and OAuth callback.
- **PEM download endpoint** — `GET /api/certificates/{id}/pem` returns raw PEM bytes with `Content-Disposition: attachment`. The detail page "Download PEM" button now links here instead of the JSON API.
- **Local break-glass admin (Plan 010 Slice 2)** — `CERT_WATCH_LOCAL_ADMIN_USER` and `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` enable a local admin account that works regardless of external provider state. Scrypt password hashing (`hashlib.scrypt`). `cert-watch hash-password` CLI for generating hashes. Break-glass login bypasses group/role gate (implicit admin) and emits WARNING log + audit row with `break_glass=true`. `_CompositeProvider` tries local admin first, then delegates to the primary provider. Login form shows username/password when local admin or form-login provider is configured.
- **Shared svg_icon macro (BC-038)** — Extracted all icon macros to `templates/macros/icons.html`. All 4 main templates now use `{% import "macros/icons.html" as icons %}`.
- **Fleet dashboard lenses (Plan 006 Phase 5)** — Dashboard pivot views: `?view=issuer`, `?view=owner`, `?view=renewal_method`. Groups entries with aggregate stats (count, worst urgency, earliest expiry). Expandable detail rows per group. `list_fleet_pivot()` in queries.py.
- **JWKS cache TTL** — `OAuthProvider` JWKS cache now expires after a configurable TTL (default 24h, `CERT_WATCH_JWKS_CACHE_TTL`). On `InvalidKeyIdError`, the cache is force-refreshed and token verification retried once.
- **CT reconciliation (Plan 006 Phase 3)** — `ct_reconciliation()` compares CT log hostnames against tracked hosts for a domain. `GET /api/ct/reconciliation?domain=…` returns tracked/ct/gap hostnames and coverage percentage. 8 tests with mocked crt.sh.
- **Audit log (Plan 008)** — Append-only `audit_log` table, `record_audit()` helper, all mutating routes instrumented. `GET /audit` (HTML) and `GET /api/audit` (JSON, paginated, filterable). Break-glass logins flagged `break_glass=true`.
- **Operator runbook (Plan 011)** — `docs/runbook.md` covers deploy, upgrade (with auto-migration backup), backup/restore, scan troubleshooting, full config reference, auth wiring, secure profile, metrics exposure decision, scale ceiling with BC-031 trigger.

## Architecture notes

- **`auth.py`** — `AuthProvider` protocol with `NoAuthProvider`, `LDAPAuthProvider`, `OAuthProvider`, `LocalAdminProvider`. `AuthResult` carries `groups`, `roles`, and `oauth_state` (signed state for OAuth callback verification) for authorization. `check_authz()` enforces the group/role gate when `CERT_WATCH_ALLOWED_GROUPS` or `CERT_WATCH_ALLOWED_ROLES` is configured. `LocalAdminProvider` checks credentials against `CERT_WATCH_LOCAL_ADMIN_USER`/`CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` (scrypt, `*_FILE` convention). `_CompositeProvider` delegates: local admin first, then primary provider. `OAuthProvider._verify_id_token()` performs full JWKS-based JWT signature verification using `joserfc` + `authlib.oidc.core.CodeIDToken` (iss/aud/exp/nonce/at_hash validation). When ID token verification fails, auth is rejected rather than silently falling back to userinfo (BC-058). OIDC discovery fetches `jwks_uri`; JWKS is cached per provider instance with TTL-based expiration (default 24h, `CERT_WATCH_JWKS_CACHE_TTL` env var). On `InvalidKeyIdError`, the JWKS cache is force-refreshed and verification retried once. Empty `CERT_WATCH_AUTH_SECRET`/`CERT_WATCH_CSRF_SECRET` treated as unset (BC-054). Session management via HMAC-signed cookies (`cw_auth`). Separate from CSRF cookies (`cw_sid`). `read_secret()` in `config.py` resolves `$NAME` or `$NAME_FILE` for all secret env vars.
- **`database.py`** — Repository pattern (`CertificateRepository`, `AlertRepository`, `SqliteHostRepository`). `replace_scanned()` does atomic delete+insert in one transaction. `init_schema()` is idempotent with column migration.
- **`scan.py`** — `scan_host()` returns `ScannedEntry | ScanError`. Accepts `pinned_ip` parameter to prevent DNS rebinding (BC-053). `_probe_hsts()` checks for HSTS header on port 443 (BC-051). On Python < 3.13, `_scan_via_openssl()` makes a single `openssl s_client` call for both leaf and chain (no second connection). `store_scanned()` delegates to `replace_scanned()` for path-based calls and also calls `_evaluate_and_store_posture()` to compute and persist TLS posture grades.
- **`posture.py`** — `evaluate_posture()` computes TLS posture grade (A+/A/B/C/F) from certificate properties. Covers key size, SHA-1 signatures, ECDSA curves, chain completeness, TLS version, validity length, self-signed, OCSP must-staple, HSTS. A+ requires TLS 1.3 + HSTS (now achievable via `_probe_hsts()`). 37 unit + integration tests.
- **`alerts.py`** — `evaluate_thresholds()` checks against LEAF_THRESHOLDS (14,7,3,1) and CHAIN_THRESHOLDS (30,14,7). Per-host custom thresholds via `hosts.threshold_days`. Owner info included in alert messages; `extra_recipients` routes to owner email. `process_pending()` tries SMTP then webhook.
- **`scheduler.py`** — Daemon thread with `threading.Event.wait()` for daily scheduling. `run_scan_now()` for immediate cycles.
- **`app.py`** — FastAPI with lifespan (scheduler start/stop), CSRF middleware, auth middleware, rate limiting.
- **`middleware.py`** — CSRF protection, rate limiting (SQLite-backed sliding window, BC-049), auth middleware. `_init_rate_db(db_path)` at startup. `_extract_client_ip()` respects `X-Forwarded-For` when `CERT_WATCH_TRUST_PROXY=1` (BC-055). `check_metrics_token()` gates `/metrics` with `CERT_WATCH_METRICS_TOKEN` bearer auth (BC-056). `/metrics` stays in `is_public_path()` for auth middleware bypass; token check is at route level.

## Breadcrumbs / memory

Project is registered with agent-notes (postgres-backed). Use the `mcp__breadcrumb__*` / `mcp__memory__*` / `mcp__search__*` tools from Claude Code; resolves via path `/projects/cert-watch`. Local mirror directories: `breadcrumbs/active/`, `breadcrumbs/resolved/`, `plans/`, `reflections/`.

## CI workflows

- `ci.yml` — ruff + pytest (unit) on every push/PR
- `e2e.yml` — Playwright E2E on every push/PR
- `release.yml` — on `main`: multi-arch image build → GHCR → commit kustomize tag bump (skips itself via `paths-ignore`)
