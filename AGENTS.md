# AGENTS.md

Conventions and quick reference for agents (and humans) working on cert-watch.

## Versioning

Version comes from `git describe --tags --abbrev=0` at Docker build time, injected via `GIT_TAG` and `GIT_COMMIT` build args. The Dockerfile writes these to `src/cert_watch/_version.txt`, and `__init__.py` reads it at import time (stripping any `v` prefix). The UI shows `v{version} ({commit})` in the header. Healthz also includes both.

When tagging a release, update `pyproject.toml` version and `src/cert_watch/_version.txt` to match the new tag number (without the `v` prefix). The release workflow stamps `_version.txt` at build time from `GIT_TAG`, so the file in the repo is a fallback for local dev.

## Why this project exists

cert-watch is a "traditional"-build comparison point for [software-factory-2](https://github.com/hraedon/software-factory-2). Same MVP spec; hand-rolled (or single-shot agent-built) instead of factory-orchestrated. The repo at `hraedon/cert-watch-factory-failed` is the prior factory attempt — kept for comparison, not for reuse.

## Orient

1. **Read the spec.** `docs/spec/wi_*.md` — one file per FR or interface module, with explicit acceptance criteria. The spec is the contract.
2. **Read the scaffold.** `src/cert_watch/` — `app.py` (FastAPI app factory + lifespan), `routes/` (HTTP handlers), `middleware.py` (security middleware + FastAPI deps), `templates/`, `static/`, plus feature modules: `certificate_model.py`, `cert_chain.py`, `scan.py`, `upload.py`, `alerts.py`, `scheduler.py`, `posture.py`, `ct_lookup.py`, `config.py`. The `auth/` package and `database/` package hold the two largest concerns (see Architecture notes).
3. **Note the deploy story.** See `deploy/` (k8s + Argo CD, docker compose, systemd, IIS). Argo CD watches `deploy/k8s/`; CI bumps the image tag there on every merge to `main`. Do not commit changes to `deploy/k8s/kustomization.yaml` in feature PRs. Windows/IIS hosting (`deploy/iis/`, `scripts/install-windows.ps1`) fronts uvicorn via HttpPlatformHandler or an ARR reverse proxy; the app is cross-platform (the only OS-specific bit is the `CERT_WATCH_DATA_DIR` default — see `config._default_data_dir`).

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q            # unit tests (excludes e2e + integration by default)
.venv/bin/ruff check .         # lint

# Auth extras (optional — tests mock these, but needed for real usage):
uv pip install -e ".[auth-ldap]"   # LDAP/AD
uv pip install -e ".[auth-oauth]"  # OAuth/OIDC (Entra, Google)
uv pip install -e ".[auth]"        # both

# Integration tests (need a real openssl binary; opt-in):
.venv/bin/pytest -m integration -q

# E2E:
uv pip install -e ".[e2e]" && .venv/bin/playwright install --with-deps chromium
.venv/bin/pytest -m e2e tests/e2e -q
```

The default pytest config (`pyproject.toml` `addopts`) runs `-m 'not e2e and not integration'`. The `@integration` openssl-`s_client` tests are environment-sensitive (need openssl on PATH + a local TLS server) and are excluded from the default run. E2E tests on the dev host need `libatk-1.0-0t64 libatk-bridge-2.0-0t64 libcups2t64 libxcomposite1 libxdamage1 libxrandr2 libgtk-3-0t64 libasound2t64` (one-time sudo install). CI handles this via `playwright install --with-deps`.

## Conventions

- **Single SQLite file** at `${CERT_WATCH_DATA_DIR}/cert-watch.sqlite3` (default `/var/lib/cert-watch`). Deployment is single-writer; `Recreate` rollout strategy in k8s. WAL mode enabled.
- **PKCS#12 (`.pfx`) and PKCS#7 (`.p7b`/`.p7c`) support extends the original spec.**
- **Auth is optional.** When `AUTH_PROVIDER` is unset, all routes are open (backward compat). Set to `ldap` or `oauth`/`entra` to enable. Auth deps (`ldap3`, `authlib`) are optional extras, not core requirements. Tests mock the import layer. A misconfigured provider raises `ValueError` at startup rather than silently degrading to open.
- **Route-level auth via dependencies.** Use `Depends(require_auth)` / `Depends(require_write)` from `middleware.py` for `/api/*` routes — never hand-roll session/CSRF checks in handlers. `require_auth` returns `""` (not 401) under `NoAuthProvider` so the "auth off = open" contract holds. Rate-limited API routes use `Depends(rate_limit("<prefix>", max, window))`; only form-POST/redirect routes (`/hosts`, `/login`, `/upload`) keep a manual `check_rate_limit` (a dependency can't return a redirect).
- **Empty-state must not error.** The dashboard renders an "empty state" message when no certificates exist.
- **Public paths are unauthenticated.** `/healthz`, `/metrics`, `/static`, and the login flow (`/login`, `/auth/*`) stay open when auth is enabled. **`/api/*` requires auth.** `/metrics` can be gated with `CERT_WATCH_METRICS_TOKEN` for bearer token auth.
- **CSP `script-src` allows `'unsafe-inline'`** (BC-075). The nonce approach (Plan 020 S4) was reverted: templates use ~24 inline event-handler attributes (`onclick=`) that CSP nonces can't whitelist, so dropping `'unsafe-inline'` broke every button. Proper hardening (handlers → `addEventListener` + nonce) is deferred to the design-session template rewrite. XSS mitigations today are `escHtml()` + the urgency-class whitelist. `security_headers_middleware` still sets CSP + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY`.
- **CSRF is double-submit cookie.** Token accepted via the `x-csrf-token` header or `_csrf_token` form field only — never the query string (BC-070).
- **Environment-driven config.** All settings via env vars (see README). GUI settings (`/settings`) persist to `kv_store`; **env vars always win** over GUI values.
- **`CERT_WATCH_ALLOW_PRIVATE_IPS`** — defaults to `1`. Set to `0` to block RFC 1918 / ULA hosts. Loopback and link-local remain blocked regardless.
- **`CERT_WATCH_DNS_SERVERS`** — comma-separated DNS server IPs for direct hostname resolution during scans (UDP/53, A/AAAA). Falls back to system resolver. Useful for internal hostnames via domain controllers.
- **`CERT_WATCH_TRUST_PROXY`** — set to `1` to extract client IP from `X-Forwarded-For` / `X-Real-IP` for rate limiting. Optionally `CERT_WATCH_TRUSTED_PROXIES` (comma-separated) to trust specific proxies.
- **`CERT_WATCH_METRICS_TOKEN`** — when set, `/metrics` requires `Authorization: Bearer <token>`.
- **`CERT_WATCH_ALLOW_UNAUTH`** — set to `1` to suppress the unauthenticated-mode startup warning and first-run setup redirect (dev/air-gapped).
- **`CERT_WATCH_HISTORY_RETENTION_DAYS`** (default `365`), **`CERT_WATCH_ALERT_RETENTION_DAYS`** (default `90`), **`CERT_WATCH_AUDIT_RETENTION_DAYS`** (default `90`) — days of history/alerts/audit to keep; purged at startup + daily; `0` disables.
- **`CERT_WATCH_DRIFT_ALERTS`** — `0` disables drift detection alerts (default `1`). Fires on issuer changes, key-size drops, SHA-1 downgrades, posture grade drops, TLS version downgrades.
- **`CERT_WATCH_CHECK_REVOCATION`** — `1` enables OCSP/CRL reachability checks during posture evaluation (default `0`). Findings are warnings, not grade penalties.
- **Spec acceptance criteria are the boundary.** Don't add features beyond the spec without a tracked breadcrumb or plan entry.

## Known issues & plan status

Breadcrumbs are tracked in **agent-notes** (postgres-backed) and mirrored as markdown under `breadcrumbs/active/` and `breadcrumbs/resolved/`. The `.md` files use YAML frontmatter (`identifier`/`title`/`kind`/`status`/`severity`), so `agent-notes breadcrumb sync` ingests them. Don't keep a changelog here — query the source of truth:

```bash
agent-notes breadcrumb find --path /projects/cert-watch --status open --json
agent-notes search all "<topic>" --path /projects/cert-watch --json
# re-import after editing files (active/ is non-standard, so sync it explicitly):
agent-notes breadcrumb sync --from-files breadcrumbs/active --path /projects/cert-watch --create-missing-vocab
agent-notes breadcrumb sync --path /projects/cert-watch --create-missing-vocab   # default dir covers resolved/
```

Unresolved backlog (as of 2026-06-02): **BC-031** (PostgreSQL/MSSQL backend — deferred), **BC-071** (OAuth userinfo nonce binding — partial), **BC-073** (grouped dashboard full-load — partial, low), **BC-075** (CSP `script-src` `'unsafe-inline'`; deferred to design rewrite), **BC-081** (no session revocation), **BC-082** (kv_store plaintext secrets at rest), **BC-083** (open-by-default *auth* posture — agreed direction: secure-by-default + `CERT_WATCH_ALLOW_UNAUTH` opt-out; breaking, not yet implemented), **BC-086** (read-only vs read-write role tier — agreed design, not yet implemented). Resolved: BC-084 (A+ non-443 posture), BC-085 (3.13 container). Resolved breadcrumbs live in the DB as history.

SSRF/scan policy is `CERT_WATCH_ALLOWED_SUBNETS` (BC-080): a CIDR allowlist scoping which **private** ranges are scannable (public always allowed; loopback/link-local/metadata always blocked). The global `allow_private` default was deliberately **not** flipped (breaks internal-monitoring on upgrade for low payoff — the scan reads cert metadata, not bodies/creds).

Plan status:
- **Plan 018** (auth/data consolidation): Phase A (A1/A2/A3) **done**; B2 (dashboard queries) **done**; **B1 (SecurityContext + create_app) — core done**: signing material is an immutable `SecurityContext` on `app.state` (`cert_watch.security`), `create_app(security=, auth_provider=, settings=)` injects deps, the session/CSRF request path reads `app.state.security`, and the test harness (`conftest`, `reload_app`) is reload-free. Two documented tails remain: the lifespan still seeds the module globals to back the OAuth-state signing path (no request available), and ~8 individual test files still use inline `importlib.reload` (some legitimately test import/lifespan behavior).
- **Plan 020** (security middleware consolidation): S1 (= 018 A3) **done**; S2 (`rate_limit` dependency) **done**; **S4 (CSP nonces) reverted** (BC-075 — broke inline event handlers; deferred to the design rewrite); **S3 (audit side-effect) and S5 (`get_db` dependency) deferred** — low leverage (S3 undercut by dynamic audit details; S5 is ~40 mechanical edits for a cosmetic convention).
- **Plan 021** (auth module decomposition): **done** — `auth.py` is now the `auth/` package.

## Architecture notes

- **`security.py` + `create_app`** — `SecurityContext(signing_key, csrf_secret)` is an immutable dataclass resolved once in the lifespan (from `config.resolve_or_persist_secret`, persisted to `data_dir/.auth_secret`) and stored on `app.state.security`. `app.create_app(*, security=None, auth_provider=None, settings=None)` is the factory; `None` deps are resolved from env in the lifespan (production / the module-level `app`), explicit deps are injected (tests). Session signing (`auth.session`) and CSRF (`middleware`) functions take an optional `security` param; the request path passes `_request_security(request)` (reads `app.state.security`), and the module-level globals remain only as an import-time fallback for request-less paths (OAuth state signing, direct unit-test calls).
- **`auth/` package** — decomposed from the former `auth.py` monolith (Plan 021). `session.py` (HMAC-signed `cw_auth` session cookies, `create_session`/`validate_session`, `set_signing_key`, signed OAuth state), `protocol.py` (`AuthProvider`, `AuthResult`, `NoAuthProvider`), `local_admin.py` (`LocalAdminProvider`, `_CompositeProvider`, scrypt hashing with `*_FILE` secret convention; `_dummy_verify()` equalizes timing on username mismatch — BC-072), `ldap_provider.py` (`LDAPAuthProvider`; STARTTLS uses `CERT_REQUIRED`), `oauth_provider.py` (`OAuthProvider` with full JWKS-based ID-token verification, TTL-cached JWKS, `CERT_WATCH_JWKS_CACHE_TTL`; auth fails rather than silently falling back to userinfo when ID-token verification fails; userinfo fallback logs a warning — BC-071), `factory.py` (`build_auth_provider`, `check_authz` group/role gate). `__init__.py` re-exports the full public API, so all callers still `from cert_watch.auth import ...`. Local admin credentials also sourced from `kv_store` (setup wizard) when env vars are unset, folded into `build_auth_provider` (Plan 018 A1).
- **`database/` package** — repository pattern (`SqliteCertificateRepository`, `SqliteAlertRepository`, `SqliteHostRepository`, `SqliteAlertGroupRepository`, `SqliteTrustAnchorRepository`) + `queries.py` (dashboard/aggregate helpers) + `connection.py` + `schema.py` + migration runner. Migrations 0001–0010 (audit log, rate limits, tls_verified, composite indexes, cert_tags, kv_store, alert_groups, cert_history, alert extra_recipients). **Dashboard data path is SQL-paginated** (Plan 018 B2): `list_dashboard_page()` (true SQL WHERE/ORDER BY/LIMIT/OFFSET), `list_dashboard_grouped_page()` (fingerprint grouping with host count + worst urgency), `get_cert_detail()` (targeted JOIN). New query methods own their `_connect()` and return plain dicts — no `sqlite3.Row` leaks into routes (backend-portability discipline; see BC-031). `_list_unified_entries_raw()` survives behind the grouped path's cross-host fingerprint search. `delete_certificate_cascade()` cleans `alerts`, `scan_posture`, `cert_history`, and `alert_group_certs`.
- **`scan.py`** — `scan_host()` returns `ScannedEntry | ScanError`. When `pinned_ip` is None, `_scan_host_once` auto-resolves and pins the IP for DNS-rebinding hardening. `_probe_hsts()` checks the HSTS header on port 443 (pinned IP + correct SNI). `ScannedEntry.tls_verified` persisted in `scan_posture`. On Python < 3.13, `_scan_via_openssl()` makes a single `openssl s_client` call for leaf + chain. `store_scanned()` delegates to `replace_scanned()`, evaluates/stores posture, records cert history, and creates drift alerts.
- **`posture.py`** — `evaluate_posture()` grades A+/A/B/C/F from cert properties (key size, SHA-1, ECDSA curves, chain completeness, TLS version, validity length, self-signed, OCSP must-staple, HSTS). A+ requires TLS 1.3 + HSTS. `check_revocation_endpoints()` checks OCSP/CRL reachability (opt-in).
- **`alerts.py`** — `evaluate_thresholds()` against LEAF_THRESHOLDS (14/7/3/1) and CHAIN_THRESHOLDS (30/14/7); per-host `threshold_days`. `resolve_all_group_recipients()` batches group routing in ≤3 queries (Plan 018 A2); `evaluate_all_certs()` merges group + owner recipients into `extra_recipients`. `process_pending()` tries SMTP then webhook with retry.
- **`scheduler.py`** — daemon thread with `threading.Event.wait()` for daily scheduling; `run_scan_now()` for immediate cycles; runs history/alert/audit purges at startup + daily.
- **`app.py`** — FastAPI app + lifespan (scheduler start/stop, persisted signing keys via `config.resolve_or_persist_secret`, setup detection, auth provider build). Middleware stack: CSRF/session, auth, rate-limit headers, security headers (CSP nonce), setup redirect.
- **`middleware.py`** — CSRF (double-submit, header/form only — BC-070), SQLite-backed rate limiting (`check_rate_limit`, `_init_rate_db`), proxy-aware `_extract_client_ip` (`CERT_WATCH_TRUST_PROXY`), `check_metrics_token`, and the FastAPI deps `require_auth` / `require_write` / `rate_limit(...)`. `security_headers_middleware` sets the per-request CSP nonce. `set_csrf_secret()` for lifespan-time key rotation. `setup_redirect_middleware` redirects HTML pages to `/setup` on fresh installs (never `/api/*` or public paths).
- **`audit.py`** — append-only `audit_log`; `resolve_source_ip()` uses proxy-aware extraction. Break-glass logins flagged `break_glass=true`.

## Breadcrumbs / memory

Project is registered with agent-notes (postgres-backed), resolving via path `/projects/cert-watch`. Use the `agent-notes` CLI (or the `/find-breadcrumb`, `/file-breadcrumb`, `/update-breadcrumb` skills). Local mirror directories: `breadcrumbs/active/`, `breadcrumbs/resolved/`, `plans/`, `reflections/`. **Search before filing** (dedup is the store's main failure mode).

## CI workflows

- `ci.yml` — ruff + pytest (unit) on every push/PR
- `e2e.yml` — Playwright E2E on every push/PR
- `release.yml` — on `main`: multi-arch image build → GHCR → commit kustomize tag bump (skips itself via `paths-ignore`)
