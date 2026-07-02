# AGENTS.md

Conventions and quick reference for agents (and humans) working on cert-watch.

## Versioning

Version comes from `git describe --tags --abbrev=0` at Docker build time, injected via `GIT_TAG` and `GIT_COMMIT` build args. The Dockerfile writes these to `src/cert_watch/_version.txt`, and `__init__.py` reads it at import time (stripping any `v` prefix). The UI shows `v{version} ({commit})` in the header. Healthz also includes both.

When tagging a release, update `pyproject.toml` version and `src/cert_watch/_version.txt` to match the new tag number (without the `v` prefix). The release workflow stamps `_version.txt` at build time from `GIT_TAG`, so the file in the repo is a fallback for local dev.

## Why this project exists

All-in-one, self-hosted certificate-lifecycle observability for SMBs — live scanning + offline upload, chain validation, posture grading, directory auth, audit log — maintained as software people run (it is deployed in production). See `docs/positioning.md` for the full identity and landscape. Historical note: it began as a "traditional"-build comparison point for [software-factory-2](https://github.com/hraedon/software-factory-2) (same MVP spec, hand-/single-agent-built; the prior factory attempt is at `hraedon/cert-watch-factory-failed`) — that origin is documented, but it is no longer what the tool is for.

## Orient

1. **Read the spec.** `docs/spec/wi_*.md` — one file per FR or interface module, with explicit acceptance criteria. The spec is the contract.
2. **Read the scaffold.** `src/cert_watch/` — `app.py` (FastAPI app factory + lifespan), `routes/` (HTTP handlers), `middleware.py` (security middleware + FastAPI deps), `templates/`, `static/`, plus feature modules: `certificate_model.py`, `cert_chain.py`, `scan.py`, `upload.py`, `alerts.py`, `scheduler.py`, `posture.py`, `config.py`. The `auth/` package and `database/` package hold the two largest concerns (see Architecture notes).
3. **Note the deploy story.** See `deploy/` (k8s + Argo CD, docker compose, systemd, IIS). Argo CD watches `deploy/k8s/`; CI bumps the image tag there on every merge to `main`. Do not commit changes to `deploy/k8s/kustomization.yaml` in feature PRs. Windows/IIS hosting (`deploy/iis/`, `scripts/install-windows.ps1`) fronts uvicorn via HttpPlatformHandler or an ARR reverse proxy; the app is cross-platform (the only OS-specific bit is the `CERT_WATCH_DATA_DIR` default — see `config._default_data_dir`).

## Test estate (mvmcitest01)

A live cert-watch instance is deployed on `mvmcitest01` (Windows/IIS, real AD LDAP auth against `ad.hraedon.com`) for operator-paced validation — the work every reflection flagged as "never happens" because fixtures can't stand in for real certs/tags/routing.

- **Access:** passwordless ssh `cw-admin@mvmcitest01` (creds via the `agent-capability-broker` project). Remote shell is PowerShell — for multi-line Python, pipe a heredoc to `python.exe -` over stdin to avoid PS quote-mangling (inline `python -c "..."` breaks on `"\""`).
- **Layout:** app at `C:\inetpub\cert-watch` (web.config has env vars); venv `C:\ProgramData\cert-watch\venv\Scripts\python.exe`; data dir `C:\ProgramData\cert-watch` (`cert-watch.sqlite3` + WAL). HTTPS at `https://mvmcitest01.ad.hraedon.com`. **Do not read the `secrets\` subdir** (auth/csrf/ldap-bind secrets).
- **Driving it:** the CLI has no scan/add-host subcommand and there are no API keys; LDAP needs a real AD password. Seed via the real scan internals — `SqliteHostRepository.add()` + `scan_host()` + `store_scanned()` against the DB (the same path `scheduler.run_scan_now` calls), or add hosts in the UI and let the scheduler's 1-hour fast-retry scan them. `allow_private=True` (private IPs are scannable; `CERT_WATCH_ALLOW_PRIVATE_IPS=1`).
- **Seeded 2026-06-18** with 12 real hosts across `ad.hraedon.com` (DCs `mvmdc0{1,2,3}` on :636, the box on :443) and `k8s.hraedon.com` (`api.k8s.hraedon.com` :6443 + LE ingress hosts on :443). This is the estate to validate posture/readiness/renewal-analytics/alert-routing heuristics against. Treat it as read-only unless intentionally populating; never mutate the production instance without a reason.
- **WI-073 (resolved 2026-07-01):** The certifi fallback fix in `cert_chain.py` was deployed to mvmcitest01 and validated — all 7 Let's Encrypt certs now grade A (was B) with `chain_status=public` (was `incomplete`). AD CS certs remain B/incomplete as expected (private CA not uploaded as anchor). **BC-153 (resolved 2026-07-02):** `certifi` is now listed as a direct dependency in `pyproject.toml` — the fallback no longer depends on transitive availability.

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q            # unit tests (excludes e2e + integration by default)
.venv/bin/ruff check .         # lint
.venv/bin/mypy src/cert_watch  # type check — CI runs this; run locally too (it has caught real bugs the ruff+pytest loop misses)

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

**After any UI change (templates, `static/css`, view routes), run the e2e suite
locally (`pytest -m e2e tests/e2e -q --no-cov -n0`).** The default `pytest` run
excludes e2e (opt-in marker), so UI redesigns can drift from the e2e selectors
without local feedback — CI's `e2e.yml` catches it, but only after push. A local
pass keeps that loop short. (Requires the `[e2e]` extra + `playwright install`.)

### UI definition of done (the embarrassment checklist)

Every item below is a bug class that **actually shipped to production** and
survived a green test suite until the 2026-06-11 UI review caught it by
looking. Before calling UI work done:

- **View every changed page populated AND empty, dark AND light.** The visual
  baselines were empty-state-only for months; every rendered-row bug slipped
  through that hole. `tests/e2e/_seed.py` seeds a deterministic demo estate
  (also runnable standalone: `.venv/bin/python tests/e2e/_seed.py <data_dir>`),
  and `test_dashboard_populated_visual` baselines the populated dashboard.
- **Read the words on the screen.** Shipped examples: "4078expired 11 years
  ago" (redundant day-count prefix), "1 hosts" (no pluralization), raw ISO
  timestamps with the `T` separator shown to users.
- **Zero is not an alarm.** A count of 0 failures/expired renders neutral, not
  red ("Failures **0**" in crit-red shipped).
- **A utility class that isn't in tokens.css silently does nothing.** Grep
  before using one — `cw-gap-9`/`cw-gap-14` were referenced for months while
  undefined, collapsing gaps to zero ("Expiry calendarby time period").
- **Color budget:** status colors (ok/warn/crit/expired) are reserved for
  status. Chrome stays neutral; the accent is for links/focus/active only.

### Verification rituals (apply beyond UI)

- **A test you have never seen fail is a rumor.** When adding a meaningful
  test, break the code once and watch it catch. The samba-container LDAP e2e
  tests were merged 2026-06-10 with a fixture that raised `NameError` on
  contact and an assertion on copy the app never emits — broken on arrival,
  never executed by their author. The dedicated `ldap-e2e` CI job would have
  caught this on first push; it sat undetected only because the commits were
  in an unpushed local backlog. Run new tests before merging, and push so the
  gates that exist can fire. (Real-AD coverage is separate and predates this:
  `scripts/e2e/ad-login-remote.sh` drives the deployed Windows/IIS instance.)
- **Skipped is invisible.** Check the skip count in test output, not just the
  failure count. Docker-dependent tests skip silently where docker is missing;
  if a test matters, make sure some environment provably *runs* it.
- **At session end, state what you did NOT verify** — explicitly, in the
  summary. Vacuous green comes from nobody asking.

### Decisions that must be surfaced to the human

Implementation tactics are the agent's call. These are **not** — flag them
before acting, even mid-task: new runtime dependencies; schema changes;
anything touching auth/session/CSRF defaults or other security posture;
changes to public API shapes or URLs; deleting user-facing features; version
bumps/releases. (Rationale: these are the decisions with consequences the
repo's tests cannot see, and the human is accountable for them.)

**Interactive UI validation (Playwright MCP).** Separate from the e2e *test*
suite, a `playwright` MCP server is wired up for ad-hoc, agent-driven UI checks —
navigate the running app, click through flows, take screenshots — without writing
a test. It's configured in `.mcp.json` (Claude Code; pre-approved via
`.claude/settings.json`) and in the global opencode config (`mcp.playwright`).
Both run `@playwright/mcp@latest` headless+isolated against the Chromium already
installed for e2e. Use it to *see* a change before committing; use the e2e suite
to *lock it in*. Start the app first (`python -m cert_watch ...`) and point the
browser at its local URL.

**Dependency resolution:** `pyproject.toml` uses open-ended `>=` lower bounds. The resolved dependency set is locked in `uv.lock` (managed by `uv pip compile` / `uv pip install`). CI and reproducible builds should use `uv.lock` as the source of truth; a bare `pip install -e .` will re-resolve and may pull newer versions. `uv.lock` is uv's **native** lockfile (TOML, `version = 1`) — when changing dependencies, regenerate it with `uv lock` (not `uv pip compile`, which emits a requirements.txt and cannot round-trip this format).

The default pytest config (`pyproject.toml` `addopts`) runs `-m 'not e2e and not integration'` **in parallel** (`-n auto`, pytest-xdist, `--dist loadscope`). The unit suite is process- and `tmp_path`-isolated, so workers don't collide; for interactive debugging (`-s`, pdb, readable serial output) override with `-n0`. For the faster coverage core, prefix with `COVERAGE_CORE=sysmon` (Python 3.12+ `sys.monitoring`; CI sets this). Together these took the unit suite from ~273s → ~90s. Real sleeps are neutralized in unit tests by an autouse conftest fixture that no-ops `retry`'s backoff (the only legit sleeps live in the e2e suite). The `@integration` openssl-`s_client` tests are environment-sensitive (need openssl on PATH + a local TLS server) and are excluded from the default run. E2E tests on the dev host need `libatk-1.0-0t64 libatk-bridge-2.0-0t64 libcups2t64 libxcomposite1 libxdamage1 libxrandr2 libgtk-3-0t64 libasound2t64` (one-time sudo install). CI handles this via `playwright install --with-deps`.

## Conventions

- **Single SQLite file** at `${CERT_WATCH_DATA_DIR}/cert-watch.sqlite3` (default `/var/lib/cert-watch`). Deployment is single-writer; `Recreate` rollout strategy in k8s. WAL mode enabled.
- **PowerShell scripts: never embed single quotes inside double-quoted strings.** PowerShell 5.1 (the Windows default) reads `.ps1` files via the system ANSI codepage when the UTF-8 BOM is missing (e.g. GitHub zip download). Multi-byte UTF-8 sequences corrupt the parser's quote-tracking state, turning every subsequent `'` inside `"..."` into a fatal parse error. Use `" "` (escaped double quotes) in subexpressions or restructure the string. See `scripts/install-windows.ps1` header for the full note.
- **Windows/IIS: Python Install Manager is per-user only.** The Python Install Manager (default for 3.14+) installs runtimes under `%LocalAppData%\Python\`. The IIS app pool identity cannot access user profiles. `install-windows.ps1` detects this and copies the runtime to `$InstallDir\python\` (shared). The venv is built from that shared interpreter. See `deploy/iis/README.md` "Why a shared Python install" for the full rationale and dismissed alternatives.
- **PKCS#12 (`.pfx`) and PKCS#7 (`.p7b`/`.p7c`) support extends the original spec.**
- **Auth is optional.** When `AUTH_PROVIDER` is unset, all routes are open (backward compat). Set to `ldap` or `oauth`/`entra` to enable. Auth deps (`ldap3`, `authlib`) are optional extras, not core requirements. Tests mock the import layer. A misconfigured provider raises `ValueError` at startup rather than silently degrading to open.
- **BC-083: Secure-by-default (auto-provision model).** A *network-exposed* instance with no `AUTH_PROVIDER` and `CERT_WATCH_ALLOW_UNAUTH` unset **auto-provisions a local `admin`** on first run (`app._provision_initial_admin`): generated password persisted to `kv_store` (same keys as `/setup`) + written to `data_dir/initial-admin-password` (0600) and logged, so the app comes up *authenticated* rather than open. "Network-exposed" = non-loopback bind (`CERT_WATCH_HOST`) **OR** loopback + `CERT_WATCH_TRUST_PROXY=1` (IIS/nginx — the proxy republishes loopback). Bare loopback (no proxy) stays open + serves the `/setup` wizard (`needs_setup`); `CERT_WATCH_ALLOW_UNAUTH=1` forces open anywhere. **Fail-closed fallback:** if provisioning can't persist an admin, a network-exposed instance still `SystemExit`s rather than serve open. **BC-090:** `CERT_WATCH_HOST` is the source-of-truth bind — the `cert-watch` entrypoint (`__main__`) normalizes `--host`/env to what it passes uvicorn, so the exposure check can't diverge from the real bind. Skipped when a provider is injected (tests) or already resolved (LDAP/OAuth/existing local admin).
- **BC-081: Session revocation.** HMAC session tokens now embed a per-user `version` field (`{username}:{version}:{timestamp}:{nonce}:{sig}`). On validation, the stored version is checked against the `session_versions` DB table. Logout bumps the stored version (invalidating all prior sessions). Setup wizard credential creation also bumps. **WI-088 hardening: legacy old-format tokens (no version field, 3-part) and 32-character signatures are rejected; only 4/6/7-part tokens with 64-char HMAC signatures validate. CSRF token signatures are 64 chars (was 32).** Callers without a `db_path` argument skip the version check entirely. Deploying invalidates pre-existing sessions and CSRF cookies (one-time re-auth wave).
- **Route-level auth via dependencies.** Use `Depends(require_auth)` / `Depends(require_write)` from `middleware.py` for `/api/*` routes — never hand-roll session/CSRF checks in handlers. `require_auth` returns `""` (not 401) under `NoAuthProvider` so the "auth off = open" contract holds. Rate-limited API routes use `Depends(rate_limit("<prefix>", max, window))`; only form-POST/redirect routes (`/hosts`, `/login`, `/upload`) keep a manual `check_rate_limit` (a dependency can't return a redirect).
- **Empty-state must not error.** The dashboard renders an "empty state" message when no certificates exist.
- **Public paths are unauthenticated.** `/healthz`, `/metrics`, `/static`, and the login flow (`/login`, `/auth/*`) stay open when auth is enabled. **`/api/*` requires auth.** `/metrics` can be gated with `CERT_WATCH_METRICS_TOKEN` for bearer token auth.
- **CSP `script-src` uses per-request nonce** (BC-075 — resolved). All inline `on*=` handlers converted to `data-action` + delegated `addEventListener` in `base.html`; `_build_csp(nonce)` emits `script-src 'self' 'nonce-{nonce}'`. A ratchet test (`tests/test_no_inline_handlers.py`) enforces zero inline handlers. `style-src` keeps `'unsafe-inline'` (inline `style=` custom properties). XSS mitigations: `escHtml()` + urgency-class whitelist. `security_headers_middleware` sets CSP + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY`.
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
- **Lock wraps DB mutations only, never network I/O.** Functions that do both (e.g. `process_pending`, `store_scanned`) must split lock/no-lock phases — acquire the write lock for the DB transaction, release it, then perform SMTP/webhook/HTTP. See `scan.py` (`store_scanned`): posture evaluation runs before `BEGIN`, deferred webhooks fire after `COMMIT`. Wrapping a mixed function in `get_write_lock()` causes a global write-lock DoS under slow network targets.
- **Spec acceptance criteria are the boundary.** Don't add features beyond the spec without a tracked breadcrumb or plan entry.

## Known issues & plan status

Breadcrumbs are tracked in **regista** (the signed, hash-chained source of truth); the local agent-notes store is a read projection. **Do not create or hand-edit physical breadcrumb files** (`breadcrumbs/active/`, `breadcrumbs/resolved/`) — those are retired. Don't keep a changelog here — query the source of truth:

```bash
agent-notes breadcrumb find --path /projects/cert-watch --status open --json
agent-notes search all "<topic>" --path /projects/cert-watch --json
```

**Do not hand-maintain a backlog list here — it drifts.** The open backlog is generated from the DB into `OPEN_WORK_ITEMS.txt` (gitignored, local-only; regenerate with `agent-notes breadcrumb export-index --path /projects/cert-watch`). **Treat the export as stale until you regenerate it** — the generated timestamp is in its header. For the live view query the DB directly (commands above).

SSRF/scan policy is `CERT_WATCH_ALLOWED_SUBNETS` (BC-080): a CIDR allowlist scoping which **private** ranges are scannable (public always allowed; loopback/link-local/metadata always blocked). The global `allow_private` default was deliberately **not** flipped (breaks internal-monitoring on upgrade for low payoff — the scan reads cert metadata, not bodies/creds).

Plan status:
- **Plan 018** (auth/data consolidation): Phase A (A1/A2/A3) **done**; B2 (dashboard queries) **done**; **B1 (SecurityContext + create_app) — core done**: signing material is an immutable `SecurityContext` on `app.state` (`cert_watch.security`), `create_app(security=, auth_provider=, settings=)` injects deps, the session/CSRF request path reads `app.state.security`, and the test harness (`conftest`, `reload_app`) is reload-free. Two documented tails remain: the lifespan still seeds the module globals to back the OAuth-state signing path (no request available), and ~8 individual test files still use inline `importlib.reload` (some legitimately test import/lifespan behavior).
- **Plan 020** (security middleware consolidation): S1 (= 018 A3) **done**; S2 (`rate_limit` dependency) **done**; **S4 (CSP nonces) done** (BC-075 — all inline handlers converted, nonce CSP active); **S3 (audit side-effect) and S5 (`get_db` dependency) deferred** — low leverage (S3 undercut by dynamic audit details; S5 is ~40 mechanical edits for a cosmetic convention).
- **Plan 021** (auth module decomposition): **done** — `auth.py` is now the `auth/` package.
- **Plan 022** (alert channel adapters): **done** — `alert_adapters.py` with Discord, Teams, PagerDuty adapters; `send_webhook` dispatches via adapter registry; PagerDuty resolve-on-renewal wired into `store_scanned`. `ALERT_WEBHOOK_KIND` and `ALERT_PAGERDUTY_ROUTING_KEY` env vars.
- **Plan 024** (test coverage to 90%): **done — ~90% (89.7%)**, ratchet at 88. Route layer (views/api/hosts/audit) at 88–96%; middleware 89%. **2026-06-04 test-quality pass:** converted ~13 theater tests into real behavioral assertions (the cert-detail renewal-method/drift branches now actually render and are asserted — they previously 303-redirected to the dashboard and asserted 200 on the *error page*; the scheduler exception tests now drive a module-level `_run_cycle` and assert failure-isolation rather than starting a thread that never fires; the CT-reconciliation test mocks crt.sh instead of hitting the network). `certificates.py` 70→85%, `scheduler.py` 81→97%; added real SMTP-send / LDAP-connect success+failure tests for `routes/settings.py`. `scan.py` is at 99% (the openssl `s_client` chain path was extracted into `scan_conn.py`, also 99%; `scan_resolver.py` is at 98% — only defensive `except ValueError` branches on malformed resolver results remain uncovered).
- **Plan 025** (compliance/auditor report): **done** — `compliance.py` with `build_compliance_report()` (reads stored posture + certs, computes grade distribution, compliance metrics, remediation buckets), HMAC-SHA256 tamper-evident signing via `SecurityContext.signing_key`, and `verify_report_signature()` for CLI verification. Three export routes: `GET /api/reports/compliance.json` (signed JSON), `GET /api/reports/compliance.csv` (signed CSV with tamper-evidence footer), `GET /reports/compliance` (print-optimized HTML with CSS `@media print`). CLI subcommand `cert-watch verify-report <file>`. Link from Insights page. 27 tests covering aggregation, signing round-trip, tamper detection, route auth-gating, and CLI verification. Deferred: CAA metric (marked N/A — not stored per scan), native PDF (`weasyprint` optional extra).
- **Plan 049** (maintenance entry): **done 2026-06-13** — the last development plan; the project is now in maintenance mode (see the *Maintenance mode* section below). P0 decided (AD CS **declined** — see positioning.md + Plan 047 decision 4; positioning window thesis written). P2 entry-fee debt done (WI-031 settings decomposition, WI-025 bare-except triage, WI-026 SSRF integration tests, settings-POST + /readiness e2e). P3 boring ops done (real-DB migration test with dashboard-query smoke read, SC-081 freeze-time boundary tests, dependency cadence). P4 maintenance contract written. **Operator-paced tails** (need the production instance / lab, tracked separately): P1 validate analytics against the real estate, P1.3 confirm WI-024 `-wal` stability on the Windows VM, P3.2 exercise the restore runbook end-to-end. See `plans/049-maintenance-entry.md`.
- **Plan 048** (47-day regime — SC-081 readiness): **done** — Workstream 1: lifetime-relative alert thresholds (certs ≤90d use % of lifetime, long-lived unchanged), renewal-overdue detection with event dedup. Workstream 2: `renewal_analytics.py` (per-host lifetimes, lead times, cadence, automation inference), `readiness.py` (SC-081 milestone timeline, margin analysis, workload forecast), `policy_packs/cab_forum_sc081.py` (opt-in PolicySet with date-aware max-validity rules, non-grade-affecting). Workstream 3: `digest.py` (weekly renewal digest), scan-cadence finding (warns when interval >10% of lifetime). Migration 0023 adds `not_before` to `cert_history`. Nav link from Insights page.

## Architecture notes

- **`security.py` + `create_app`** — `SecurityContext(signing_key, csrf_secret)` is an immutable dataclass resolved once in the lifespan (from `config.resolve_or_persist_secret`, persisted to `data_dir/.auth_secret`) and stored on `app.state.security`. `app.create_app(*, security=None, auth_provider=None, settings=None)` is the factory; `None` deps are resolved from env in the lifespan (production / the module-level `app`), explicit deps are injected (tests). Session signing (`auth.session`) and CSRF (`middleware`) functions take an optional `security` param; the request path passes `_request_security(request)` (reads `app.state.security`), and the module-level globals remain only as an import-time fallback for request-less paths (OAuth state signing, direct unit-test calls).
- **`auth/` package** — decomposed from the former `auth.py` monolith (Plan 021). `session.py` (HMAC-signed `cw_auth` session cookies, `create_session`/`validate_session`, `set_signing_key`, signed OAuth state; BC-081: tokens now embed a per-user `version` field, checked against `session_versions` DB table on validation — logout/credential-change bumps the stored version, invalidating prior sessions), `protocol.py` (`AuthProvider`, `AuthResult`, `NoAuthProvider`), `local_admin.py` (`LocalAdminProvider`, `_CompositeProvider`, scrypt hashing with `*_FILE` secret convention; `_dummy_verify()` equalizes timing on username mismatch — BC-072), `ldap_provider.py` (`LDAPAuthProvider`; STARTTLS uses `CERT_REQUIRED`; BC-115: service conn binds after start_tls, user conn start_tls before bind; BC-118: configurable group filter via `LDAP_GROUP_FILTER` with `{group}` placeholder, default = AD transitive OID), `oauth_provider.py` (`OAuthProvider` with full JWKS-based ID-token verification, TTL-cached JWKS, `CERT_WATCH_JWKS_CACHE_TTL`; auth fails rather than silently falling back to userinfo when ID-token verification fails; userinfo fallback verifies nonce claim when present — BC-071 resolved; nonce generated in authorization request, embedded in signed state, verified in ID token claims), `factory.py` (`build_auth_provider`, `check_authz` group/role gate). `__init__.py` re-exports the full public API, so all callers still `from cert_watch.auth import ...`. Local admin credentials also sourced from `kv_store` (setup wizard) when env vars are unset, folded into `build_auth_provider` (Plan 018 A1).
- **`database/` package** — connection lifetime (WI-024): `connection._connect()` caches one connection per (thread, db_path) in a `_ThreadConnections` holder whose `__del__` closes everything when the thread exits; the cache is capped at `_MAX_CACHED_CONNECTIONS` per thread (oldest evicted + closed). Short-lived worker threads that touch the DB should still call `close_connections()` in a `finally` — the holder is the safety net, not the convention. Repository pattern (`SqliteCertificateRepository`, `SqliteAlertRepository`, `SqliteHostRepository`, `SqliteAlertGroupRepository`, `SqliteTrustAnchorRepository`) + `queries.py` (dashboard/aggregate helpers) + `connection.py` + `schema.py` + migration runner. Migrations 0001–0028 (canonical list in `migrations/registry.py`). Notable: 0006 adds a `tags` column to `certificates` (not a separate table), 0011 session_versions (BC-081), 0012 chain_incomplete (BC-108), 0013 renames tls_verified→verify_requested (BC-125), 0015 api_keys for M2M auth (Plan 039 / BC-104), 0016 chain_status (BC-100), 0017 CAA columns (BC-121), 0019 users/roles for local auth (Plan 040), 0021 event_log (Plan 044), 0023 cert_history.not_before (Plan 048), 0024 role permission_tier/scope_tag (WI-050/052), 0025 alert_group threshold_days/digest_cadence (WI-056), 0026 roles.alert_group_id joint routing (WI-061), 0027 hosts.starttls_mode (STARTTLS scanning), 0028 drop unused ct_issuer_first_seen table (WI-082). **Dashboard data path is SQL-paginated** (Plan 018 B2): `list_dashboard_page()` (true SQL WHERE/ORDER BY/LIMIT/OFFSET), `list_dashboard_grouped_page()` (fingerprint grouping with host count + worst urgency), `get_cert_detail()` (targeted JOIN). New query methods own their `_connect()` and return plain dicts — no `sqlite3.Row` leaks into routes (backend-portability discipline; see BC-031). `list_unified_entries()` delegates to `_load_unified_filtered(include_uploaded=True)` with SQL-level EXISTS subqueries (BC-073). `delete_certificate_cascade()` cleans `alerts`, `scan_posture`, `cert_history`, and `alert_group_certs`.
- **`scan.py`** — `scan_host()` returns `ScannedEntry | ScanError`. When `pinned_ip` is None, `_scan_host_once` auto-resolves and pins the IP for DNS-rebinding hardening. `_probe_hsts()` checks the HSTS header on port 443 (pinned IP + correct SNI). `ScannedEntry.verify_requested` persisted in `scan_posture` (BC-125: renamed from `tls_verified` to clarify it stores the operator config flag, not the TLS handshake outcome). On Python < 3.13, `_scan_via_openssl()` makes a single `openssl s_client` call for leaf + chain. `store_scanned()` delegates to `replace_scanned()`, evaluates/stores posture, records cert history, and creates drift alerts. `store_scanned()` accepts optional `webhook_config` — when PagerDuty, sends resolve events for replaced cert's open incidents (Plan 022 Slice 4). `scan_host_async()` and `store_scanned_async()` are `asyncio.to_thread` wrappers used by route handlers for non-blocking concurrent scans. Retry logic uses `retry.backoff_range()` (exponential strategy).
- **`posture.py`** — `evaluate_posture()` grades A+/A/B/C/F from cert properties (key size, SHA-1, ECDSA curves, chain completeness, TLS version, validity length, self-signed, OCSP must-staple, HSTS). A+ requires TLS 1.3 + HSTS. `check_revocation_endpoints()` checks OCSP/CRL reachability (opt-in). BC-117: OCSP/CRL probes route through `http_client.ssrf_safe_urlopen` with SSRF validation; blocked endpoints emit clear "blocked by SSRF policy" findings.
- **`http_client.py`** — Shared SSRF-safe HTTP opener (`ssrf_safe_urlopen`). Validates every hop (initial URL + each redirect) against `scan._is_blocked_ip`. Used by `alerts.py` for webhook delivery (BC-116) and `posture.py` for OCSP/CRL probes (BC-117). `validate_webhook_url()` provides the shared validator for the API route. Honors `allow_private`/`allowed_subnets` from `Settings`.
- **`alerts.py`** — `evaluate_thresholds()` against LEAF_THRESHOLDS (14/7/3/1) and CHAIN_THRESHOLDS (30/14/7); per-host `threshold_days`. **Plan 048 WI-1.1:** `effective_thresholds()` returns lifetime-relative thresholds for certs ≤90d (50%/25%/10% of lifetime), fixed thresholds for long-lived; backward-identical for 365-day certs. `resolve_all_group_recipients()` batches group routing in ≤3 queries (Plan 018 A2); `evaluate_all_certs()` merges group + owner recipients into `extra_recipients`. **Routing resolver (Plan 050):** `resolve_cert_recipients()` is the single source of truth for *who* a cert's alert reaches (deduped union of alert-group + owner + role members); `evaluate_all_certs` and `find_orphan_certs()` both call it, so the orphan report can't drift from the delivery path. A multi-match cert produces **one** alert with a deduped recipient union (decision pinned 2026-06-20). `find_orphan_certs()` returns leaf certs resolving to zero specific recipients (no group, no owner) — they fall back to global recipients at send time, so they're surfaced, not rerouted. `process_pending()` tries SMTP then webhook with retry (uses `retry.backoff_range()`, linear strategy). BC-116: webhook delivery uses SSRF-safe opener; `WebhookConfig` carries `allow_private`/`allowed_subnets`. **Plan 022:** `send_webhook()` dispatches to adapter registry (`alert_adapters.py`); `WebhookConfig.kind` selects generic/discord/teams/pagerduty. `send_pagerduty_resolve()` and `resolve_pagerduty_for_renewed_cert()` handle incident auto-close on renewal.
- **`alert_adapters.py`** — Channel adapter seam (Plan 022). `AlertRequest` + `AlertAdapter` protocol. Four adapters (`GenericAdapter`, `DiscordAdapter`, `TeamsAdapter`, `PagerDutyAdapter`), each pure `build()`. `PagerDutyAdapter.build_resolve()` for renewal resolve events. Registry via `get_adapter(kind)`. PagerDuty success = HTTP 202; dedup_key is `sha256(cert_id:alert_type:threshold_days)[:32]`.
- **`scheduler.py`** — daemon thread with `threading.Event.wait()` for daily scheduling; `run_scan_now()` for immediate cycles; runs history/alert/audit purges at startup + daily. The per-day work is a module-level `_run_cycle(scan_fn, alert_fn, ct_fn=, maintenance_fn=)` (not a closure) so its **failure-isolation** contract — one stage raising must not stop the others or escape the cycle — is directly unit-testable without waiting for the timer.
- **`app.py`** — FastAPI app + lifespan (scheduler start/stop, persisted signing keys via `config.resolve_or_persist_secret`, setup detection, auth provider build). Middleware stack (outermost→in): `CSPNonceMiddleware`, auth, setup redirect, CSRF/session, rate-limit headers, security headers. The module-level `templates` and each route module's own `Jinja2Templates` instance both surface the nonce via `{{ request.state.csp_nonce }}` (no per-instance context processor needed).
- **`middleware.py`** — CSRF (double-submit, header/form only — BC-070), SQLite-backed rate limiting (`check_rate_limit`, `_init_rate_db`), proxy-aware `_extract_client_ip` (`CERT_WATCH_TRUST_PROXY`), `check_metrics_token`, and the FastAPI deps `require_auth` / `require_write` / `rate_limit(...)`. `CSPNonceMiddleware` (pure ASGI) issues the per-request CSP nonce into `scope['state']`; `security_headers_middleware` builds the response CSP via `_build_csp(nonce)` (BC-075 — nonce CSP active). `set_csrf_secret()` for lifespan-time key rotation. `setup_redirect_middleware` redirects HTML pages to `/setup` on fresh installs (never `/api/*` or public paths).
- **`audit.py`** — append-only `audit_log`; `resolve_source_ip()` uses proxy-aware extraction. Break-glass logins flagged `break_glass=true`.
- **`compliance.py`** — Compliance report aggregation + tamper-evident signing (Plan 025). `build_compliance_report(db_path, scope_tag=, version=, commit=, signing_key=)` reads stored posture + certificates and produces a `ComplianceReport` with grade distribution, fleet grade, compliance metrics (SHA-1, strong key, TLS version, HSTS), and remediation buckets (7/30/90 day expiry + failed posture checks). `sign_report()` HMAC-SHA256-signs the canonical JSON representation. `verify_report_signature()` verifies a report dict against the signing key. `report_to_dict()` and `report_to_csv_rows()` for JSON/CSV export. Three routes: `/api/reports/compliance.json`, `/api/reports/compliance.csv`, `/reports/compliance` (HTML). CLI `cert-watch verify-report <file>`.
- **`renewal_analytics.py`** — Per-host renewal analytics over `cert_history` (Plan 048 WI-2.1). `compute_host_analytics()` returns `HostRenewalAnalytics` with observed lifetimes (from `not_before`→`not_after`), renewal lead times, median cadence, and automation inference (`likely-automated`/`manual`/`unknown` via ACME-issuer detection + cadence consistency). `compute_fleet_analytics()` batches all hosts in one query. `detect_renewal_overdue()` flags hosts past expected renewal point with "same fingerprint" guard and confidence levels.
- **`readiness.py`** — SC-081 readiness report (Plan 048 WI-2.2). `build_readiness_report()` produces milestone timeline (200d/100d/47d max validity), per-host margin analysis (lead time vs future cap), workload forecast (renewals/month at each milestone). Public-trust vs private-CA separation via `chain_status`. Routes: `/api/readiness.json`, `/readiness` (HTML).
- **`digest.py`** — Weekly renewal digest (Plan 048 WI-3.1). `build_renewal_digest()` queries event_log for `cert_renewed` and `renewal_overdue` events, groups by owner. Zero-activity periods produce nothing. **Orphan notice (Plan 050):** `send_renewal_digest()` also calls `send_orphan_notice()` each run — it emails `permission_tier=='admin'` users (`_admin_emails()`) a flagged list of orphaned certs (from `alerts.find_orphan_certs`), independent of renewal activity so a quiet week still surfaces them. No orphans or no admins ⇒ nothing sent; logs its own SMTP failures and does not gate the digest's return value.
- **`policy_packs/cab_forum_sc081.py`** — Opt-in SC-081 PolicySet with date-aware max-validity rules (200d/100d/47d milestones). Non-grade-affecting violations. Disabled by default.
- **`crypto_posture.py`** — Fleet crypto inventory & agility lens (`/crypto` page), **informational, never grade-affecting** (same convention as the SC-081 pack). `classify_cert_crypto(raw_der)` reads key family/label, signature hash, and a *weak-today* flag (SHA-1/MD5, RSA<2048, weak EC curve) per cert; `analyze_fleet_crypto(db)` aggregates key-algorithm/sig-hash/family distributions + a sorted weak-offender list over leaf certs. The "PQC readiness" framing is honest inventory-for-future-migration — production TLS has no PQC primitives yet, so it does **not** claim to detect them. SHA-1 detection is tested with a pre-baked `openssl -sha1` DER fixture because modern `cryptography` refuses to *sign* SHA-1 (parsing is fine).

## Breadcrumbs / memory

Project is registered with agent-notes and routes to its regista schema via path `/projects/cert-watch`. Use the `agent-notes` CLI (or the `/find-breadcrumb`, `/file-breadcrumb`, `/update-breadcrumb` skills); **do not create physical breadcrumb files** — regista is the source of truth. **Search before filing** (dedup is the store's main failure mode). Session reflections live under `reflections/`; plans under `plans/`.

## CI workflows

- `ci.yml` — ruff + pytest (unit) on every push/PR
- `e2e.yml` — Playwright E2E on every push/PR. Two jobs: the functional job runs `-m "e2e and not visual"`; the **`visual` job is a required gate** that screenshot-compares against the committed baselines in `tests/e2e/__screenshots__/`. Those baselines are pinned to GitHub's `ubuntu-latest` font rendering — **they cannot be faithfully regenerated on a dev box or a local container** (both drift). When a deliberate UI change makes the visual job fail: run `scripts/update-visual-baselines.sh --latest` to download the `visual-snapshot-diffs` artifact and overwrite the committed baselines with the `actual_*.png` files it contains (those ARE the correct ubuntu-latest baselines), then commit. Do not regenerate baselines locally with `--update-snapshots`.
- `release.yml` — on `main`: multi-arch image build → GHCR → commit kustomize tag bump (skips itself via `paths-ignore`). Does **not** gate on the e2e/visual jobs — a red visual gate won't block the image build, but leaving it red is a maintenance-contract violation (doc truth-keeping).

## Maintenance mode

This project entered maintenance mode after Plan 049 (2026-06-13). Development is done; the surface is closed. Work is now limited to:

**What gets done:**
- **Defect fixes** — bugs in existing functionality
- **Security** — CVE response, auth/session/CSRF hardening, dependency patches
- **Dependency updates** — monthly `uv lock` refresh + `trivy` review; CRITICAL CVEs out-of-cycle
- **SC-081 date-logic upkeep** — the policy pack in `policy_packs/cab_forum_sc081.py` changes behavior on milestone dates (2026-03-15, 2027-03-15, 2029-03-15); freeze-time tests in `tests/test_policy_sc081.py` guard the boundaries
- **Doc truth-keeping** — AGENTS.md, positioning.md, and README must stay accurate

**What doesn't get done (without a priced plan):**
- New alert channels, auth providers, report formats, or pages
- New product surface of any kind
- Postgres backend (Plan 043 — deferred; SQLite single-writer is a documented feature)
- ACME renewal automation or cloud-API discovery (positioning.md non-goals)
- Private-CA / AD CS certificate inventory (declined 2026-06-13; see Plan 047 decision 4)

**Conventions for maintenance agents:**
- The test suite (2039+ unit, 18+ E2E, 9+ integration) is the safety net. Run it after every change.
- The ruff + pytest gates in CI are the authority. A passing local run is necessary but not sufficient — push and watch CI.
- When fixing a bug, add a regression test that fails without the fix. The suite is the only brake that survives session boundaries.
- `docs/positioning.md` records the product identity and what was deliberately declined. Consult it before adding features.
