# Plan 012: Safe Defaults for SMB Deployment

> cert-watch is evolving from an internal comparison tool into a product for
> small-to-medium businesses with limited technical resources. These users
> won't read runbooks, won't configure LDAP, and won't notice silent security
> degradation. The tool must be safe by default, loud about misconfiguration,
> and operable without a security engineer.
>
> This plan addresses the structural gaps that are cheapest to fix now, before
> the user base and codebase grow further.

---

## Why now

Three things get harder as the system grows:

1. **Changing defaults.** Once users deploy with today's insecure defaults
   (no auth, ephemeral keys, open metrics), changing those defaults breaks
   their installations. Every day the default is "insecure" creates more
   installations that depend on that behavior.

2. **Restructuring the auth layer.** The composite-provider pattern,
   middleware-vs-route-level auth checks, and the OAuth fallback path are
   already complex. Adding more providers or RBAC later will be harder if
   the foundation isn't clean.

3. **Fixing the data access pattern.** `_list_unified_entries_raw()` loads
   the entire database into Python. This is the foundation for the dashboard,
   metrics, healthz, pivot views, and grouped mode. Every new feature that
   reads data plugs into this function. Fixing it later means rewriting every
   caller.

---

## Phase 1 — Secure-by-default bootstrap (BLOCKER)

The single highest-leverage change: make the first-run experience safe
without requiring any configuration.

### 1.1 Auto-generate and persist signing keys

**Problem:** `CERT_WATCH_AUTH_SECRET` and `CERT_WATCH_CSRF_SECRET` default
to ephemeral random values. Sessions break on restart. If set to empty
string, they're accepted as valid (BC-054).

**Fix:**
- On first startup, if `CERT_WATCH_AUTH_SECRET` is not set, generate a
  32-byte random key and persist it to `$CERT_WATCH_DATA_DIR/.auth_secret`.
  On subsequent startups, read it back.
- Derive `CERT_WATCH_CSRF_SECRET` from the auth secret if not independently
  set.
- Treat empty/whitespace-only values as unset.
- Log at INFO on generation, WARNING if using a persisted key without
  explicit env var (so operators know they can pin it).

**Files:** `config.py` (`read_secret` + new `_persist_secret` helper),
`auth.py` (key init), `middleware.py` (CSRF key init).

**Tests:** key persists across restarts (mock filesystem); empty string
treated as unset; explicit env var takes precedence.

### 1.2 First-run setup redirect

**Problem:** A new user starts cert-watch, sees an empty dashboard, and
doesn't know they're running unauthenticated with no alerts configured.

**Fix:**
- On startup, check if the database has zero hosts AND no auth provider is
  configured. If so, set an `app.state.needs_setup = True` flag.
- Add a `GET /setup` route that renders a first-run wizard:
  - **Step 1:** Create a local admin password (writes
    `CERT_WATCH_LOCAL_ADMIN_USER` + hash to `.env` file or prints the env
    vars to copy). This makes auth trivially achievable without LDAP/OAuth.
  - **Step 2:** Optionally configure SMTP alerts (test connection button).
  - **Step 3:** Add first host (reuses the existing add-host form).
- When `needs_setup` is true, redirect `/` → `/setup` (except `/healthz`,
  `/static`, `/setup` itself).
- After setup completes (at least one host added OR auth configured), clear
  the flag. Store a `setup_complete` row in a new `kv_store` table (simple
  key-value for app state).

**Files:** new `routes/setup.py`, new `templates/setup.html`,
`app.py` (lifespan flag), `middleware.py` (public path for `/setup`).

**Tests:** redirect fires on fresh DB with no auth; redirect stops after
setup; `/healthz` never redirected; auth configured without host still
clears setup flag.

### 1.3 Require explicit opt-in for unauthenticated mode

**Problem:** `AUTH_PROVIDER` unset = everything open. An SMB user who
forgets to set it runs an open tool without knowing.

**Fix:**
- When `AUTH_PROVIDER` is unset AND the app binds to a non-loopback address
  (default `0.0.0.0`), emit a WARNING at startup:
  ```
  CERT-WATCH WARNING: Running without authentication on 0.0.0.0:8000.
  All certificate and host data is publicly accessible.
  Set AUTH_PROVIDER=local and configure CERT_WATCH_LOCAL_ADMIN_USER to secure this instance.
  Set CERT_WATCH_ALLOW_UNAUTH=1 to suppress this warning.
  ```
- Do NOT hard-fail (preserves local dev and air-gapped demos).
- Add `CERT_WATCH_ALLOW_UNAUTH` env var to suppress the warning explicitly.

**Files:** `app.py` (lifespan startup check).

**Tests:** warning emitted when auth unset + non-loopback; no warning on
loopback; no warning when `CERT_WATCH_ALLOW_UNAUTH=1`; no warning when
`AUTH_PROVIDER` set.

---

## Phase 2 — Surface operational health in the UI (HIGH)

SMB users don't scrape Prometheus or read structured logs. They check the
dashboard.

### 2.1 Health status banner

**Problem:** The scheduler, alerts, and scans can silently fail. The only
indication is a missing email or a stale "last scanned" timestamp buried in
the scan-history page.

**Fix:**
- Add a persistent health status component to `base.html` (below the
  topbar, above the content). Shows:
  - **Scheduler:** running / not running (check `_scheduler_thread.is_alive()`)
  - **Last scan:** relative time + status (from `scan_history` LIMIT 1)
  - **Failed alerts:** count in last 24h (from `alerts WHERE status='failed'
    AND created_at > now - 24h`)
  - **Auth:** provider name + "break-glass enabled" warning if local admin
    is configured
- Color-coded: green (all ok), yellow (degraded — failed alerts, stale
  scan), red (scheduler not running).
- Dismissible per-session (stored in sessionStorage).
- Data comes from a new `GET /api/health` endpoint (JSON, cached 30s) that
  returns structured health data without loading the full inventory.

**Files:** new `routes/health.py` (or extend `views.py`), new
`templates/macros/health_banner.html`, `base.html`, `static/css/tokens.css`.

**Tests:** `/api/health` returns correct scheduler/scan/alert status;
banner renders in template; stale scan triggers yellow; failed alerts
trigger yellow; scheduler down triggers red.

### 2.2 Fix healthz memory usage

**Problem:** `healthz` calls `list_scan_history(db)` loading all rows
(BC-052).

**Fix:**
- Replace with `SELECT scanned_at, status FROM scan_history ORDER BY
  scanned_at DESC LIMIT 1`.
- Use `_connect()` instead of raw `sqlite3.connect()`.

**Files:** `routes/views.py`.

**Tests:** healthz returns correct last scan; no full-table scan.

### 2.3 Fix metrics memory usage

**Problem:** `/metrics` calls `list_dashboard_rows(db)` loading all certs
(BC-050).

**Fix:**
- Replace with targeted SQL queries:
  - `cert_watch_cert_expiry_days`: iterate cursor over `SELECT hostname,
    subject, port, julianday(not_after) - julianday('now') FROM certificates
    WHERE is_leaf = 1`
  - `cert_watch_hosts_tracked`: `SELECT COUNT(*) FROM hosts`
  - `cert_watch_certificates_tracked`: `SELECT COUNT(*) FROM certificates
    WHERE is_leaf = 1`
  - `cert_watch_certificates_expired`: `SELECT COUNT(*) FROM certificates
    WHERE is_leaf = 1 AND julianday(not_after) <= julianday('now')`

**Files:** `routes/views.py`.

**Tests:** metrics returns same values as before; no full-table
materialization.

---

## Phase 3 — Close security gaps (HIGH)

These are the issues identified in the adversarial review that have
concrete exploit paths.

### 3.1 Fix empty-string signing key acceptance (BC-054)

Covered by Phase 1.1 (treat empty as unset). No separate work.

### 3.2 Fix OAuth userinfo fallback (BC-058)

**Problem:** When ID token verification fails, the code falls back to the
userinfo endpoint without verifying its response. An attacker who can
intercept the token response could strip the ID token and cause the system
to accept unverified userinfo claims.

**Fix:**
- When an ID token IS present in the token response, its claims are
  authoritative. If verification fails, authentication fails — no fallback.
- The userinfo endpoint is only used when NO id_token is present in the
  token response (some OAuth providers don't issue ID tokens).

**Files:** `auth.py` (`complete_oauth_flow`).

**Tests:** id_token verification failure → auth failure (no fallback);
no id_token present → userinfo used; id_token present + valid → userinfo
ignored.

### 3.3 Gate /metrics behind bearer token (BC-056)

**Problem:** `/metrics` is unauthenticated and exposes all monitored
hostnames, cert subjects, and operational data.

**Fix:**
- Add `CERT_WATCH_METRICS_TOKEN` env var.
- When set, `/metrics` requires `Authorization: Bearer <token>` header.
  Missing/wrong token → 401.
- When unset, `/metrics` remains open (backward compat) but logs a WARNING
  at startup if auth is enabled.
- Document in README and runbook.

**Files:** `routes/views.py`, `app.py` (startup warning).

**Tests:** token required when set; open when unset; wrong token → 401;
warning at startup when auth on + no metrics token.

### 3.4 Fix DNS rebinding TOCTOU (BC-053)

**Problem:** SSRF check resolves hostname, then scan resolves it again
separately.

**Fix:**
- In the add-host flow, pass the resolved IP from the SSRF check to the
  scan function. The scan uses the pre-resolved IP for the TLS connection
  (still using the hostname for SNI).
- Add a `_resolved_ip` parameter to `scan_host()` / `_open_tls_connection()`.
  When provided, skip DNS resolution and connect directly to the IP.
- For scheduled scans, the SSRF check at add-time is the gate; the scan
  uses whatever DNS returns at scan time (this is acceptable because the
  operator controls the host list).

**Files:** `scan.py` (`_open_tls_connection`, `_resolve_host`),
`routes/hosts.py` (pass resolved IP).

**Tests:** add-host with DNS rebinding simulation (mock DNS returning
different IPs on second call); scheduled scan still resolves normally.

### 3.5 Fix rate limiter behind reverse proxy (BC-055)

**Problem:** All requests behind a reverse proxy share one rate limit key.

**Fix:**
- Add `CERT_WATCH_TRUST_PROXY` env var (default `0`).
- When set, extract client IP from `X-Forwarded-For` header (rightmost
  entry that is not a trusted proxy) or `X-Real-IP` header.
- Document in README.

**Files:** `middleware.py`.

**Tests:** proxy header used when `TRUST_PROXY=1`; direct client used
when `TRUST_PROXY=0`; spoofed header from non-proxy ignored.

---

## Phase 4 — Structural cleanup (MEDIUM)

> **Moved to Plan 018** (auth & data-layer consolidation). Plan 018
> refines and replaces these items with concrete sequencing, blast-radius
> analysis, and acceptance criteria informed by a codebase-wide review.
> The summary below is kept for reference; see Plan 018 for the current
> spec.

### 4.1 Consolidate auth checks with FastAPI dependencies

→ Plan 018 A3 (`Depends(require_auth)` / `Depends(require_write)` sweep).

### 4.2 Unify data access for dashboard/metrics/healthz

→ Plan 018 B2 (purpose-built dashboard queries).

### 4.3 Audit log retention

**Problem:** The audit log grows unbounded. SMB users won't manage this.

**Fix:**
- Add `CERT_WATCH_AUDIT_RETENTION_DAYS` env var (default `90`).
- On startup (and daily via scheduler), delete audit rows older than the
  retention period.
- Log at INFO when rows are purged.

**Files:** `audit.py`, `scheduler.py`.

**Tests:** old rows purged; recent rows retained; configurable retention;
default 90 days.

**Problem:** The audit log grows unbounded. SMB users won't manage this.

**Fix:**
- Add `CERT_WATCH_AUDIT_RETENTION_DAYS` env var (default `90`).
- On startup (and daily via scheduler), delete audit rows older than the
  retention period.
- Log at INFO when rows are purged.

**Files:** `audit.py`, `scheduler.py`.

**Tests:** old rows purged; recent rows retained; configurable retention;
default 90 days.

---

## Phase 5 — Documentation for the SMB user (MEDIUM)

### 5.1 Quick-start guide with secure defaults

Rewrite the README "Quick start" section to include:
1. Docker one-liner with `AUTH_PROVIDER=local` and a generated admin
   password.
2. "What you get" summary (auth on, scheduler running, dashboard at
   localhost:8000).
3. "Next steps" — add hosts, configure email alerts, set up OAuth.

### 5.2 Configuration wizard in /setup

The Phase 1.2 setup page serves as interactive documentation. Each field
has inline help text explaining what it does and why you'd configure it.

### 5.3 Troubleshooting guide

Add `docs/troubleshooting.md` covering:
- "I can't log in" → check AUTH_PROVIDER, check local admin, check logs.
- "Scans are failing" → DNS, firewall, private IP settings.
- "Alerts aren't sending" → SMTP connectivity, webhook URL, check
  /alerts page for error messages.
- "The dashboard is slow" → host count, SQLite WAL, disk I/O.

---

## Sequencing

```
Phase 1 (secure bootstrap) ─── BLOCKER, do first
  ├── 1.1 persisted signing keys
  ├── 1.2 first-run setup redirect
  └── 1.3 unauth mode warning

Phase 2 (operational visibility) ─── HIGH, can parallel with Phase 1
  ├── 2.1 health banner + /api/health
  ├── 2.2 healthz memory fix (BC-052)
  └── 2.3 metrics memory fix (BC-050)

Phase 3 (security gaps) ─── HIGH, can parallel with Phase 2
  ├── 3.1 empty key fix (covered by 1.1)
  ├── 3.2 OAuth fallback fix (BC-058)
  ├── 3.3 metrics token (BC-056)
  ├── 3.4 DNS rebinding fix (BC-053)
  └── 3.5 proxy-aware rate limiting (BC-055)

Phase 4 (structural cleanup) ─── MEDIUM, see Plan 018
  ├── 4.1 FastAPI auth dependencies → Plan 018 A3
  ├── 4.2 unified data access → Plan 018 B2
  └── 4.3 audit log retention (stays in this plan)

Phase 5 (documentation) ─── MEDIUM, after Phase 4
  ├── 5.1 quick-start guide
  ├── 5.2 setup wizard docs
  └── 5.3 troubleshooting guide
```

Phases 1–3 are the "resolve now" work. Phase 4 is the "while we can still
refactor" work. Phase 5 follows naturally.

---

## Acceptance criteria

### Phase 1
- AC-1: Fresh install with no env vars → signing key auto-generated and
  persisted → sessions survive restart.
- AC-2: Fresh install on `0.0.0.0` with no auth → WARNING at startup.
- AC-3: `/setup` wizard creates a local admin account without CLI
  interaction.
- AC-4: After setup, the app is auth-protected and has at least one host.

### Phase 2
- AC-5: Dashboard shows scheduler/scan/alert health without navigating
  away.
- AC-6: `/healthz` does not load the full scan_history table.
- AC-7: `/metrics` does not load the full certificate table.

### Phase 3
- AC-8: Empty `CERT_WATCH_AUTH_SECRET=""` is treated as unset.
- AC-9: OAuth with present-but-invalid ID token fails auth (no fallback).
- AC-10: `/metrics` with `CERT_WATCH_METRICS_TOKEN` set requires bearer
  token.
- AC-11: Add-host SSRF check and scan use the same DNS resolution.

### Phase 4
- AC-12..AC-13: moved to Plan 018.
- AC-14: Audit rows older than retention period are purged automatically.

---

## Breadcrumbs resolved by this plan

- BC-050 (metrics memory) → Phase 2.3
- BC-052 (healthz memory) → Phase 2.2
- BC-053 (DNS rebinding) → Phase 3.4
- BC-054 (empty signing keys) → Phase 1.1
- BC-055 (rate limiter proxy) → Phase 3.5
- BC-056 (metrics auth) → Phase 3.3
- BC-058 (OAuth fallback) → Phase 3.2
