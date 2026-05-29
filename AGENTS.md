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
- **Public paths are unauthenticated.** `/healthz`, `/metrics`, `/api/*`, `/static` stay open for monitoring when auth is enabled.
- **Environment-driven config.** All settings via env vars (see README). No config files.
- **`CERT_WATCH_ALLOW_PRIVATE_IPS`** — defaults to `1` (private IP scanning enabled). Set to `0` to block RFC 1918 / ULA hosts. Loopback and link-local remain blocked regardless.
- **`CERT_WATCH_DNS_SERVERS`** — comma-separated list of DNS server IPs for hostname resolution during scans. When set, queries are sent directly to these servers (UDP port 53, A/AAAA records) instead of using the system resolver. Falls back to system resolver if custom DNS returns no results. Useful for resolving internal hostnames via domain controllers.
- **Spec acceptance criteria are the boundary.** Don't add features beyond the spec without a tracked breadcrumb or plan entry.

## Known issues (open breadcrumbs)

9 open breadcrumbs in agent-notes: 0 critical, 0 high, 0 medium, 9 low.

- **BC-026** (low) — Missing unit tests for trust anchor CA validation (BC-024 follow-up)
- **BC-027** (low) — openssl s_client fallback opens second TLS connection per scan
- **BC-028** (low) — openssl s_client fallback opens second TLS connection per scan (duplicate of BC-027, keep one)
- **BC-029** (low) — REST API pagination lacks HATEOAS navigation links
- **BC-030** (low) — app.py decomposition (in-progress, initial split done)
- **BC-031** (low) — Add PostgreSQL and MSSQL support alongside SQLite
- **BC-032** (low) — Structured JSON logging for observability integration
- **BC-033** (low) — Dashboard grouping by cert fingerprint with per-host status
- **BC-034** (low) — Owner/contact field with alert routing and renewal status
- **FEAT-006** (low) — Database migration tooling (alembic)

### Recently resolved

- **BC-016** (high) — Deploy lag: code current, ops push needed for CI
- **BC-017** (medium) — E2E test now asserts host row + scan-history failure
- **BC-022** (medium) — openssl s_client fallback for Python 3.12 chain extraction
- **BC-023** (low) — DER-based issuer/subject comparison in validate_chain_order
- **BC-024** (low) — Trust anchor CA validation (BasicConstraints check)
- **BC-025** (low) — Private IP rejection includes CERT_WATCH_ALLOW_PRIVATE_IPS hint

### Recently implemented features

- **Scan retry** — `scan_host()` retries transient failures (connection refused, timeout) up to 2 times with exponential backoff.
- **Fast scheduler retry** — When hosts have no successful scan yet, the scheduler retries every hour instead of waiting for the daily cycle.
- **Scan result diffing** — On renewal (fingerprint change), `replace_scanned()` logs what changed (expiry shift, SAN changes, issuer change).
- **Confirmation dialogs** — Destructive actions ("Clear results", "Delete host", "Remove trust anchor") require `confirm()` before submitting.
- **Rate limit headers** — API responses include `X-RateLimit-Remaining`, `X-RateLimit-Limit`, and `Retry-After` (on 429).
- **System CA chain validation** — `chain_status()` checks the system trust store, so LE and other public CA chains show as "public" even when the root is omitted.
- **Scan failure UX** — Scan failures show as yellow warnings (not red errors) with human-friendly messages.
- **Rate limit enforcement** — API middleware returns 429 on rate limit exceeded (not just headers).
- **app.py decomposition** — Split ~1500-line monolith into `middleware.py`, `filters.py`, and `routes/` modules.
- **Host tags** — `tags` column on hosts for categorization and filtering.
- **Per-host scan scheduling** — `scan_interval_hours` column allows different scan frequencies per host.
- **Webhook test endpoint** — `POST /api/webhook/test` sends a test payload to verify webhook config.
- **Expiry digest mode** — `ALERT_DIGEST_ONLY=1` sends a single daily summary instead of per-cert alerts.
- **Webhook retry** — `process_pending()` retries failed alerts up to 3 times with exponential backoff.
- **Host export CSV** — `GET /api/export/hosts.csv` for bulk host list export.
- **SQL-level pagination** — `list_dashboard_rows()` accepts sort/pagination params for efficient queries.

## Architecture notes

- **`auth.py`** — `AuthProvider` protocol with `NoAuthProvider`, `LDAPAuthProvider`, `OAuthProvider`. Session management via HMAC-signed cookies (`cw_auth`). Separate from CSRF cookies (`cw_sid`).
- **`database.py`** — Repository pattern (`CertificateRepository`, `AlertRepository`, `SqliteHostRepository`). `replace_scanned()` does atomic delete+insert in one transaction. `init_schema()` is idempotent with column migration.
- **`scan.py`** — `scan_host()` returns `ScannedEntry | ScanError`. `store_scanned()` delegates to `replace_scanned()` for path-based calls.
- **`alerts.py`** — `evaluate_thresholds()` checks against LEAF_THRESHOLDS (14,7,3,1) and CHAIN_THRESHOLDS (30,14,7). Per-host custom thresholds via `hosts.threshold_days`. `process_pending()` tries SMTP then webhook.
- **`scheduler.py`** — Daemon thread with `threading.Event.wait()` for daily scheduling. `run_scan_now()` for immediate cycles.
- **`app.py`** — FastAPI with lifespan (scheduler start/stop), CSRF middleware, auth middleware, rate limiting.

## Breadcrumbs / memory

Project is registered with agent-notes (postgres-backed). Use the `mcp__breadcrumb__*` / `mcp__memory__*` / `mcp__search__*` tools from Claude Code; resolves via path `/projects/cert-watch`. Local mirror directories: `breadcrumbs/active/`, `breadcrumbs/resolved/`, `plans/`, `reflections/`.

## CI workflows

- `ci.yml` — ruff + pytest (unit) on every push/PR
- `e2e.yml` — Playwright E2E on every push/PR
- `release.yml` — on `main`: multi-arch image build → GHCR → commit kustomize tag bump (skips itself via `paths-ignore`)
