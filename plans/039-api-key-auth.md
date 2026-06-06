# Plan 039 — API Key / Service-Account Authentication

**Status:** proposed 2026-06-06
**Author:** Opus 4.8 (portfolio review)
**Strategic role:** Unlock automation: CI pipelines, cert-manager hooks, and monitoring tools need programmatic access to `/api/*` without dancing through OAuth redirects or session cookies.

## Why now

The REST API is fully functional (decomposed into `routes/api/`), but every endpoint is gated by `cw_auth` session cookies set via browser login. This means:
- A cron job that POSTs `/api/hosts` to register a new load balancer must screen-scrape the login flow.
- A cert-manager sidecar that queries posture via `/api/reports/compliance.json` cannot authenticate at all.
- External monitoring tools (Datadog, Grafana Alerting) cannot pull the health/metrics endpoint without being exposed as public paths.

The middleware and auth packages already support scoped roles (`require_write`, `require_auth`). Adding a scoped API-key mechanism is a small, natural extension that dramatically extends the tool's useful surface.

## Scope

### WI-1 — `api_keys` table and repository
- Add migration `0015_api_keys.sql`: `id`, `key_hash` (SHA-256 of the raw token), `name`, `scope` (`read` | `write` | `admin`), `created_at`, `last_used_at`, `revoked`.
- Repository: `SqliteApiKeyRepository` with `create_key`, `verify_key`, `revoke_key`, `list_keys`.
- Key generation: `secrets.token_urlsafe(32)` prefix; the raw token is shown **once** on creation and never stored (only the hash).

### WI-2 — API key auth dependency
- `cert_watch.middleware` adds `api_key_auth(request, required_scope)`:
  - Reads `Authorization: Bearer <token>` header.
  - Looks up `<token>` in `api_keys` (hash match, not revoked, not expired).
  - Returns `username` (the `name` field) for audit logging; raises 401/403 otherwise.
- FastAPI dependency `require_api_key(scope)` usable alongside `require_auth` and `require_write`.
  - Union logic: if `cw_auth` session cookie is present and valid, accept it; else fall back to API key. This preserves existing browser UX while adding programmatic access.

### WI-3 — Management routes
- `GET /api/api-keys` — list keys (redacted, no raw tokens; admin scope required).
- `POST /api/api-keys` — create a new key; returns the raw token **once** in the response body.
- `DELETE /api/api-keys/{id}` — revoke a key.
- `GET /settings/api-keys` (HTML) — UI for creation and revocation with copy-to-clipboard.

### WI-4 — Audit logging
- Every API-key-authenticated request is logged to `audit_log` with `actor=<key_name>`, `source_ip`, and `action=<route>`.
- Key creation and revocation are also audited.

## Acceptance

- A request with `Authorization: Bearer <valid_token>` to `/api/hosts` succeeds without a session cookie.
- A request with an invalid or revoked token returns 401.
- A `write`-scoped key can POST/PUT; a `read`-scoped key GETting a write route gets 403.
- The UI `/settings/api-keys` page can create, list, and revoke keys.
- Audit log entries contain the key name for API-key-authenticated requests.
- 0 lint errors; unit test coverage on new modules >= 85%; full suite passes.

## Non-goals

- Rate-limiting per API key (can reuse existing per-IP rate limiting; per-key rate limits are a follow-up).
- Key rotation via scheduled expiry; keys are manual-revoke only in this plan.
- mTLS or OAuth client-credentials flow; this is the simplest possible bearer-token scheme.
- Changing any existing session-cookie auth behavior; the API key path is additive only.
