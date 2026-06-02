# Plan 020: Security Middleware Consolidation

> **Status:** ready for implementation
> **Prereq:** Plan 018 Phase A3 (Depends sweep) is the natural prerequisite,
> but this can be done independently if A3 is skipped.

## Why this exists

Two adversarial review rounds found 27 security issues. The pattern is clear:
every new route author must remember to add `_require_api_auth()` calls,
`_extract_client_ip()` for rate limiting, CSRF checks, and audit logging —
four manual conventions applied inconsistently across 30+ route handlers. This
is exactly how the auth bypass bugs (4 endpoints missing checks) kept
happening. The fix wasn't "remember better" — it was the Depends sweep in
Plan 018 A3. But A3 only covers auth. Rate limiting, IP extraction, and
security headers are still per-route manual conventions.

The current state after two hardening rounds:

```
routes/api.py           — 4 manual _require_api_auth() calls
routes/certificates.py  — 2 manual inline auth checks
routes/hosts.py          — manual check_rate_limit + _extract_client_ip
routes/auth.py           — manual check_rate_limit + _extract_client_ip
routes/views.py          — manual check_rate_limit + _extract_client_ip
middleware.py            — 4 separate middleware functions + rate limit helpers
app.py                   — 4 middleware registrations in specific order
```

Every rate limit callsite constructs its own key (`f"login:{client_ip}"`,
`f"add_host:{request.client.host}"`, `f"ct:{client_ip}"`). The key format
and whether `_extract_client_ip` is used are per-file decisions. Three of
these were inconsistent (views.py and auth.py used `request.client.host`
instead of `_extract_client_ip()`.

Security headers are a single middleware now, but they were added piecemeal
across two sessions. The CSP is broad (`'unsafe-inline'` for scripts) because
inline `<script>` blocks in templates make nonces hard.

---

## What this plan covers

Consolidate the fragmented security surface into composable, self-documenting
infrastructure so that adding a new route requires zero security boilerplate.

What it does NOT cover:
- Auth module decomposition (Plan 021)
- Dashboard query consolidation (Plan 018 B2)
- Test harness refactor (Plan 018 B1)

---

## Slice 1 — `Depends(require_auth)` sweep (Plan 018 A3, restated)

This is the same as Plan 018 A3. It's the foundation everything else builds
on. Reproduced here for completeness because this plan replaces A3 with a
wider scope.

Create FastAPI dependency functions in `deps.py` (or `middleware.py`):

```python
async def require_auth(request: Request) -> str:
    """Returns username or raises 401. Returns '' under NoAuthProvider."""
    ...

async def require_write(request: Request) -> str:
    """Auth + CSRF. Returns username or raises 401/403."""
    ...
```

Replace all manual auth checks in `api.py`, `certificates.py`, `hosts.py`
with `Depends(require_auth)` or `Depends(require_write)`.

**AC:** All `/api/*` routes return 401 without valid session when auth enabled
and 200 when auth disabled. All mutating routes return 403 on missing CSRF.
`_require_api_auth` and `_require_api_write` are deleted.

---

## Slice 2 — Rate limit dependency

**Problem:** Rate limit keys are constructed manually in 6+ route handlers,
and 3 of them used `request.client.host` instead of `_extract_client_ip()`
before this session's fix. The pattern is fragile — every new rate-limited
route must remember to use the helper and construct the key correctly.

**Fix:** Create a rate-limit dependency:

```python
def rate_limit(key_template: str, max_requests: int, window_seconds: int):
    """FastAPI dependency factory. Usage: Depends(rate_limit("add_host", 20, 60))"""
    async def _check(request: Request) -> None:
        client_ip = _extract_client_ip(request)
        if not check_rate_limit(f"{key_template}:{client_ip}", max_requests, window_seconds):
            raise HTTPException(status_code=429, detail="rate limited")
    return _check
```

Replace all manual `check_rate_limit()` calls in route handlers with
`Depends(rate_limit("login", 10, 300))` etc. Rate-limit headers (remaining,
limit, retry-after) are added by the existing `rate_limit_headers_middleware`
for `/api/*` routes — no change needed there.

Non-API routes (like `/login`) that return redirects on rate limit keep their
manual check (they can't raise HTTPException because they return
RedirectResponses). These are the exception, not the rule.

**Files:** new dependency in `deps.py` or `middleware.py`, `routes/auth.py`,
`routes/hosts.py`, `routes/certificates.py`, `routes/views.py`.

**AC:** AC-S2a: All rate-limited API routes use `Depends(rate_limit(...))`.
AC-S2b: No route handler directly calls `check_rate_limit` except
`/login` (which returns redirect, not 401). AC-S2c: Rate limiting still
uses `_extract_client_ip()` for proxy support.

---

## Slice 3 — Audit logging as a dependency / side-effect

**Problem:** `record_audit()` is called manually in 10+ mutating route
handlers. Each callsite constructs the same `(actor, source_ip, action,
details)` tuple. Missing an audit call is invisible until a compliance
review.

**Fix:** Add an optional `audit_action` parameter to `require_write`:

```python
async def require_write(
    request: Request,
    audit_action: str | None = None,
    audit_details: dict | None = None,
) -> str:
    username = await require_auth(request)
    csrf_err = await check_csrf(request)
    if csrf_err:
        raise HTTPException(status_code=403, detail=csrf_err)
    if audit_action:
        record_audit(
            db_path=_db_path(request),
            actor=username or "anonymous",
            source_ip=_extract_client_ip(request),
            action=audit_action,
            details=audit_details or {},
        )
    return username
```

This makes audit logging automatic for any route that uses
`Depends(require_write(audit_action="delete_host"))`. Routes that need
dynamic details (like the cert ID being deleted) can call `record_audit`
directly — this is for the common case.

**AC:** AC-S3a: All mutating routes that currently call `record_audit` can
be migrated to `require_write(audit_action=...)`. AC-S3b: Existing audit
rows are identical in format and content. AC-S3c: New mutating routes
automatically get audit logging if they use the dependency.

---

## Slice 4 — CSP nonce for script tags

**Problem:** The current CSP is `script-src 'self' 'unsafe-inline'` because
templates have inline `<script>` blocks (dashboard, base, scan_history).
`'unsafe-inline'` defeats most of CSP's XSS mitigation value.

**Fix:** Generate a per-request CSP nonce in `security_headers_middleware`:

```python
async def security_headers_middleware(request: Request, call_next):
    nonce = secrets.token_hex(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        f"connect-src 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
```

In templates, replace `<script>` with `<script nonce="{{ csp_nonce }}">`
and pass `csp_nonce=request.state.csp_nonce` in template context.

After this change, inline scripts without the correct nonce are blocked.
This is a hardening measure — if XSS injects `<script>alert(1)</script>`,
the browser refuses to execute it because it lacks the nonce.

**Files:** `middleware.py` (nonce generation), `app.py` (template context),
`templates/base.html`, `templates/dashboard.html`,
`templates/scan_history.html`.

**AC:** AC-S4a: CSP header includes `script-src 'self' 'nonce-<hex>'`
with a unique nonce per request. AC-S4b: All inline `<script>` blocks
include the nonce attribute. AC-S4c: Dashboard and scan_history pages
render and function identically. AC-S4d: An injected `<script>` tag
without the nonce is blocked by CSP (manual verification or E2E test).

---

## Slice 5 — `_db_path` as a dependency

**Problem:** `db_path = _db_path(request)` is the first line of 30+ route
handlers. It's a convention, not enforced. A handler that forgets it gets
a crash at the point where `db_path` is first used (or worse, uses a
module-level default).

**Fix:** Create a FastAPI dependency:

```python
def get_db(request: Request) -> Path:
    return _db_path(request)
```

Replace `db = _db_path(request)` with `db: Path = Depends(get_db)` in all
route handlers. This makes the DB path injectable for testing and removes
the `_db_path` import from route files.

**AC:** AC-S5a: No route handler imports `_db_path` directly. AC-S5b:
All route handlers that access the DB use `Depends(get_db)`. AC-S5c:
Test fixtures can override `get_db` to point at `tmp_path`.

---

## Sequencing

```
Slice 1  Depends(require_auth) sweep    (foundation — all others depend on it)
Slice 2  Rate limit dependency            (builds on deps pattern)
Slice 3  Audit as side-effect              (builds on require_write)
Slice 4  CSP nonce                         (independent, template-only)
Slice 5  get_db dependency                 (independent, mechanical)
```

Slices 1–3 form a dependency chain: 2 and 3 are easier after 1 lands.
Slices 4 and 5 are independent of each other and the chain. Slice 5 is
the most mechanical — it can be done at any point.

Each slice should be a separate commit with green tests. The slices are
small enough that a working session can do 1–2 of them.

---

## Acceptance criteria (summary)

- AC-S1: All API routes use `Depends(require_auth)` or `Depends(require_write)`.
  No manual `_require_api_auth` calls remain.
- AC-S2: All rate-limited API routes use `Depends(rate_limit(...))`. Only
  `/login` calls `check_rate_limit` directly (returns redirect, not 401).
- AC-S3: Mutating routes can opt into audit logging via `require_write(audit_action=...)`.
  Existing audit rows are identical.
- AC-S4: CSP uses per-request nonces. No `'unsafe-inline'` for scripts.
  Dashboard and scan_history render correctly.
- AC-S5: No route handler imports `_db_path`. All use `Depends(get_db)`.