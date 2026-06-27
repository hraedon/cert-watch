"""CSRF, rate limiting, and auth middleware."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple
from urllib.parse import quote

from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.auth import SESSION_COOKIE, NoAuthProvider, decode_session, validate_session
from cert_watch.auth.rbac import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    AuthContext,
    build_auth_context,
)
from cert_watch.security import SecurityContext  # noqa: F401  (re-exported)

logger = logging.getLogger("cert_watch.middleware")


def _is_auth_enabled(request: Request) -> bool:
    """Return True when an auth provider is configured (not NoAuthProvider)."""
    auth = getattr(request.app.state, "auth_provider", None)
    return auth is not None and not isinstance(auth, NoAuthProvider)


_COOKIE_SECURE = os.environ.get("CERT_WATCH_COOKIE_SECURE", "1") == "1"

# ---------- CSRF protection (double-submit cookie) ----------

_csrf_secret_val = os.environ.get("CERT_WATCH_CSRF_SECRET") or None
if not _csrf_secret_val:
    _csrf_secret_val = secrets.token_hex(32)
_CSRF_SECRET = _csrf_secret_val
_CSRF_TOKEN_TTL = 3600 * 2  # 2 hours
_SID_COOKIE_TTL = 3600 * 8  # 8 hours — matches session cookie TTL
_CSRF_BYPASS = False


def set_csrf_secret(value: str) -> None:
    """Replace the module-level CSRF secret (test-only; production uses SecurityContext)."""
    global _csrf_secret_val, _CSRF_SECRET
    _csrf_secret_val = value
    _CSRF_SECRET = value


def _csrf_key(security: SecurityContext | None) -> str:
    """Resolve the CSRF secret: the injected SecurityContext, else the
    module-level import-time fallback (WI-083 — test-only path)."""
    return security.csrf_secret if security is not None else _CSRF_SECRET


def _request_security(request: Request) -> SecurityContext | None:
    """The SecurityContext carried on app.state, if the lifespan set one."""
    return getattr(request.app.state, "security", None)


def _request_db_path(request: Request) -> str | None:
    """The database path from app.state.settings, if available (BC-081)."""
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        return str(settings.db_path)
    return None


def make_csrf_token(session_id: str, security: SecurityContext | None = None) -> str:
    payload = f"{session_id}:{int(datetime.now(UTC).timestamp())}"
    sig = hmac.new(_csrf_key(security).encode(), payload.encode(), hashlib.sha256).hexdigest()[:64]
    return f"{payload}:{sig}"


def validate_csrf_token(
    token: str, session_id: str, security: SecurityContext | None = None
) -> bool:
    # rsplit: the session_id (cw_auth) contains colons, so split from the
    # right to extract the trailing timestamp and HMAC signature.
    parts = token.rsplit(":", 2)
    if len(parts) != 3:
        return False
    ts_str, sig = parts[1], parts[2]
    payload = f"{session_id}:{ts_str}"
    key = _csrf_key(security).encode()
    expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()[:64]
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    return (datetime.now(UTC).timestamp() - ts) < _CSRF_TOKEN_TTL


def get_session_id(request: Request) -> str:
    sid = request.cookies.get("cw_sid")
    if sid:
        return sid
    scope_sid = request.scope.get("session_id")
    if scope_sid:
        return scope_sid
    return secrets.token_hex(16)


def get_session_token(request: Request) -> str:
    """Return the ``cw_auth`` session cookie value for CSRF binding.

    The ``cw_auth`` cookie carries the HMAC-signed session token — binding
    the CSRF token to it (rather than ``cw_sid``) prevents subdomain
    cookie injection from forging CSRF tokens.  Falls back to ``get_session_id``
    when no session cookie is present (unauthenticated requests).
    """
    auth_token = request.cookies.get(SESSION_COOKIE, "")
    if auth_token:
        return auth_token
    return get_session_id(request)


# ---------- Rate limiting (SQLite-backed sliding window, BC-049) ----------

_RATE_SHARDS = 256
_rate_db_init_lock = threading.Lock()
_rate_db_path: Path | None = None
_rate_db_initialized = False
# In-memory cache for reduced DB I/O (per-key, synced to SQLite). Sharded to
# avoid a single global lock serialising unrelated keys under concurrent load.
_rate_locks: tuple[threading.Lock, ...] = tuple(threading.Lock() for _ in range(_RATE_SHARDS))
_rate_caches: list[dict[str, list[float]]] = [{} for _ in range(_RATE_SHARDS)]
_RATE_CACHE_TTL = 10.0  # seconds before cache entry is considered stale
_RATE_STALE_TTL = 600.0  # evict rows stale for 10 minutes


def _rate_shard(key: str) -> int:
    return hash(key) % _RATE_SHARDS


def _clear_rate_caches() -> None:
    """Clear all in-memory rate-limit cache shards (test helper)."""
    for cache in _rate_caches:
        cache.clear()

_TRUST_PROXY = os.environ.get("CERT_WATCH_TRUST_PROXY", "") == "1"
_TRUSTED_PROXIES = frozenset(
    p.strip() for p in os.environ.get("CERT_WATCH_TRUSTED_PROXIES", "").split(",") if p.strip()
)


def _extract_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting X-Forwarded-For when trusted proxy is configured.

    When ``TRUST_PROXY=1`` and ``TRUSTED_PROXIES`` is empty, we use the **rightmost**
    XFF entry (the hop the trusted proxy appended) rather than the leftmost
    (client-controlled) entry, which is spoofable. This is the correct behavior
    for a single trusted proxy; multi-proxy chains should use ``TRUSTED_PROXIES``.
    """
    if not _TRUST_PROXY:
        return request.client.host if request.client else "unknown"
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        parts = [p.strip() for p in xff.split(",")]
        if _TRUSTED_PROXIES:
            for part in reversed(parts):
                if part not in _TRUSTED_PROXIES:
                    return part
        else:
            # Rightmost entry = the proxy that directly contacted us (BC-029)
            return parts[-1] if parts else (request.client.host if request.client else "unknown")
    real_ip = request.headers.get("x-real-ip", "")
    if real_ip:
        logger.warning(
            "TRUST_PROXY=1: using X-Real-IP (%s) — ensure your reverse proxy "
            "strips or overwrites this header from clients", real_ip,
        )
        return real_ip
    return request.client.host if request.client else "unknown"


def _init_rate_db(db_path: Path | str) -> None:
    """Initialize the rate limit database path. Called at app startup."""
    global _rate_db_path
    _rate_db_path = Path(db_path)


def _load_timestamps(conn: sqlite3.Connection, key: str, cutoff: float) -> list[float]:
    """Load and filter timestamps for a rate limit key from SQLite."""
    row = conn.execute(
        "SELECT timestamps FROM rate_limits WHERE key = ?", (key,)
    ).fetchone()
    if not row:
        return []
    try:
        all_ts = json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return []
    return [t for t in all_ts if t >= cutoff]


def _save_timestamps(conn: sqlite3.Connection, key: str, timestamps: list[float]) -> None:
    """Save timestamps for a rate limit key to SQLite."""
    now_iso = datetime.now(UTC).isoformat()
    ts_json = json.dumps(timestamps)
    conn.execute(
        "INSERT OR REPLACE INTO rate_limits (key, timestamps, updated_at) "
        "VALUES (?, ?, ?)",
        (key, ts_json, now_iso),
    )


def _cleanup_stale(conn: sqlite3.Connection) -> None:
    """Remove rate limit entries that haven't been updated recently."""
    stale_before = (
        datetime.now(UTC).timestamp() - _RATE_STALE_TTL
    )
    stale_iso = datetime.fromtimestamp(stale_before, tz=UTC).isoformat()
    conn.execute(
        "DELETE FROM rate_limits WHERE updated_at < ?", (stale_iso,)
    )


def _apply_memory_limit(
    cache: dict[str, list[float]], key: str, cutoff: float, max_requests: int, now: float
) -> bool:
    """Apply sliding-window rate limit in-memory for a single cache shard."""
    ts = [t for t in cache.get(key, []) if t >= cutoff]
    if len(ts) >= max_requests:
        cache[key] = ts
        return False
    ts.append(now)
    cache[key] = ts
    # Evict stale keys to prevent unbounded growth; per-shard threshold keeps
    # total cache bounded without a global lock.
    if len(cache) > max(16, 256 // _RATE_SHARDS):
        stale = [k for k, v in cache.items() if not v or max(v) < cutoff]
        for k in stale:
            del cache[k]
    return True


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if request is allowed, False if rate-limited.

    Uses SQLite for persistence so rate limits are shared across workers (BC-049).
    Falls back to in-memory mode when no database is configured.
    """
    now = datetime.now(UTC).timestamp()
    cutoff = now - window_seconds

    shard = _rate_shard(key)
    lock = _rate_locks[shard]
    cache = _rate_caches[shard]

    if _rate_db_path is None:
        # Fallback: in-memory only (single-worker mode)
        with lock:
            return _apply_memory_limit(cache, key, cutoff, max_requests, now)

    with lock:
        try:
            from cert_watch.database.connection import _connect
            from cert_watch.database.schema import init_schema

            global _rate_db_initialized
            if not _rate_db_initialized:
                with _rate_db_init_lock:
                    if not _rate_db_initialized:
                        init_schema(_rate_db_path)
                        _rate_db_initialized = True
            with _connect(_rate_db_path) as conn:
                # Periodic cleanup of stale entries
                cache_ts = cache.get(key)
                if cache_ts is not None and now - min(cache_ts, default=now) < _RATE_CACHE_TTL:
                    # Use cached timestamps (still valid within cache TTL)
                    ts = [t for t in cache_ts if t >= cutoff]
                else:
                    ts = _load_timestamps(conn, key, cutoff)

                # Evict stale in-memory cache entries periodically
                if len(cache) > max(16, 256 // _RATE_SHARDS):
                    stale = [k for k, v in cache.items() if not v or max(v) < cutoff]
                    for k in stale:
                        del cache[k]

                if len(ts) >= max_requests:
                    cache[key] = ts
                    _save_timestamps(conn, key, ts)
                    conn.commit()
                    return False

                ts.append(now)
                cache[key] = ts
                _save_timestamps(conn, key, ts)
                conn.commit()
                return True
        except (sqlite3.Error, OSError):
            # WARNING, not DEBUG (BC-078): a silent DB-error fallback degrades
            # rate limiting to per-process counters without anyone noticing.
            # This is fail-open (degraded rather than denied) — crashing the
            # whole app over a rate-limit DB error is worse than temporarily
            # losing cross-worker limit enforcement.
            logger.warning(
                "rate limit DB error, falling back to per-process in-memory limiting",
                exc_info=True,
            )
            # Fallback to in-memory on DB errors
            return _apply_memory_limit(cache, key, cutoff, max_requests, now)


def get_rate_remaining(key: str, max_requests: int, window_seconds: int) -> tuple[int, int]:
    """Return (remaining, retry_after_seconds) for the given rate limit window."""
    now = datetime.now(UTC).timestamp()
    cutoff = now - window_seconds
    shard = _rate_shard(key)
    cache = _rate_caches[shard]

    if _rate_db_path is not None:
        try:
            from cert_watch.database.connection import _connect

            with _connect(_rate_db_path) as conn:
                ts = _load_timestamps(conn, key, cutoff)
        except (sqlite3.Error, OSError):
            with _rate_locks[shard]:
                ts = [t for t in cache.get(key, []) if t >= cutoff]
    else:
        with _rate_locks[shard]:
            ts = [t for t in cache.get(key, []) if t >= cutoff]

    count = len(ts)
    remaining = max(0, max_requests - count)
    oldest = min(ts, default=now)
    retry_after = max(0, int(window_seconds - (now - oldest)))
    return remaining, retry_after


async def check_csrf(request: Request) -> str | None:
    """Validate CSRF double-submit cookie. Returns error message or None.

    Checks the ``x-csrf-token`` header, then the ``_csrf_token`` form field.
    The query-string fallback was removed (BC-070): query-param tokens leak
    into browser history, access logs, and Referer headers, weakening the
    double-submit pattern on state-changing routes.
    """
    if _CSRF_BYPASS:
        sid = get_session_token(request)
        security = _request_security(request)
        token = make_csrf_token(sid, security)
        validate_csrf_token(token, sid, security)
        return None
    token = request.headers.get("x-csrf-token") or ""
    if not token:
        try:
            form = await request.form()
            raw = form.get("_csrf_token", "")
            token = raw if isinstance(raw, str) else ""
        except (ValueError, RuntimeError):
            pass
    if not token:
        return "missing CSRF token"
    session_id = get_session_token(request)
    if not validate_csrf_token(token, session_id, _request_security(request)):
        return "invalid or expired CSRF token"
    return None


def get_auth_context(request: Request) -> dict:
    """Return template context dict with auth_user, may_write, etc.

    When an AuthContext is present (Plan 035 RBAC), may_write is
    derived from AuthContext permissions.  Otherwise the legacy
    write_users / admin_users logic is used.
    """
    username = request.scope.get("auth_user", "")
    auth_ctx = getattr(request.state, "auth_context", None)

    may_write = auth_ctx.may_write() if auth_ctx is not None else _may_write(request, username)

    # Detect whether the local admin password is auto-generated
    settings = getattr(request.app.state, "settings", None)
    autogenerated = False
    if settings:
        from cert_watch.config import LOCAL_ADMIN_AUTOGENERATED
        from cert_watch.database import kv_get
        val = kv_get(settings.db_path, LOCAL_ADMIN_AUTOGENERATED)
        autogenerated = val is not None and val == "1"

    # Plan 040: resolve user email from session or DB
    user_email = ""
    if auth_ctx:
        user_email = getattr(auth_ctx, "email", "")
    if not user_email and settings:
        try:
            from cert_watch.auth.session import decode_session
            from cert_watch.database.users_roles import SqliteUserRepository

            token = request.cookies.get(SESSION_COOKIE, "")
            info = decode_session(token, _request_security(request))
            if info and info.email:
                user_email = info.email
            else:
                user_repo = SqliteUserRepository(settings.db_path)
                user = user_repo.get_by_username(username)
                if user:
                    user_email = user.email
        except Exception:
            logger.debug("failed to resolve user email for %s", username, exc_info=True)

    no_auth = not _is_auth_enabled(request)
    is_admin = (
        auth_ctx.is_admin if auth_ctx is not None else no_auth
    )

    return {
        "auth_user": username,
        "may_write": may_write,
        "is_admin": is_admin,
        "local_admin_autogenerated": autogenerated,
        "user_email": user_email,
        "scope_tag": getattr(auth_ctx, "scope_tag", "") if auth_ctx else "",
        "permission_tier": getattr(auth_ctx, "tier", "") if auth_ctx else "",
    }


def get_csrf_context(request: Request) -> dict:
    """Return template context dict with CSRF token for the current session."""
    session_token = get_session_token(request)
    token = make_csrf_token(session_token, _request_security(request))
    return {"csrf_token": token}


# ---------- Middleware functions ----------

_PUBLIC_PATHS = frozenset({
    "/healthz", "/readyz", "/login", "/auth/callback", "/auth/logout", "/setup",
    "/favicon.ico",
})

_METRICS_TOKEN = os.environ.get("CERT_WATCH_METRICS_TOKEN") or None


def is_public_path(path: str) -> bool:
    # NOTE: /api/* is intentionally NOT public. The data API (cert/host
    # inventory, CSV export, posture) requires auth when AUTH_PROVIDER is set;
    # unauthenticated API requests get a 401 (see auth_middleware). Only
    # liveness/scrape and the login flow stay open.
    if path in _PUBLIC_PATHS:
        return True
    if path.startswith("/static/"):
        return True
    return path == "/metrics" or path.startswith("/metrics/")


def check_metrics_token(request: Request) -> bool:
    """Check bearer token for /metrics when CERT_WATCH_METRICS_TOKEN is set.

    Returns True if the request is authorized (or no token is configured).
    """
    if not _METRICS_TOKEN:
        return True
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return hmac.compare_digest(token, _METRICS_TOKEN)
    return False


async def rate_limit_headers_middleware(request: Request, call_next):
    """Enforce rate limits on API routes and add X-RateLimit headers."""
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    # Health checks are polled frequently (UI banner, k8s probes) — exempt.
    if request.url.path == "/api/health":
        return await call_next(request)
    client = _extract_client_ip(request)
    key = f"api:{client}"
    if not check_rate_limit(key, 60, 60):
        remaining, retry_after = get_rate_remaining(key, 60, 60)
        response = JSONResponse(
            content={"error": "rate limited"},
            status_code=429,
        )
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Limit"] = "60"
        response.headers["Retry-After"] = str(retry_after)
        return response
    response = await call_next(request)
    remaining, _ = get_rate_remaining(key, 60, 60)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Limit"] = "60"
    return response


async def csrf_session_middleware(request: Request, call_next):
    """Ensure every visitor has a session cookie for CSRF protection."""
    if not request.cookies.get("cw_sid"):
        sid = secrets.token_hex(16)
        request.scope["session_id"] = sid
        response = await call_next(request)
        # HttpOnly: the CSRF token is HMAC'd with a server-side secret and
        # rendered into forms server-side, so no client JS ever reads cw_sid.
        # Keeping it HttpOnly denies an XSS one more primitive at zero cost.
        response.set_cookie(
            "cw_sid", sid, httponly=True, samesite="strict", max_age=_SID_COOKIE_TTL,
            secure=_COOKIE_SECURE, path="/",
        )
        return response
    return await call_next(request)


async def setup_redirect_middleware(request: Request, call_next):
    """Redirect all HTML page requests to /setup when the app needs first-run configuration.

    Detected via app.state.needs_setup flag set during lifespan.
    Public paths, /setup itself, and API paths are never redirected.
    API requests without auth will get 401 from auth_middleware regardless.
    """
    needs_setup = getattr(request.app.state, "needs_setup", False)
    if not needs_setup:
        return await call_next(request)
    path = request.url.path
    if is_public_path(path) or path.startswith("/setup") or path.startswith("/api/"):
        return await call_next(request)
    return RedirectResponse(url="/setup", status_code=303)


# ---------- API-key (bearer) authentication (Plan 039 / BC-104) ----------

# API-key scope → cert-watch RBAC role. read=viewer, write=operator, admin=admin.
_API_KEY_SCOPE_ROLE = {
    "read": ROLE_VIEWER,
    "write": ROLE_OPERATOR,
    "admin": ROLE_ADMIN,
}


def authenticate_api_key(
    request: Request, db_path: str | Path | None
) -> AuthContext | None:
    """Authenticate an ``Authorization: Bearer cwk_…`` API key.

    On success, sets ``request.scope['auth_user']`` to the key name, stores the
    derived ``AuthContext`` on ``request.state.auth_context``, flags
    ``request.state.api_key_auth = True`` (so CSRF is skipped for the token
    path), and returns the context. Returns ``None`` when no valid key is
    presented — leaving cookie-session auth and metrics-token auth untouched.
    """
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    if not token.startswith("cwk_") or not db_path:
        return None
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    result = SqliteApiKeyRepository(db_path).verify_key(token)
    if result is None:
        return None
    role = _API_KEY_SCOPE_ROLE.get(result.scope, ROLE_VIEWER)
    ctx = AuthContext.from_tier(result.name, tier=role, roles=[role])
    request.scope["auth_user"] = result.name
    request.state.auth_context = ctx
    request.state.api_key_auth = True
    return ctx


async def auth_middleware(request: Request, call_next):
    """Enforce authentication when AUTH_PROVIDER is configured.

    Public paths (/healthz, /metrics, /static, /login, /auth/*) are exempt.
    The /api/* data routes require auth: unauthenticated API requests get a
    401, unauthenticated UI requests redirect to /login.
    """
    if not _is_auth_enabled(request):
        return await call_next(request)

    path = request.url.path
    if is_public_path(path):
        return await call_next(request)

    token = request.cookies.get(SESSION_COOKIE, "")
    db_path = _request_db_path(request)
    _settings = getattr(request.app.state, "settings", None)
    _ttl = getattr(_settings, "session_ttl", None) if _settings else None
    username = validate_session(
        token, _request_security(request),
        db_path=db_path, session_ttl=_ttl,
    )
    if username:
        request.scope["auth_user"] = username
        # BC-145: propagate IdP groups/roles into the AuthContext so that
        # form-POST routes (require_write_form) and templates (get_auth_context)
        # enforce RBAC even when they don't go through the require_auth dependency.
        settings = getattr(request.app.state, "settings", None)
        role_map = getattr(settings, "role_map", {}) if settings else {}
        role_repo = None
        if settings:
            try:
                from cert_watch.database.users_roles import SqliteRoleRepository
                role_repo = SqliteRoleRepository(settings.db_path)
            except (OSError, sqlite3.Error):
                pass
        info = decode_session(token, _request_security(request))
        if info is not None:
            auth_ctx = build_auth_context(
                username, info.groups, info.roles, role_map, role_repo=role_repo,
            )
            request.state.auth_context = auth_ctx
        return await call_next(request)

    # API-key bearer auth (Plan 039): cron jobs / CI / monitoring tools with no
    # session cookie. Only valid on top of a configured auth provider.
    if authenticate_api_key(request, db_path) is not None:
        return await call_next(request)

    # Unauthenticated
    if path.startswith("/api/"):
        return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
    return RedirectResponse(url="/login", status_code=303)


def _build_csp(nonce: str) -> str:
    """Build the Content-Security-Policy header for a request.

    ``script-src`` uses a per-request nonce — inline ``on*=`` event-handler
    attributes have been fully converted to ``data-*`` + delegated
    ``addEventListener`` (BC-075).

    ``style-src`` keeps ``'unsafe-inline'``: the UI binds dynamic CSS custom
    properties via inline ``style=`` attributes, which nonces can't cover.

    ``report-uri`` is appended when ``CERT_WATCH_CSP_REPORT_URI`` is set.
    """
    policy = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    report_uri = os.environ.get("CERT_WATCH_CSP_REPORT_URI", "")
    if report_uri:
        policy += f"; report-uri {report_uri}"
    return policy


class CSPNonceMiddleware:
    """Pure-ASGI middleware that issues a per-request CSP nonce into
    ``scope['state']`` before anything else runs.

    Done as raw ASGI (not ``BaseHTTPMiddleware``) deliberately: ``request.state``
    set inside a ``BaseHTTPMiddleware`` does not propagate to the endpoint /
    template render (task isolation), but ``scope['state']`` written here is
    shared with the downstream request — so both the templates
    (``{{ request.state.csp_nonce }}``) and ``security_headers_middleware`` (for
    the eventual header flip) read the same value. See BC-075.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})["csp_nonce"] = secrets.token_urlsafe(16)
        await self.app(scope, receive, send)


async def security_headers_middleware(request: Request, call_next):
    """Add security response headers (CSP, X-Content-Type-Options, etc.).

    The per-request CSP nonce is issued upstream by :class:`CSPNonceMiddleware`
    (``request.state.csp_nonce``) and consumed here by ``_build_csp(nonce)``: the
    emitted ``script-src`` is ``'self' 'nonce-{nonce}'`` with no ``'unsafe-inline'``
    (BC-075 flip done). ``style-src`` intentionally retains ``'unsafe-inline'`` for
    dynamic inline ``style=`` custom properties.
    """
    nonce = getattr(request.state, "csp_nonce", "")
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = _build_csp(nonce)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if _COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# ---------- FastAPI dependencies (replaces manual auth checks) ----------


def _may_write(request: Request, username: str) -> bool:
    """Return True if *username* is allowed to perform mutations.

    Uses the legacy write_users/admin_users lists only — RBAC is handled
    by the caller (``require_write``) through the AuthContext.
    """
    if not _is_auth_enabled(request):
        return True
    settings = getattr(request.app.state, "settings", None)
    if not settings:
        return True
    if not settings.write_users:
        return True
    if username in settings.write_users:
        return True
    return username in settings.admin_users


def _write_denied(request: Request, username: str) -> bool:
    """Return True if *username* must be denied write access.

    Single source of truth for the write decision shared by ``require_write``
    (API, raises) and ``require_write_form`` (HTML forms, redirects), so the
    two paths cannot diverge. When a role map is configured (Plan 035 RBAC),
    the request's AuthContext permissions decide; otherwise the legacy
    write_users/admin_users lists apply. A missing AuthContext under the
    role-map or API-key paths is treated as deny-by-default.
    """
    # API-key auth (Plan 039) always carries an explicit scope-derived
    # AuthContext, so its scope governs regardless of whether a role map is set
    # — otherwise a read-scoped key could write when no role map is configured.
    if getattr(request.state, "api_key_auth", False):
        api_ctx: AuthContext | None = getattr(request.state, "auth_context", None)
        return api_ctx is None or not api_ctx.may_write()
    settings = getattr(request.app.state, "settings", None)
    role_map = getattr(settings, "role_map", {}) if settings else {}
    if role_map:
        auth_ctx: AuthContext | None = getattr(request.state, "auth_context", None)
        return auth_ctx is None or not auth_ctx.may_write()
    return not _may_write(request, username)


def _admin_redirect_target(request: Request) -> str:
    """Return a sensible redirect URL for admin-form failures.

    Settings POSTs should bounce back to the settings page; other admin
    routes can pass their own via the helper. Falls back to ``/`` when the
    route is unknown.
    """
    path = request.url.path
    if path.startswith("/settings"):
        return "/settings"
    return "/"


def _admin_allowed(request: Request, user: str, *, use_legacy: bool = False) -> bool:
    """Check whether *user* may perform admin actions.

    The legacy ``admin_users`` list is an explicit allowlist only — an empty
    list never grants admin (fail-closed), so a misconfigured deployment
    cannot silently widen admin access.
    """
    settings = getattr(request.app.state, "settings", None)
    role_map = getattr(settings, "role_map", {}) if settings else {}
    ctx: AuthContext | None = getattr(request.state, "auth_context", None)
    if role_map or not use_legacy:
        return ctx is not None and ctx.is_admin
    admin_ok = ctx is not None and ctx.is_admin
    if not admin_ok:
        admin_list = getattr(settings, "admin_users", None) if settings else None
        if admin_list and user in admin_list:
            admin_ok = True
    return admin_ok


class _AuthResult(NamedTuple):
    user: str | None = None
    error: str | None = None
    api_key_auth: bool = False


def _set_request_auth_context(request: Request, username: str, info) -> None:
    settings = getattr(request.app.state, "settings", None)
    role_map = getattr(settings, "role_map", {}) if settings else {}
    role_repo = None
    if settings:
        try:
            from cert_watch.database.users_roles import SqliteRoleRepository
            role_repo = SqliteRoleRepository(settings.db_path)
        except (OSError, sqlite3.Error):
            pass
    auth_ctx = build_auth_context(
        username, info.groups, info.roles, role_map, role_repo=role_repo,
    )
    request.state.auth_context = auth_ctx
    request.scope["auth_user"] = username


def _resolve_session_user(request: Request) -> _AuthResult:
    token = request.cookies.get(SESSION_COOKIE, "")
    db_path = _request_db_path(request)
    _settings = getattr(request.app.state, "settings", None)
    _ttl = getattr(_settings, "session_ttl", None) if _settings else None
    info = decode_session(token, _request_security(request))
    username = (
        validate_session(
            token, _request_security(request),
            db_path=db_path, session_ttl=_ttl,
        )
        if info is not None
        else ""
    )
    if info is not None and username:
        _set_request_auth_context(request, username, info)
        return _AuthResult(user=username)
    api_ctx = authenticate_api_key(request, db_path)
    if api_ctx is not None:
        return _AuthResult(user=api_ctx.username, api_key_auth=True)
    return _AuthResult(error="unauthenticated")


def _check_auth(
    request: Request,
    *,
    resolve_session: bool = True,
    require_write: bool = False,
    require_admin: bool = False,
    admin_legacy: bool = False,
) -> _AuthResult:
    if not _is_auth_enabled(request):
        request.state.auth_context = AuthContext.full_access("")
        return _AuthResult(user="")

    if resolve_session:
        result = _resolve_session_user(request)
        user = result.user
        api_key_auth = result.api_key_auth
        error = result.error
    else:
        user = request.scope.get("auth_user")
        api_key_auth = getattr(request.state, "api_key_auth", False)
        error = None

    if error:
        return _AuthResult(error=error)
    if not user:
        return _AuthResult(error="unauthenticated")

    if require_write and _write_denied(request, user):
        return _AuthResult(user=user, error="read-only user")
    if require_admin and not _admin_allowed(request, user, use_legacy=admin_legacy):
        return _AuthResult(user=user, error="admin required")

    return _AuthResult(user=user, api_key_auth=api_key_auth)


async def _csrf_required_error(request: Request) -> str | None:
    if getattr(request.state, "api_key_auth", False):
        return None
    return await check_csrf(request)


async def require_auth(request: Request) -> str:
    """FastAPI dependency. Returns username or raises 401."""
    result = _check_auth(request)
    if result.error:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return result.user or ""


async def require_write(request: Request) -> str:
    """Auth + CSRF + write_users check. Returns username or raises 401/403."""
    result = _check_auth(request, require_write=True)
    if result.error:
        if result.error == "unauthenticated":
            raise HTTPException(status_code=401, detail="unauthenticated")
        raise HTTPException(status_code=403, detail=result.error)
    if _is_auth_enabled(request):
        csrf_err = await _csrf_required_error(request)
        if csrf_err:
            raise HTTPException(status_code=403, detail=csrf_err)
    return result.user or ""


async def require_admin(request: Request) -> str:
    """Auth + admin-permission check (no CSRF). Use for admin-scoped GETs."""
    result = _check_auth(request, require_admin=True)
    if result.error:
        if result.error == "unauthenticated":
            raise HTTPException(status_code=401, detail="unauthenticated")
        raise HTTPException(status_code=403, detail=result.error)
    return result.user or ""


async def require_admin_write(request: Request) -> str:
    """``require_admin`` + CSRF (skipped for API-key auth). Use for admin mutations."""
    result = _check_auth(request, require_admin=True)
    if result.error:
        if result.error == "unauthenticated":
            raise HTTPException(status_code=401, detail="unauthenticated")
        raise HTTPException(status_code=403, detail=result.error)
    if _is_auth_enabled(request):
        csrf_err = await _csrf_required_error(request)
        if csrf_err:
            raise HTTPException(status_code=403, detail=csrf_err)
    return result.user or ""


def require_admin_form(request: Request) -> RedirectResponse | None:
    """Form-POST helper: admin-only check (no CSRF), redirect on failure."""
    if not _is_auth_enabled(request):
        return None
    result = _check_auth(
        request, resolve_session=False, require_admin=True, admin_legacy=True,
    )
    if result.error:
        if result.error == "unauthenticated":
            return RedirectResponse(url="/login", status_code=303)
        return RedirectResponse(
            url=f"{_admin_redirect_target(request)}?error={quote(result.error)}",
            status_code=303,
        )
    return None


async def require_write_form(request: Request) -> RedirectResponse | None:
    """Form-POST helper: check write access + CSRF, return redirect on failure."""
    result = _check_auth(request, resolve_session=False, require_write=True)
    if result.error:
        if result.error == "unauthenticated":
            return RedirectResponse(url="/login", status_code=303)
        return RedirectResponse(url=f"/?error={quote(result.error)}", status_code=303)
    csrf_err = await _csrf_required_error(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    return None


async def require_admin_write_form(request: Request) -> RedirectResponse | None:
    """Form-POST helper: admin + write + CSRF check, redirect on failure."""
    result = _check_auth(
        request, resolve_session=False, require_admin=True, admin_legacy=True,
    )
    if result.error:
        if result.error == "unauthenticated":
            return RedirectResponse(url="/login", status_code=303)
        return RedirectResponse(
            url=f"{_admin_redirect_target(request)}?error={quote(result.error)}",
            status_code=303,
        )
    csrf_err = await _csrf_required_error(request)
    if csrf_err:
        return RedirectResponse(
            url=f"{_admin_redirect_target(request)}?error={quote(csrf_err)}",
            status_code=303,
        )
    return None


def rate_limit(key_prefix: str, max_requests: int, window_seconds: int):
    """FastAPI dependency factory for per-client-IP rate limiting (Plan 020 S2).

    Usage: ``deps=[Depends(rate_limit("ct", 10, 60))]`` (or a parameter
    ``_rl: None = Depends(rate_limit("ct", 10, 60))``). Raises
    ``HTTPException(429)`` when the limit is exceeded, and always uses
    ``_extract_client_ip()`` so proxy-aware identification is automatic — a
    new API route can't forget it.

    This is for JSON/API routes. Routes that return a ``RedirectResponse`` on
    limit (form POSTs like ``/hosts`` and ``/login``) must keep a manual
    ``check_rate_limit`` call, because a dependency can only raise, not return
    a redirect.
    """

    async def _dep(request: Request) -> None:
        client_ip = _extract_client_ip(request)
        if not check_rate_limit(f"{key_prefix}:{client_ip}", max_requests, window_seconds):
            raise HTTPException(status_code=429, detail="rate limited")

    return _dep
