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

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.auth import SESSION_COOKIE, NoAuthProvider, validate_session

logger = logging.getLogger("cert_watch.middleware")

_COOKIE_SECURE = os.environ.get("CERT_WATCH_COOKIE_SECURE", "1") == "1"

# ---------- CSRF protection (double-submit cookie) ----------

_csrf_secret_val = os.environ.get("CERT_WATCH_CSRF_SECRET") or None
if not _csrf_secret_val:
    _csrf_secret_val = secrets.token_hex(32)
_CSRF_SECRET = _csrf_secret_val
_CSRF_TOKEN_TTL = 3600 * 8  # 8 hours


def set_csrf_secret(value: str) -> None:
    """Replace the module-level CSRF secret (used during lifespan startup)."""
    global _csrf_secret_val, _CSRF_SECRET
    _csrf_secret_val = value
    _CSRF_SECRET = value


def make_csrf_token(session_id: str) -> str:
    payload = f"{session_id}:{int(datetime.now(UTC).timestamp())}"
    sig = hmac.new(_CSRF_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{sig}"


def validate_csrf_token(token: str, session_id: str) -> bool:
    parts = token.split(":")
    if len(parts) != 3:
        return False
    ts_str, sig = parts[1], parts[2]
    payload = f"{session_id}:{ts_str}"
    expected = hmac.new(_CSRF_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
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


# ---------- Rate limiting (SQLite-backed sliding window, BC-049) ----------

_rate_lock = threading.Lock()
_rate_db_path: Path | None = None
# In-memory cache for reduced DB I/O (per-key, synced to SQLite)
_rate_cache: dict[str, list[float]] = {}
_RATE_CACHE_TTL = 10.0  # seconds before cache entry is considered stale
_RATE_STALE_TTL = 600.0  # evict rows stale for 10 minutes

_TRUST_PROXY = os.environ.get("CERT_WATCH_TRUST_PROXY", "") == "1"
_TRUSTED_PROXIES = frozenset(
    p.strip() for p in os.environ.get("CERT_WATCH_TRUSTED_PROXIES", "").split(",") if p.strip()
)


def _extract_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting X-Forwarded-For when trusted proxy is configured."""
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
            return parts[0] if parts else (request.client.host if request.client else "unknown")
    real_ip = request.headers.get("x-real-ip", "")
    if real_ip:
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


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if request is allowed, False if rate-limited.

    Uses SQLite for persistence so rate limits are shared across workers (BC-049).
    Falls back to in-memory mode when no database is configured.
    """
    now = datetime.now(UTC).timestamp()
    cutoff = now - window_seconds

    if _rate_db_path is None:
        # Fallback: in-memory only (single-worker mode)
        with _rate_lock:
            if key not in _rate_cache:
                _rate_cache[key] = []
            ts = [t for t in _rate_cache[key] if t >= cutoff]
            if len(ts) >= max_requests:
                _rate_cache[key] = ts
                return False
            ts.append(now)
            _rate_cache[key] = ts
            return True

    with _rate_lock:
        try:
            from cert_watch.database.connection import _connect
            from cert_watch.database.schema import init_schema

            init_schema(_rate_db_path)
            with _connect(_rate_db_path) as conn:
                # Periodic cleanup of stale entries
                cache_ts = _rate_cache.get(key)
                if cache_ts is not None and now - min(cache_ts, default=now) < _RATE_CACHE_TTL:
                    # Use cached timestamps (still valid within cache TTL)
                    ts = [t for t in cache_ts if t >= cutoff]
                else:
                    ts = _load_timestamps(conn, key, cutoff)

                if len(ts) >= max_requests:
                    _rate_cache[key] = ts
                    _save_timestamps(conn, key, ts)
                    conn.commit()
                    return False

                ts.append(now)
                _rate_cache[key] = ts
                _save_timestamps(conn, key, ts)
                conn.commit()
                return True
        except Exception:
            logger.debug("rate limit DB error, falling back to in-memory", exc_info=True)
            # Fallback to in-memory on DB errors
            if key not in _rate_cache:
                _rate_cache[key] = []
            ts = [t for t in _rate_cache[key] if t >= cutoff]
            if len(ts) >= max_requests:
                _rate_cache[key] = ts
                return False
            ts.append(now)
            _rate_cache[key] = ts
            return True


def get_rate_remaining(key: str, max_requests: int, window_seconds: int) -> tuple[int, int]:
    """Return (remaining, retry_after_seconds) for the given rate limit window."""
    now = datetime.now(UTC).timestamp()
    cutoff = now - window_seconds

    if _rate_db_path is not None:
        try:
            from cert_watch.database.connection import _connect

            with _connect(_rate_db_path) as conn:
                ts = _load_timestamps(conn, key, cutoff)
        except Exception:
            ts = [t for t in _rate_cache.get(key, []) if t >= cutoff]
    else:
        ts = [t for t in _rate_cache.get(key, []) if t >= cutoff]

    count = len(ts)
    remaining = max(0, max_requests - count)
    oldest = min(ts, default=now)
    retry_after = max(0, int(window_seconds - (now - oldest)))
    return remaining, retry_after


async def check_csrf(request: Request) -> str | None:
    """Validate CSRF double-submit cookie. Returns error message or None.

    Checks: x-csrf-token header, _csrf_token form field, then query param (fallback).
    Skipped when CERT_WATCH_CSRF_DISABLED=1 (for testing).
    """
    if os.environ.get("CERT_WATCH_CSRF_DISABLED") == "1":
        return None
    token = request.headers.get("x-csrf-token") or request.query_params.get("_csrf_token") or ""
    if not token:
        try:
            form = await request.form()
            token = form.get("_csrf_token", "")
        except Exception:
            pass
    if not token:
        return "missing CSRF token"
    session_id = request.cookies.get("cw_sid", "")
    if not validate_csrf_token(token, session_id):
        return "invalid or expired CSRF token"
    return None


def get_csrf_context(request: Request) -> dict:
    """Return template context dict with CSRF token for the current session."""
    session_id = get_session_id(request)
    token = make_csrf_token(session_id)
    return {"csrf_token": token}


# ---------- Middleware functions ----------

_PUBLIC_PATHS = frozenset({
    "/healthz", "/login", "/auth/callback", "/auth/logout", "/setup",
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
    return path.startswith("/metrics")


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
        response.set_cookie(
            "cw_sid", sid, httponly=False, samesite="strict", max_age=_CSRF_TOKEN_TTL,
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


async def auth_middleware(request: Request, call_next):
    """Enforce authentication when AUTH_PROVIDER is configured.

    Public paths (/healthz, /metrics, /static, /login, /auth/*) are exempt.
    The /api/* data routes require auth: unauthenticated API requests get a
    401, unauthenticated UI requests redirect to /login.
    """
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return await call_next(request)

    path = request.url.path
    if is_public_path(path):
        return await call_next(request)

    token = request.cookies.get(SESSION_COOKIE, "")
    username = validate_session(token)
    if username:
        request.scope["auth_user"] = username
        return await call_next(request)

    # Unauthenticated
    if path.startswith("/api/"):
        return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
    return RedirectResponse(url="/login", status_code=303)


_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)


async def security_headers_middleware(request: Request, call_next):
    """Add security response headers (CSP, X-Content-Type-Options, etc.)."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = _CSP_HEADER
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
