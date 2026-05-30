"""CSRF, rate limiting, and auth middleware."""

from __future__ import annotations

import collections
import hashlib
import hmac
import logging
import os
import secrets
import threading
from datetime import UTC, datetime

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.auth import SESSION_COOKIE, NoAuthProvider, validate_session

logger = logging.getLogger("cert_watch.middleware")

_COOKIE_SECURE = os.environ.get("CERT_WATCH_COOKIE_SECURE", "1") == "1"

# ---------- CSRF protection (double-submit cookie) ----------

_CSRF_SECRET = os.environ.get("CERT_WATCH_CSRF_SECRET") or secrets.token_hex(32)
_CSRF_TOKEN_TTL = 3600 * 8  # 8 hours


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


# ---------- Rate limiting (in-memory sliding window) ----------

_rate_lock = threading.Lock()
_rate_windows: dict[str, collections.deque] = {}
_rate_last_activity: dict[str, float] = {}
_rate_last_sweep = 0.0
_RATE_SWEEP_INTERVAL = 300.0
_RATE_WINDOW_TTL = 600.0  # evict windows inactive for 10 minutes


def _sweep_rate_windows() -> None:
    """Remove entries with empty windows or stale last activity."""
    now = datetime.now(UTC).timestamp()
    for key in list(_rate_windows):
        if not _rate_windows[key] or (now - _rate_last_activity.get(key, 0)) > _RATE_WINDOW_TTL:
            _rate_windows.pop(key, None)
            _rate_last_activity.pop(key, None)


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    global _rate_last_sweep
    now = datetime.now(UTC).timestamp()
    with _rate_lock:
        if now - _rate_last_sweep > _RATE_SWEEP_INTERVAL:
            _sweep_rate_windows()
            _rate_last_sweep = now
        if key not in _rate_windows:
            _rate_windows[key] = collections.deque()
        window = _rate_windows[key]
        cutoff = now - window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= max_requests:
            return False
        window.append(now)
        _rate_last_activity[key] = now
        return True


def get_rate_remaining(key: str, max_requests: int, window_seconds: int) -> tuple[int, int]:
    """Return (remaining, retry_after_seconds) for the given rate limit window."""
    now = datetime.now(UTC).timestamp()
    with _rate_lock:
        window = _rate_windows.get(key, collections.deque())
        cutoff = now - window_seconds
        count = sum(1 for t in window if t >= cutoff)
        remaining = max(0, max_requests - count)
        oldest = min((t for t in window if t >= cutoff), default=now)
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
    "/healthz", "/login", "/auth/callback", "/auth/logout",
})


def is_public_path(path: str) -> bool:
    # NOTE: /api/* is intentionally NOT public. The data API (cert/host
    # inventory, CSV export, posture) requires auth when AUTH_PROVIDER is set;
    # unauthenticated API requests get a 401 (see auth_middleware). Only
    # liveness/scrape and the login flow stay open.
    return (
        path in _PUBLIC_PATHS
        or path.startswith("/static/")
        or path.startswith("/metrics")
    )


async def rate_limit_headers_middleware(request: Request, call_next):
    """Enforce rate limits on API routes and add X-RateLimit headers."""
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    client = request.client.host if request.client else "unknown"
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
            secure=_COOKIE_SECURE,
        )
        return response
    return await call_next(request)


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
