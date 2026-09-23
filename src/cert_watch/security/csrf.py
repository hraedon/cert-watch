"""Double-submit CSRF protection: token mint/validate, session binding, the
per-request check, and the ``cw_sid`` cookie middleware.

Route code never calls :func:`check_csrf` itself: every write/admin guard in
:mod:`cert_watch.auth.guards` runs it. The pre-session routes (``/login``,
``/setup``, ``/auth/logout``) are the only direct callers.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from cert_watch.auth import SESSION_COOKIE
from cert_watch.security import SecurityContext, _request_security

_COOKIE_SECURE = os.environ.get("CERT_WATCH_COOKIE_SECURE", "1") == "1"

# ---------- CSRF protection (double-submit cookie) ----------

_csrf_secret_val = os.environ.get("CERT_WATCH_CSRF_SECRET") or None
if not _csrf_secret_val:
    _csrf_secret_val = secrets.token_hex(32)
_CSRF_SECRET = _csrf_secret_val
_CSRF_TOKEN_TTL = 3600 * 2  # 2 hours
_SID_COOKIE_TTL = 3600 * 8  # 8 hours — matches session cookie TTL

# Test-only flag: when True, check_csrf() auto-generates and validates a token
# instead of requiring one from the request. Never enabled in production.
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
        return cast(str, scope_sid)
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


def get_csrf_context(request: Request) -> dict[str, Any]:
    """Return template context dict with CSRF token for the current session."""
    session_token = get_session_token(request)
    token = make_csrf_token(session_token, _request_security(request))
    return {"csrf_token": token}


async def csrf_session_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
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
