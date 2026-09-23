"""Who is making this request: session and API-key authentication, the
per-request :class:`~cert_watch.auth.rbac.AuthContext`, public-path rules and
the ``auth_middleware`` that enforces them.

There is exactly one AuthContext builder for a cookie session,
:func:`attach_session_context`, used both by ``auth_middleware`` (every
request) and by the guards' session re-resolution
(:func:`resolve_session_user`), so the two paths cannot drift.
"""

from __future__ import annotations

import hmac
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from cert_watch.auth import SESSION_COOKIE, NoAuthProvider, decode_session, validate_session
from cert_watch.auth.rbac import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    AuthContext,
    build_auth_context,
)
from cert_watch.security import _request_security

if TYPE_CHECKING:
    from cert_watch.auth.session import SessionInfo


def _is_auth_enabled(request: Request) -> bool:
    """Return True when an auth provider is configured (not NoAuthProvider)."""
    auth = getattr(request.app.state, "auth_provider", None)
    return auth is not None and not isinstance(auth, NoAuthProvider)


def _request_db_path(request: Request) -> str | None:
    """The database path from app.state.settings, if available (BC-081)."""
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        return str(settings.db_path)
    return None


# ---------- public paths + metrics token ----------

# Every /auth/* route is part of the pre-session login flow and is listed here
# explicitly (#58: /auth/login, the OAuth start, was missing, so the only OAuth
# entry point bounced to /login). No /auth/ prefix rule, so a future /auth/*
# route is private until it is added deliberately.
_PUBLIC_PATHS = frozenset({
    "/healthz", "/readyz", "/login", "/auth/login", "/auth/callback", "/auth/logout",
    "/setup", "/favicon.ico",
})

_METRICS_TOKEN: str | None = None  # Direct-call/test fallback.


def _metrics_token(request: Request | None = None) -> str:
    if _METRICS_TOKEN is not None:
        return _METRICS_TOKEN
    app = request.scope.get("app") if request is not None else None
    settings = getattr(getattr(app, "state", None), "settings", None)
    value = getattr(settings, "metrics_token", "")
    return value if isinstance(value, str) else ""


def is_public_path(path: str, request: Request | None = None) -> bool:
    # NOTE: /api/* is intentionally NOT public. The data API (cert/host
    # inventory, CSV export, posture) requires auth when AUTH_PROVIDER is set;
    # unauthenticated API requests get a 401 (see auth_middleware). Only
    # liveness/scrape and the login flow stay open.
    normalized = path.rstrip("/")
    if normalized in _PUBLIC_PATHS:
        return True
    if normalized == "/metrics":
        # /metrics is public only when gated by a bearer token
        # (CERT_WATCH_METRICS_TOKEN). Without a token, it requires a
        # session to prevent fleet metadata disclosure.
        return bool(_metrics_token(request))
    return bool(path.startswith("/static/"))


def check_metrics_token(request: Request) -> bool:
    """Check bearer token for /metrics when CERT_WATCH_METRICS_TOKEN is set.

    Returns True if the request is authorized (or no token is configured).
    """
    metrics_token = _metrics_token(request)
    if not metrics_token:
        return True
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return hmac.compare_digest(token, metrics_token)
    return False


def metrics_token_configured(request: Request) -> bool:
    """Return whether this app configured the dedicated metrics bearer token."""
    return bool(_metrics_token(request))


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

    result = SqliteApiKeyRepository(
        db_path, security=_request_security(request)
    ).verify_key(token)
    if result is None:
        return None
    role = _API_KEY_SCOPE_ROLE.get(result.scope, ROLE_VIEWER)
    ctx = AuthContext.from_tier(result.name, tier=role, roles=[role])
    request.scope["auth_user"] = result.name
    request.state.auth_context = ctx
    request.state.api_key_auth = True
    return ctx


# ---------- cookie sessions ----------


def attach_session_context(request: Request, username: str, info: SessionInfo) -> AuthContext:
    """Build the AuthContext for a validated cookie session and attach it.

    The single builder for session requests (BC-145: IdP groups/roles from
    the cookie resolve through the role map on every request, so form routes
    and templates enforce RBAC even when they never touch a guard). Sets
    ``request.state.auth_context`` and ``request.scope['auth_user']``.
    """
    settings = getattr(request.app.state, "settings", None)
    role_map = getattr(settings, "role_map", {}) if settings else {}
    role_repo = user_repo = None
    if settings:
        try:
            from cert_watch.database.users_roles import (
                SqliteRoleRepository,
                SqliteUserRepository,
            )
            role_repo = SqliteRoleRepository(settings.db_path)
            user_repo = SqliteUserRepository(settings.db_path)
        except (OSError, sqlite3.Error):
            pass
    auth_ctx = build_auth_context(
        username, info.groups, info.roles, role_map,
        role_repo=role_repo, user_repo=user_repo,
        write_users=tuple(getattr(settings, "write_users", ()) or ()),
        admin_users=tuple(getattr(settings, "admin_users", ()) or ()),
    )
    request.state.auth_context = auth_ctx
    request.scope["auth_user"] = username
    return auth_ctx


def _session_ttl(request: Request) -> int | None:
    settings = getattr(request.app.state, "settings", None)
    return getattr(settings, "session_ttl", None) if settings else None


class SessionUser(NamedTuple):
    user: str | None = None
    error: str | None = None
    api_key_auth: bool = False


def resolve_session_user(request: Request) -> SessionUser:
    """Authenticate the request from its session cookie, else an API key.

    Attaches the AuthContext on success. ``error`` is ``"unauthenticated"``
    when neither credential is valid.
    """
    token = request.cookies.get(SESSION_COOKIE, "")
    db_path = _request_db_path(request)
    info = decode_session(token, _request_security(request))
    username = (
        validate_session(
            token, _request_security(request),
            db_path=db_path, session_ttl=_session_ttl(request),
        )
        if info is not None
        else ""
    )
    if info is not None and username:
        attach_session_context(request, username, info)
        return SessionUser(user=username)
    api_ctx = authenticate_api_key(request, db_path)
    if api_ctx is not None:
        return SessionUser(user=api_ctx.username, api_key_auth=True)
    return SessionUser(error="unauthenticated")


async def auth_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Enforce authentication when AUTH_PROVIDER is configured.

    Public paths (/healthz, token-gated /metrics, /static, /login, /auth/*) are exempt.
    The /api/* data routes require auth: unauthenticated API requests get a
    401, unauthenticated UI requests redirect to /login.
    """
    if not _is_auth_enabled(request):
        return await call_next(request)

    path = request.url.path
    if is_public_path(path, request):
        return await call_next(request)

    if resolve_session_user(request).error is None:
        return await call_next(request)

    # Unauthenticated
    if path.rstrip("/") == "/metrics" or path.startswith("/api/"):
        return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
    return RedirectResponse(url="/login", status_code=303)
