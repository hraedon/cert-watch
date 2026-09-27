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
import logging
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


logger = logging.getLogger("cert_watch.auth.request_context")


class BearerCredentials(NamedTuple):
    """A strictly parsed Authorization header.

    cert-watch accepts exactly one ``Authorization`` field containing an
    exact-case ``Bearer`` scheme, one ASCII space, and a whitespace-free
    token.  Keeping this parser shared prevents the report-key precheck,
    API-key authentication, and metrics authentication from disagreeing.
    """

    token: str | None = None
    malformed: bool = False


def parse_bearer_credentials(request: Request) -> BearerCredentials:
    """Return the single strict bearer token, or classify a malformed header."""
    values = [
        value
        for name, value in request.scope.get("headers", ())
        if name.lower() == b"authorization"
    ]
    if not values:
        return BearerCredentials()
    if len(values) != 1:
        return BearerCredentials(malformed=True)
    try:
        value = values[0].decode("latin-1")
    except UnicodeDecodeError:
        return BearerCredentials(malformed=True)
    if not value.startswith("Bearer "):
        return BearerCredentials(malformed=True)
    token = value[7:]
    if not token or any(char.isspace() for char in token):
        return BearerCredentials(malformed=True)
    return BearerCredentials(token=token)


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
    credentials = parse_bearer_credentials(request)
    return credentials.token is not None and hmac.compare_digest(
        credentials.token, metrics_token
    )


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

_RENEWAL_REPORT_SCOPE = "renewal-report"
_RENEWAL_REPORT_ROUTES = frozenset({
    ("GET", "/api/renewal-reports"),
    ("POST", "/api/renewal-reports"),
})
_RENEWAL_REPORT_FORBIDDEN = "forbidden for this key"


def _is_renewal_report_route(request: Request) -> bool:
    raw_path = request.scope.get("raw_path")
    if not isinstance(raw_path, bytes):
        raw_path = request.scope.get("path", "").encode("utf-8")
    return (request.method, raw_path) in {
        (method, path.encode("ascii")) for method, path in _RENEWAL_REPORT_ROUTES
    }


def authenticate_api_key(
    request: Request,
    db_path: str | Path | None,
    *,
    renewal_report_only: bool = False,
) -> AuthContext | None:
    """Authenticate an ``Authorization: Bearer cwk_…`` API key.

    On success, sets ``request.scope['auth_user']`` to the key name, stores the
    derived ``AuthContext`` on ``request.state.auth_context``, flags
    ``request.state.api_key_auth = True`` (so CSRF is skipped for the token
    path), and returns the context. Returns ``None`` when no valid key is
    presented — leaving cookie-session auth and metrics-token auth untouched.
    """
    credentials = parse_bearer_credentials(request)
    token = credentials.token
    if token is None:
        return None
    if not token.startswith("cwk_") or not db_path:
        return None
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    repo = SqliteApiKeyRepository(db_path, security=_request_security(request))
    # Verification is deliberately side-effect free until route authorization
    # succeeds. A report credential refused by the capability allowlist must
    # not gain last_used_at or a signing-pepper hash upgrade.
    result = repo.verify_key(
        token, renewal_report_only=renewal_report_only, record_use=False
    )
    if result is None:
        return None
    if result.scope == _RENEWAL_REPORT_SCOPE:
        if not _is_renewal_report_route(request):
            request.state.api_key_forbidden = True
            return None
        if repo.verify_key(
            token, renewal_report_only=True, record_use=True
        ) is None:
            return None
        ctx = AuthContext.renewal_report_key(
            result.name,
            principal_id=result.id,
            binding=result.binding,
            bound_tags=result.bound_tags,
        )
        request.scope["auth_user"] = result.name
        request.state.auth_context = ctx
        request.state.api_key_auth = True
        return ctx
    role = _API_KEY_SCOPE_ROLE.get(result.scope)
    if role is None:
        logger.warning("rejecting API key %s with unknown scope", result.id)
        return None
    if repo.verify_key(token, record_use=True) is None:
        return None
    ctx = AuthContext.from_tier(
        result.name,
        tier=role,
        roles=[role],
        principal_id=result.id,
        principal_kind="api-key",
    )
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
    if getattr(request.state, "api_key_forbidden", False):
        return SessionUser(error=_RENEWAL_REPORT_FORBIDDEN, api_key_auth=True)
    existing = getattr(request.state, "auth_context", None)
    if (
        existing is not None
        and getattr(existing, "principal_kind", "") == _RENEWAL_REPORT_SCOPE
    ):
        return SessionUser(user=existing.username, api_key_auth=True)

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
    if getattr(request.state, "api_key_forbidden", False):
        return SessionUser(error=_RENEWAL_REPORT_FORBIDDEN, api_key_auth=True)
    return SessionUser(error="unauthenticated")


async def auth_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Enforce authentication when AUTH_PROVIDER is configured.

    Public paths (/healthz, token-gated /metrics, /static, /login, /auth/*) are exempt.
    The /api/* data routes require auth: unauthenticated API requests get a
    401, unauthenticated UI requests redirect to /login.
    """
    path = request.url.path
    # Renewal-report keys are capability credentials with a two-route
    # allowlist. Inspect them before public-path routing so every other path,
    # including static files and unknown routes, has one indistinguishable
    # refusal. Existing key scopes retain their normal route behaviour.
    credentials = parse_bearer_credentials(request)
    if credentials.malformed:
        return JSONResponse(
            content={"error": "malformed authorization"}, status_code=401
        )
    if credentials.token and credentials.token.startswith("cwk_"):
        api_ctx = authenticate_api_key(
            request, _request_db_path(request), renewal_report_only=True
        )
        if getattr(request.state, "api_key_forbidden", False):
            return JSONResponse(
                content={"error": _RENEWAL_REPORT_FORBIDDEN}, status_code=403
            )
        if (
            api_ctx is not None
            and getattr(api_ctx, "principal_kind", "") == _RENEWAL_REPORT_SCOPE
        ):
            return await call_next(request)
    if not _is_auth_enabled(request):
        return await call_next(request)
    if is_public_path(path, request):
        return await call_next(request)

    if resolve_session_user(request).error is None:
        return await call_next(request)

    # Unauthenticated
    cert_watch_key_presented = bool(
        credentials.token and credentials.token.startswith("cwk_")
    )
    if (
        cert_watch_key_presented
        or path.rstrip("/") == "/metrics"
        or path.startswith("/api/")
    ):
        return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
    return RedirectResponse(url="/login", status_code=303)
