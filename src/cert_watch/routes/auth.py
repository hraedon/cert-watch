"""Login, OAuth, and logout routes."""

from __future__ import annotations

import hmac
import logging
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.auth import (
    SESSION_COOKIE,
    LocalAdminProvider,
    NoAuthProvider,
    _CompositeProvider,
    check_authz,
    create_session,
)
from cert_watch.auth.rbac import claims_for_session
from cert_watch.database import bump_session_version, get_session_version
from cert_watch.middleware import (
    _COOKIE_SECURE,
    _extract_client_ip,
    _request_security,
    check_csrf,
    check_rate_limit,
    get_csrf_context,
)
from cert_watch.routes._deps import get_templates

logger = logging.getLogger("cert_watch.routes.auth")

router = APIRouter()

templates = get_templates()


@router.get("/login", response_class=HTMLResponse, response_model=None)
def login_page(request: Request, error: str | None = None) -> HTMLResponse | RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    local_admin_configured = type(auth).__name__ in ("LocalAdminProvider", "_CompositeProvider")
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "version": __version__, "commit": __commit__,
            "provider": auth.provider_name,
            "provider_label": getattr(auth, "provider_label", auth.provider_name),
            "supports_form_login": auth.supports_form_login,
            "local_admin_configured": local_admin_configured,
            "error": error,
            # CSRF token so POST /login can enforce the double-submit check
            # (login CSRF, review #19). cw_sid is issued to unauthenticated
            # visitors too, so the token binds to it.
            **get_csrf_context(request),
        },
    )


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    client_ip = _extract_client_ip(request)
    if not check_rate_limit(f"login:{client_ip}", 10, 300):
        return RedirectResponse(
            url="/login?error=rate+limited:+too+many+login+attempts", status_code=303
        )
    # Login CSRF (review #19): reuse the existing double-submit machinery
    # (cw_sid cookie + form token) rather than a bespoke per-IP nonce. The login
    # page renders the token; reject a POST that doesn't carry a matching one.
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(
            url=f"/login?error={quote(csrf_err)}", status_code=303
        )
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    result = auth.authenticate(username, password)
    if not result.success:
        return RedirectResponse(
            url=f"/login?error={quote(result.error or 'login failed')}", status_code=303
        )
    is_break_glass = isinstance(auth, LocalAdminProvider) or (
        isinstance(auth, _CompositeProvider) and result.username == auth._local.username
    )
    if is_break_glass:
        logger.warning("Break-glass login by local admin: %s", result.username)
        try:
            settings = getattr(request.app.state, "settings", None)
            if settings:
                from cert_watch.audit import record_audit
                record_audit(
                    settings.db_path,
                    actor=result.username,
                    action="break_glass_login",
                    target_type="session",
                    target_id=result.username,
                    detail={"break_glass": True},
                    source_ip=_extract_client_ip(request) if request else None,
                )
        except OSError:
            logger.debug("audit log write failed for break-glass login", exc_info=True)
    else:
        settings = getattr(request.app.state, "settings", None)
        allowed_groups = list(settings.allowed_groups) if settings else []
        allowed_roles = list(settings.allowed_roles) if settings else []
        result = check_authz(result, allowed_groups, allowed_roles)
        if not result.success:
            return RedirectResponse(
                url=f"/login?error={quote(result.error or 'access denied')}", status_code=303
            )
    # BC-081: embed current session version in the token
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        raise RuntimeError("settings not initialized on app.state")
    _db_path = str(settings.db_path)
    version = get_session_version(_db_path, result.username)
    # BC-029 D: ensure stored version is >= 1 so old 3-part tokens are phased out
    if version == 0:
        bump_session_version(settings.db_path, result.username)
        version = get_session_version(_db_path, result.username)
    # Store only role-map-relevant claims in the cookie — a full AD memberOf
    # list can overflow the browser's ~4 KB cookie limit and cause a silent
    # post-login redirect loop (see claims_for_session).
    role_map = getattr(settings, "role_map", {}) or {}
    stored_groups, stored_roles = claims_for_session(result.groups, result.roles, role_map)
    token = create_session(
        result.username,
        _request_security(request),
        version=version,
        groups=stored_groups,
        roles=stored_roles,
        email=result.email,
    )
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict",
        max_age=settings.session_ttl,
        secure=_COOKIE_SECURE, path="/",
    )
    logger.info(
        "user logged in: %s (%s)",
        result.username,
        "local-admin" if is_break_glass else auth.provider_name,
    )
    return response


def _get_base_url(request: Request) -> str:
    """Return the configured OAuth base URL (``CERT_WATCH_BASE_URL``), or "".

    Deliberately does **not** fall back to ``request.base_url`` (review #3): the
    redirect_uri must never be derived from the attacker-influenced Host header,
    or a Host-injection / rebinding attack could steer the IdP's redirect to an
    attacker-controlled callback. Callers refuse to start OAuth when this is
    empty.
    """
    settings = getattr(request.app.state, "settings", None)
    return getattr(settings, "base_url", "") if settings else ""


@router.get("/auth/login")
def oauth_start(request: Request) -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    base = _get_base_url(request)
    if not base:
        return RedirectResponse(
            url="/login?error=OAuth+redirect+URI+not+configured:+set+CERT_WATCH_BASE_URL",
            status_code=303,
        )
    redirect_uri = f"{base}/auth/callback"
    result = auth.start_oauth_flow(redirect_uri)
    if not result.success:
        return RedirectResponse(
            url=f"/login?error={quote(result.error or 'OAuth start failed')}", status_code=303
        )
    response = RedirectResponse(url=result.redirect_url, status_code=303)
    # BC-009: store signed state in a cookie for callback verification
    if result.oauth_state:
        response.set_cookie(
            "cw_oauth_state",
            result.oauth_state,
            httponly=True,
            samesite="strict",
            max_age=600,
            secure=_COOKIE_SECURE,
            path="/",
        )
    return response


@router.get("/auth/callback")
def oauth_callback(
    request: Request,
    code: str = "",
    error: str = "",
    state: str = "",
) -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    if error:
        response = RedirectResponse(
            url=f"/login?error={quote(error)}", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="strict", secure=_COOKIE_SECURE,
        )
        return response
    if not code:
        response = RedirectResponse(
            url="/login?error=no+authorization+code", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="strict", secure=_COOKIE_SECURE,
        )
        return response
    signed_state = request.cookies.get("cw_oauth_state", "")
    if not signed_state:
        response = RedirectResponse(
            url="/login?error=OAuth+state+cookie+missing", status_code=303
        )
        return response
    from cert_watch.auth import _verify_state as _verify_oauth_state
    verify_result = _verify_oauth_state(signed_state, security=_request_security(request))
    if verify_result is None:
        response = RedirectResponse(
            url="/login?error=OAuth+state+mismatch", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="strict", secure=_COOKIE_SECURE,
        )
        return response
    cookie_raw, _nonce, _verifier = verify_result
    if not hmac.compare_digest(cookie_raw, state):
        response = RedirectResponse(
            url="/login?error=OAuth+state+mismatch", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="strict", secure=_COOKIE_SECURE,
        )
        return response
    base = _get_base_url(request)
    if not base:
        return RedirectResponse(
            url="/login?error=OAuth+redirect+URI+not+configured:+set+CERT_WATCH_BASE_URL",
            status_code=303,
        )
    redirect_uri = f"{base}/auth/callback"
    result = auth.complete_oauth_flow(code, redirect_uri, state=signed_state)
    if not result.success:
        response = RedirectResponse(
            url=f"/login?error={quote(result.error or 'OAuth failed')}", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="strict", secure=_COOKIE_SECURE,
        )
        return response
    # Authorization gate: check group/role membership
    settings = getattr(request.app.state, "settings", None)
    allowed_groups = list(settings.allowed_groups) if settings else []
    allowed_roles = list(settings.allowed_roles) if settings else []
    result = check_authz(result, allowed_groups, allowed_roles)
    if not result.success:
        response = RedirectResponse(
            url=f"/login?error={quote(result.error or 'access denied')}", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="strict", secure=_COOKIE_SECURE,
        )
        return response
    # BC-081: embed current session version in the token
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        raise RuntimeError("settings not initialized on app.state")
    _db_path = str(settings.db_path)
    version = get_session_version(_db_path, result.username)
    # BC-029 D: ensure stored version is >= 1 so old 3-part tokens are phased out
    if version == 0:
        bump_session_version(settings.db_path, result.username)
        version = get_session_version(_db_path, result.username)
    # Store only role-map-relevant claims in the cookie — a full AD memberOf
    # list can overflow the browser's ~4 KB cookie limit and cause a silent
    # post-login redirect loop (see claims_for_session).
    role_map = getattr(settings, "role_map", {}) or {}
    stored_groups, stored_roles = claims_for_session(result.groups, result.roles, role_map)
    token = create_session(
        result.username,
        _request_security(request),
        version=version,
        groups=stored_groups,
        roles=stored_roles,
        email=result.email,
    )
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict",
        max_age=settings.session_ttl,
        secure=_COOKIE_SECURE, path="/",
    )
    response.delete_cookie(
        "cw_oauth_state", httponly=True, samesite="strict", secure=_COOKIE_SECURE,
    )
    logger.info("user logged in via OAuth: %s", result.username)
    return response


@router.post("/auth/logout")
async def logout(request: Request) -> RedirectResponse:
    # /auth/logout is intentionally a public path so expired sessions can still
    # log out (BC-081 / middleware._PUBLIC_PATHS). Only enforce CSRF here — no
    # auth/role check, matching the prior behavior.
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    # BC-081: bump session version to revoke all active sessions for this user.
    # /auth/logout is a public path (auth_middleware skips it so expired sessions
    # can still log out), so auth_user may not be set. Read the cookie directly.
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        settings = getattr(request.app.state, "settings", None)
        if settings:
            db_path = str(settings.db_path)
            from cert_watch.auth import validate_session
            from cert_watch.middleware import _request_security
            username = validate_session(token, _request_security(request), db_path=db_path)
            if username:
                bump_session_version(settings.db_path, username)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(
        SESSION_COOKIE, httponly=True, samesite="strict", secure=_COOKIE_SECURE,
    )
    return response
