"""Login, OAuth, and logout routes."""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __commit__, __version__
from cert_watch.auth import (
    SESSION_COOKIE,
    SESSION_TTL,
    LocalAdminProvider,
    NoAuthProvider,
    _CompositeProvider,
    check_authz,
    create_session,
)
from cert_watch.middleware import (
    _COOKIE_SECURE,
    _extract_client_ip,
    _request_security,
    check_csrf,
    check_rate_limit,
)

logger = logging.getLogger("cert_watch.routes.auth")

router = APIRouter()

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None) -> HTMLResponse:
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
            "supports_form_login": auth.supports_form_login,
            "local_admin_configured": local_admin_configured,
            "error": error,
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
        except Exception:
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
    token = create_session(result.username, _request_security(request))
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL,
        secure=_COOKIE_SECURE, path="/",
    )
    logger.info(
        "user logged in: %s (%s)",
        result.username,
        "local-admin" if is_break_glass else auth.provider_name,
    )
    return response


def _get_base_url(request: Request) -> str:
    """Return base URL for OAuth redirect URIs.

    Prefers CERT_WATCH_BASE_URL when set (prevents Host header injection).
    Falls back to request.base_url.
    """
    settings = getattr(request.app.state, "settings", None)
    base = getattr(settings, "base_url", "") if settings else ""
    return base or str(request.base_url).rstrip("/")


@router.get("/auth/login")
def oauth_start(request: Request) -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    base = _get_base_url(request)
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
            samesite="lax",
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
            "cw_oauth_state", httponly=True, samesite="lax", secure=_COOKIE_SECURE,
        )
        return response
    if not code:
        response = RedirectResponse(
            url="/login?error=no+authorization+code", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="lax", secure=_COOKIE_SECURE,
        )
        return response
    signed_state = request.cookies.get("cw_oauth_state", "")
    if not signed_state:
        response = RedirectResponse(
            url="/login?error=OAuth+state+cookie+missing", status_code=303
        )
        return response
    from cert_watch.auth import _verify_state as _verify_oauth_state
    cookie_raw = _verify_oauth_state(signed_state)
    if cookie_raw is None or cookie_raw != state:
        response = RedirectResponse(
            url="/login?error=OAuth+state+mismatch", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="lax", secure=_COOKIE_SECURE,
        )
        return response
    base = _get_base_url(request)
    redirect_uri = f"{base}/auth/callback"
    result = auth.complete_oauth_flow(code, redirect_uri, state=signed_state)
    if not result.success:
        response = RedirectResponse(
            url=f"/login?error={quote(result.error or 'OAuth failed')}", status_code=303
        )
        response.delete_cookie(
            "cw_oauth_state", httponly=True, samesite="lax", secure=_COOKIE_SECURE,
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
            "cw_oauth_state", httponly=True, samesite="lax", secure=_COOKIE_SECURE,
        )
        return response
    token = create_session(result.username, _request_security(request))
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(
        "cw_oauth_state", httponly=True, samesite="lax", secure=_COOKIE_SECURE,
    )
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL,
        secure=_COOKIE_SECURE, path="/",
    )
    logger.info("user logged in via OAuth: %s", result.username)
    return response


@router.post("/auth/logout")
async def logout(request: Request) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(
        SESSION_COOKIE, httponly=True, samesite="strict", secure=_COOKIE_SECURE,
    )
    return response
