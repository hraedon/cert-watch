"""Login, OAuth, and logout routes."""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __version__
from cert_watch.auth import SESSION_COOKIE, SESSION_TTL, NoAuthProvider, create_session
from cert_watch.middleware import _COOKIE_SECURE

logger = logging.getLogger("cert_watch.routes.auth")

router = APIRouter()

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "version": __version__,
            "provider": auth.provider_name,
            "supports_form_login": auth.supports_form_login,
            "error": error,
        },
    )


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    result = auth.authenticate(username, password)
    if not result.success:
        return RedirectResponse(
            url=f"/login?error={quote(result.error or 'login failed')}", status_code=303
        )
    token = create_session(result.username)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL,
        secure=_COOKIE_SECURE,
    )
    logger.info("user logged in: %s (%s)", result.username, auth.provider_name)
    return response


@router.get("/auth/login")
def oauth_start(request: Request) -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/auth/callback"
    result = auth.start_oauth_flow(redirect_uri)
    if not result.success:
        return RedirectResponse(
            url=f"/login?error={quote(result.error or 'OAuth start failed')}", status_code=303
        )
    response = RedirectResponse(url=result.redirect_url, status_code=303)
    # BC-009: store signed state in a cookie for callback verification
    if result.error:
        response.set_cookie(
            "cw_oauth_state",
            result.error,
            httponly=True,
            samesite="lax",
            max_age=600,
            secure=_COOKIE_SECURE,
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
        response.delete_cookie("cw_oauth_state")
        return response
    if not code:
        response = RedirectResponse(
            url="/login?error=no+authorization+code", status_code=303
        )
        response.delete_cookie("cw_oauth_state")
        return response
    # BC-009: verify state parameter
    signed_state = request.cookies.get("cw_oauth_state", "")
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/auth/callback"
    result = auth.complete_oauth_flow(code, redirect_uri, state=signed_state)
    if not result.success:
        response = RedirectResponse(
            url=f"/login?error={quote(result.error or 'OAuth failed')}", status_code=303
        )
        response.delete_cookie("cw_oauth_state")
        return response
    token = create_session(result.username)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("cw_oauth_state")
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL,
        secure=_COOKIE_SECURE,
    )
    logger.info("user logged in via OAuth: %s", result.username)
    return response


@router.get("/auth/logout")
def logout(request: Request) -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response
