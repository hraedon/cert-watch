"""First-run setup wizard routes."""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __commit__, __version__
from cert_watch.auth import _scrypt_hash, build_auth_provider
from cert_watch.config import Settings
from cert_watch.database import kv_set
from cert_watch.middleware import get_csrf_context

logger = logging.getLogger("cert_watch.routes.setup")

router = APIRouter()

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _db_path(request: Request) -> Path:
    return _get_settings(request).db_path


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, step: int = 1, error: str | None = None) -> HTMLResponse:
    needs_setup = getattr(request.app.state, "needs_setup", False)
    if not needs_setup:
        return RedirectResponse(url="/", status_code=303)
    ctx = get_csrf_context(request)
    return templates.TemplateResponse(
        request=request,
        name="setup.html",
        context={
            "version": __version__, "commit": __commit__,
            "step": step,
            "error": error,
            **ctx,
        },
    )


@router.post("/setup")
async def setup_submit(
    request: Request,
    step: int = Form(1),
    username: str = Form(""),
    password: str = Form(""),
    password_confirm: str = Form(""),
    allowed_subnets: str = Form(""),
) -> RedirectResponse:
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(
            url=f"/setup?error={csrf_err}", status_code=303
        )
    needs_setup = getattr(request.app.state, "needs_setup", False)
    if not needs_setup:
        return RedirectResponse(url="/", status_code=303)
    db = _db_path(request)
    s = _get_settings(request)

    if step == 1:
        # Validate local admin creation
        username = username.strip()
        password = password.strip()
        password_confirm = password_confirm.strip()
        if not username or not password:
            return RedirectResponse(
                url="/setup?step=1&error=username+and+password+are+required", status_code=303
            )
        if len(username) < 3:
            return RedirectResponse(
                url="/setup?step=1&error=username+must+be+at+least+3+characters", status_code=303
            )
        if len(password) < 8:
            return RedirectResponse(
                url="/setup?step=1&error=password+must+be+at+least+8+characters", status_code=303
            )
        if password != password_confirm:
            return RedirectResponse(
                url="/setup?step=1&error=passwords+do+not+match", status_code=303
            )
        # Optional: scan-allowlist of private CIDRs (SSRF policy). Validate before
        # persisting so a typo doesn't half-complete setup.
        import ipaddress
        from dataclasses import replace as _dc_replace

        subnet_list = [c.strip() for c in allowed_subnets.split(",") if c.strip()]
        for cidr in subnet_list:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                return RedirectResponse(
                    url=f"/setup?step=1&error=invalid+subnet:+{quote(cidr)}", status_code=303
                )
        # Store in kv_store
        password_hash = _scrypt_hash(password)
        kv_set(db, "local_admin_user", username)
        kv_set(db, "local_admin_password_hash", password_hash)
        if subnet_list:
            kv_set(db, "allowed_subnets", ",".join(subnet_list))
            # Apply immediately to the running app (Settings is frozen).
            request.app.state.settings = _dc_replace(s, allowed_subnets=tuple(subnet_list))
            s = request.app.state.settings
            logger.info("setup wizard: scan allowlist set to %s", subnet_list)
        kv_set(db, "setup_complete", "1")

        # Rebuild auth provider with the new local admin
        auth = build_auth_provider(
            provider=s.auth_provider,
            ldap_server=s.ldap_server,
            ldap_base_dn=s.ldap_base_dn,
            ldap_bind_dn=s.ldap_bind_dn,
            ldap_bind_password=s.ldap_bind_password,
            ldap_user_filter=s.ldap_user_filter,
            ldap_start_tls=s.ldap_start_tls,
            ldap_ca_cert=s.ldap_ca_cert,
            ldap_required_groups=list(s.ldap_required_groups),
            ldap_connect_timeout=s.ldap_connect_timeout,
            oauth_client_id=s.oauth_client_id,
            oauth_client_secret=s.oauth_client_secret,
            oauth_issuer_url=s.oauth_issuer_url,
            oauth_scope=s.oauth_scope,
            oauth_authorization_endpoint=s.oauth_authorization_endpoint,
            oauth_token_endpoint=s.oauth_token_endpoint,
            oauth_userinfo_endpoint=s.oauth_userinfo_endpoint,
            allowed_groups=list(s.allowed_groups),
            allowed_roles=list(s.allowed_roles),
            local_admin_user=username,
            local_admin_password_hash=password_hash,
        )
        request.app.state.auth_provider = auth
        request.app.state.needs_setup = False

        logger.info("setup wizard: local admin '%s' created, auth enabled", username)
        return RedirectResponse(url="/", status_code=303)

    return RedirectResponse(url="/setup", status_code=303)