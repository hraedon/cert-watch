"""First-run setup wizard routes."""

from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.auth import _scrypt_hash
from cert_watch.database import kv_set
from cert_watch.database.queries import bump_session_version
from cert_watch.middleware import check_csrf, get_csrf_context
from cert_watch.routes._deps import _db_path, _get_settings, get_templates

logger = logging.getLogger("cert_watch.routes.setup")

router = APIRouter()

templates = get_templates()


@router.get("/setup", response_class=HTMLResponse, response_model=None)
def setup_page(
    request: Request,
    step: int = 1,
    error: str | None = None,
) -> HTMLResponse | RedirectResponse:
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
    # /setup is intentionally callable when no auth is configured (first-run
    # wizard). CSRF is still required (review #19) and the failure target
    # must be /setup (not /) so the wizard can re-render. Authenticated
    # users reaching this path get bounced to / (handled by the
    # needs_setup check below).
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
        auth = s.build_auth_provider()
        request.app.state.auth_provider = auth
        request.app.state.needs_setup = False

        # BC-081: bump session version to invalidate any pre-setup sessions
        # (defensive — there shouldn't be any, but the gate should be explicit)
        bump_session_version(db, username)

        logger.info("setup wizard: local admin '%s' created, auth enabled", username)
        return RedirectResponse(url="/", status_code=303)

    return RedirectResponse(url="/setup", status_code=303)
