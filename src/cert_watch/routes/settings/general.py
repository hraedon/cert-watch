"""General / root settings page route."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch.middleware import require_admin_form
from cert_watch.routes._deps import get_templates
from cert_watch.routes.settings.render import _settings_context

templates = get_templates()
router = APIRouter()


@router.get("/settings", response_class=HTMLResponse, response_model=None)
def settings_page(
    request: Request,
    tab: str = "auth",
    saved: str | None = None,
    error: str | None = None,
    password_changed: str | None = None,
) -> HTMLResponse | RedirectResponse:
    redirect_resp = require_admin_form(request)
    if redirect_resp:
        return redirect_resp
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=_settings_context(
            request,
            tab=tab,
            saved=saved,
            error=error,
            password_changed=password_changed,
        ),
    )
