"""Settings section routing.

Canonical URLs are ``/settings/{section}`` (one template per section).
``/settings`` and the legacy ``/settings?tab=X`` links redirect so old
bookmarks and post-save redirects keep working; the old ``smtp`` and
``alerts`` tabs merged into ``channels``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch.middleware import require_admin_form
from cert_watch.routes._deps import get_templates
from cert_watch.routes.settings.render import LEGACY_TAB_MAP, _render_settings

templates = get_templates()
router = APIRouter()

_PASSTHROUGH_PARAMS = ("saved", "error", "password_changed")


@router.get("/settings", response_class=HTMLResponse, response_model=None)
def settings_page(
    request: Request,
    tab: str | None = None,
    saved: str | None = None,
    error: str | None = None,
    password_changed: str | None = None,
) -> HTMLResponse | RedirectResponse:
    redirect_resp = require_admin_form(request)
    if redirect_resp:
        return redirect_resp
    section = LEGACY_TAB_MAP.get(tab or "auth", "auth")
    query = "&".join(
        f"{k}={v}"
        for k, v in (
            ("saved", saved),
            ("error", error),
            ("password_changed", password_changed),
        )
        if v
    )
    url = f"/settings/{section}" + (f"?{query}" if query else "")
    return RedirectResponse(url=url, status_code=303)


def _section_route(section: str) -> Any:
    def handler(
        request: Request,
        saved: str | None = None,
        error: str | None = None,
        password_changed: str | None = None,
    ) -> HTMLResponse | RedirectResponse:
        redirect_resp = require_admin_form(request)
        if redirect_resp:
            return redirect_resp
        return _render_settings(
            request,
            section,
            saved=saved,
            error=error,
            password_changed=password_changed,
        )

    return handler


# Sections without their own dedicated router (roles/users/alert-groups/
# events/api-keys GETs live in their feature routers).
for _section in ("auth", "channels", "policy", "tags", "trust-anchors"):
    router.add_api_route(
        f"/settings/{_section}",
        _section_route(_section),
        methods=["GET"],
        response_class=HTMLResponse,
        response_model=None,
    )
