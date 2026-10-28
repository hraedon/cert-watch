"""Administrator-facing application credential metadata inventory."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import admin_form_guard, admin_page_guard, get_auth_context
from cert_watch.database.application_secrets import list_application_secrets
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, acting_auth, get_templates
from cert_watch.security.csrf import get_csrf_context
from cert_watch.services.application_secrets import (
    create_application_secret,
    retire_application_secret,
)

router = APIRouter()


@router.get("/application-secrets", response_class=HTMLResponse,
            dependencies=[Depends(admin_page_guard)])
def application_secrets_page(request: Request, saved: str = "", error: str = "") -> HTMLResponse:
    now = datetime.now(UTC)
    entries = [{"secret": item, "state": item.state(now)}
               for item in list_application_secrets(_db_path(request))]
    return get_templates().TemplateResponse(request, "application_secrets.html", {
        "active_page": "credentials", "entries": entries,
        "saved": saved, "error": error, "version": __version__, "commit": __commit__,
        **get_auth_context(request), **get_csrf_context(request),
    })


@router.post("/application-secrets", dependencies=[Depends(admin_form_guard)])
async def add_application_secret(request: Request) -> RedirectResponse:
    form = await request.form()
    data = {key: value for key, value in form.items() if key != "_csrf_token"}
    # This browser control is labelled UTC and emits a timezone-less local value.
    expiry = data.get("expires_at")
    if isinstance(expiry, str) and len(expiry) == 16:
        data["expires_at"] = expiry + ":00Z"
    try:
        create_application_secret(
            _db_path(request), data, auth=acting_auth(request),
            actor=resolve_actor(request), source_ip=resolve_source_ip(request),
        )
    except ValueError as exc:
        return RedirectResponse("/application-secrets?" + urlencode({"error": str(exc)}), 303)
    return RedirectResponse("/application-secrets?saved=added", 303)


@router.post("/application-secrets/{secret_id}/retire", dependencies=[Depends(admin_form_guard)])
def retire_secret(request: Request, secret_id: IdParam) -> RedirectResponse:
    changed = retire_application_secret(
        _db_path(request), secret_id, auth=acting_auth(request),
        actor=resolve_actor(request), source_ip=resolve_source_ip(request),
        webhook_config=_get_settings(request).build_webhook_config(),
    )
    return RedirectResponse("/application-secrets?" + urlencode(
        {"saved": "retired"} if changed else {"error": "Active credential record not found."}
    ), 303)
