"""API key management routes for the settings area."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import SqliteApiKeyRepository
from cert_watch.database.api_keys import VALID_SCOPES
from cert_watch.middleware import check_csrf, require_admin_form
from cert_watch.routes._deps import IdParam, _db_path
from cert_watch.routes.settings.core import _render_api_keys

router = APIRouter()


@router.get("/settings/api-keys", response_model=None)
def api_keys_page(request: Request) -> RedirectResponse:
    redirect_resp = require_admin_form(request)
    if redirect_resp:
        return redirect_resp
    return RedirectResponse(url="/settings?tab=api-keys", status_code=303)


@router.post("/settings/api-keys", response_class=HTMLResponse, response_model=None)
async def api_keys_create(
    request: Request,
) -> HTMLResponse | RedirectResponse | JSONResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return _render_api_keys(request, error=csrf_err)

    form = await request.form()
    name = str(form.get("name") or "").strip()
    scope = str(form.get("scope") or "read")
    if not name:
        return _render_api_keys(request, error="A name is required.")
    if scope not in VALID_SCOPES:
        return _render_api_keys(request, error="Invalid scope.")

    repo = SqliteApiKeyRepository(_db_path(request))
    entry, raw_token = repo.create_key(name, scope)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="api_key.create",
        target_type="api_key",
        target_id=entry.id,
        detail={"name": name, "scope": scope},
        source_ip=resolve_source_ip(request),
    )
    return _render_api_keys(request, new_token=raw_token, new_name=name)


@router.post("/settings/api-keys/{key_id}/revoke", response_model=None)
async def api_keys_revoke(
    key_id: IdParam, request: Request
) -> RedirectResponse | HTMLResponse | JSONResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return _render_api_keys(request, error=csrf_err)
    SqliteApiKeyRepository(_db_path(request)).revoke_key(key_id)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="api_key.revoke",
        target_type="api_key",
        target_id=key_id,
        source_ip=resolve_source_ip(request),
    )
    return RedirectResponse(url="/settings?tab=api-keys", status_code=303)
