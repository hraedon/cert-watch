"""API key management routes for the settings area."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.auth.guards import admin_session_page_guard, admin_settings_form
from cert_watch.database import SqliteApiKeyRepository, get_write_lock
from cert_watch.database.api_keys import VALID_SCOPES
from cert_watch.routes._deps import IdParam, _db_path
from cert_watch.routes.settings.render import _render_api_keys
from cert_watch.security import _request_security

router = APIRouter()


def _repository(request: Request) -> SqliteApiKeyRepository:
    return SqliteApiKeyRepository(
        _db_path(request),
        security=_request_security(request),
    )


# A CSRF failure re-renders the page with the error, as it always has.
_API_KEYS_FORM = admin_settings_form(
    lambda request, error: _render_api_keys(request, error=error),
    session_only=True,
)


@router.get("/settings/api-keys", response_class=HTMLResponse, response_model=None)
def api_keys_page(
    request: Request, _auth: str = Depends(admin_session_page_guard),
) -> HTMLResponse | RedirectResponse:
    return _render_api_keys(request)


@router.post("/settings/api-keys", response_class=HTMLResponse, response_model=None)
async def api_keys_create(
    request: Request,
    _auth: str = Depends(_API_KEYS_FORM),
) -> HTMLResponse | RedirectResponse | JSONResponse:
    form = await request.form()
    name = str(form.get("name") or "").strip()
    scope = str(form.get("scope") or "read")
    if not name:
        return _render_api_keys(request, error="A name is required.")
    if scope not in VALID_SCOPES:
        return _render_api_keys(request, error="Invalid scope.")

    repo = _repository(request)
    with get_write_lock():
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
    key_id: IdParam, request: Request,
    _auth: str = Depends(_API_KEYS_FORM),
) -> RedirectResponse | HTMLResponse | JSONResponse:
    with get_write_lock():
        _repository(request).revoke_key(key_id)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="api_key.revoke",
        target_type="api_key",
        target_id=key_id,
        source_ip=resolve_source_ip(request),
    )
    return RedirectResponse(url="/settings?tab=api-keys", status_code=303)
