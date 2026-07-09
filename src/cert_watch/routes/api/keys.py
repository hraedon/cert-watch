"""API key management endpoints (Plan 039 / BC-104).

Admin-scoped CRUD for machine-to-machine API keys. The raw token is returned
exactly once, in the ``POST`` response; thereafter only metadata is exposed.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import ApiKeyEntry, SqliteApiKeyRepository, get_write_lock
from cert_watch.database.api_keys import VALID_SCOPES
from cert_watch.middleware import _request_security, require_admin, require_admin_write
from cert_watch.routes._deps import IdParam, _db_path

logger = logging.getLogger("cert_watch.routes.api.keys")

router = APIRouter()


def _repository(request: Request) -> SqliteApiKeyRepository:
    return SqliteApiKeyRepository(
        _db_path(request),
        security=_request_security(request),
    )


def _entry_json(entry: ApiKeyEntry) -> dict[str, Any]:
    return {
        "id": entry.id,
        "name": entry.name,
        "scope": entry.scope,
        "created_at": entry.created_at.isoformat(),
        "last_used_at": entry.last_used_at.isoformat() if entry.last_used_at else None,
        "revoked": entry.revoked,
    }


@router.get("/api/api-keys")
def api_list_keys(
    request: Request, _auth: str = Depends(require_admin)
) -> JSONResponse:
    repo = _repository(request)
    return JSONResponse(content={"api_keys": [_entry_json(e) for e in repo.list_keys()]})


@router.post("/api/api-keys")
async def api_create_key(
    request: Request, _auth: str = Depends(require_admin_write)
) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)

    name = (body.get("name") or "").strip()
    scope = body.get("scope") or "read"
    if not name:
        return JSONResponse(content={"error": "name is required"}, status_code=400)
    if scope not in VALID_SCOPES:
        return JSONResponse(
            content={"error": f"scope must be one of {list(VALID_SCOPES)}"},
            status_code=400,
        )

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
    # The raw token is returned exactly once here and never stored.
    return JSONResponse(
        content={**_entry_json(entry), "token": raw_token},
        status_code=201,
    )


@router.delete("/api/api-keys/{key_id}")
async def api_revoke_key(
    key_id: IdParam, request: Request, _auth: str = Depends(require_admin_write)
) -> JSONResponse:
    repo = _repository(request)
    with get_write_lock():
        revoked = repo.revoke_key(key_id)
        if not revoked:
            return JSONResponse(content={"error": "not found"}, status_code=404)
        record_audit(
            _db_path(request),
            actor=resolve_actor(request),
            action="api_key.revoke",
            target_type="api_key",
            target_id=key_id,
            source_ip=resolve_source_ip(request),
        )
    return JSONResponse(content={"status": "revoked", "id": key_id})
