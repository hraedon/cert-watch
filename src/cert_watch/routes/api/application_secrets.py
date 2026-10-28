"""JSON equivalent of the administrator credential metadata inventory."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import admin_json_write_guard, require_admin
from cert_watch.database.application_secrets import list_application_secrets
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, acting_auth
from cert_watch.services.application_secrets import (
    create_application_secret,
    retire_application_secret,
)

router = APIRouter()


@router.get("/api/application-secrets", dependencies=[Depends(require_admin)])
def get_application_secrets(request: Request) -> JSONResponse:
    now = datetime.now(UTC)
    return JSONResponse(jsonable_encoder([
        {**asdict(item), "state": item.state(now)}
        for item in list_application_secrets(_db_path(request))
    ]))


@router.post("/api/application-secrets", dependencies=[Depends(admin_json_write_guard)])
async def add_application_secret(request: Request) -> JSONResponse:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 16384:
            return JSONResponse({"error": "Metadata request is too large."}, 413)
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return JSONResponse({"error": "Expected a JSON metadata object."}, 422)
    if not isinstance(data, dict):
        return JSONResponse({"error": "Expected a JSON metadata object."}, 422)
    try:
        identifier = create_application_secret(
            _db_path(request), data, auth=acting_auth(request),
            actor=resolve_actor(request), source_ip=resolve_source_ip(request),
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, 422)
    return JSONResponse({"id": identifier}, 201)


@router.post("/api/application-secrets/{secret_id}/retire",
             dependencies=[Depends(admin_json_write_guard)])
def retire_secret(request: Request, secret_id: IdParam) -> JSONResponse:
    changed = retire_application_secret(
        _db_path(request), secret_id, auth=acting_auth(request),
        actor=resolve_actor(request), source_ip=resolve_source_ip(request),
        webhook_config=_get_settings(request).build_webhook_config(),
    )
    if not changed:
        return JSONResponse({"error": "Active credential record not found."}, 404)
    return JSONResponse({"retired": True})
