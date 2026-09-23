"""Small alert-state JSON actions."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import write_guard
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.routes._deps import IdParam, _db_path, acting_auth
from cert_watch.security.ratelimit import rate_limit
from cert_watch.services.alert_state import (
    AlertNotFoundError,
    mark_all_alerts_read,
)
from cert_watch.services.alert_state import (
    mark_alert_read as mark_alert_read_service,
)

router = APIRouter()


@router.post("/api/alerts/{alert_id}/read", response_model=None)
async def mark_alert_read(
    request: Request,
    alert_id: IdParam,
    _auth: str = Depends(write_guard),
) -> dict[str, Any] | JSONResponse:
    try:
        updated = mark_alert_read_service(
            _db_path(request), alert_id, auth=acting_auth(request)
        )
    except AlertNotFoundError:
        return {"ok": False, "error": "alert not found"}
    except ScopeDeniedError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=403)
    return {"ok": True, "id": alert_id, "updated": updated}


@router.post("/api/alerts/mark-all-read")
async def api_mark_all_alerts_read(
    request: Request,
    _auth: str = Depends(write_guard),
    _rl: None = Depends(rate_limit("mark_all_read", 10, 300)),
) -> JSONResponse:
    count = mark_all_alerts_read(
        _db_path(request),
        auth=acting_auth(request),
        actor=resolve_actor(request),
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"count": count})
