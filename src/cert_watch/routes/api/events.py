"""Event streaming API endpoints (Plan 044)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from cert_watch.events import get_events, get_failed_deliveries
from cert_watch.middleware import require_auth
from cert_watch.routes._deps import _db_path

logger = logging.getLogger("cert_watch.routes.api.events")

router = APIRouter()


@router.get("/api/events")
def api_list_events(
    request: Request,
    _auth: str = Depends(require_auth),
    event_type: str | None = Query(None),
    source: str | None = Query(None),
    since: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    db = _db_path(request)
    events = get_events(
        db,
        event_type=event_type,
        source=source,
        since=since,
        limit=limit,
        offset=offset,
    )
    return JSONResponse(content={"events": events})


@router.get("/api/events/stream")
async def api_event_stream(
    request: Request,
    _auth: str = Depends(require_auth),
    event_type: str | None = Query(None),
    source: str | None = Query(None),
) -> EventSourceResponse:
    db = str(_db_path(request))

    async def _generate():
        max_id = 0
        while True:
            if await request.is_disconnected():
                break
            try:
                events = get_events(db, event_type=event_type, source=source, limit=100)
            except Exception:
                logger.warning("SSE event query failed", exc_info=True)
                events = []
            for evt in reversed(events):
                eid = evt.get("id")
                if eid is not None and isinstance(eid, int) and eid > max_id:
                    max_id = eid
                    payload = evt.get("payload")
                    if isinstance(payload, str):
                        with contextlib.suppress(json.JSONDecodeError, TypeError):
                            payload = json.loads(payload)
                    evt_data = {k: v for k, v in evt.items() if k != "payload"}
                    evt_data["payload"] = payload
                    yield {
                        "event": evt.get("event_type", "event"),
                        "data": json.dumps(evt_data, default=str),
                    }
            await asyncio.sleep(3)

    return EventSourceResponse(_generate())


@router.get("/api/events/failed")
def api_failed_deliveries(
    request: Request,
    _auth: str = Depends(require_auth),
    limit: int = Query(50, ge=1, le=500),
) -> JSONResponse:
    db = _db_path(request)
    failures = get_failed_deliveries(db, limit=limit)
    return JSONResponse(content={"events": failures})