"""Event streaming API endpoints (Plan 044)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sqlite3
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sse_starlette.event import ServerSentEvent
from sse_starlette.sse import EventSourceResponse

from cert_watch.events import get_events, get_failed_deliveries
from cert_watch.middleware import require_auth
from cert_watch.routes._deps import _db_path
from cert_watch.routes._scoped import scope_tags_from_auth

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
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    events = get_events(
        db,
        event_type=event_type,
        source=source,
        since=since,
        limit=limit,
        offset=offset,
        scope_tags=scope_tags,
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
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))

    async def _generate() -> AsyncIterator[dict[str, Any]]:
        max_id = 0
        while True:
            if await request.is_disconnected():
                break
            try:
                events = get_events(
                    db, event_type=event_type, source=source, limit=100,
                    scope_tags=scope_tags,
                )
            except (sqlite3.DatabaseError, OSError):  # DB query / network
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

    return EventSourceResponse(
        _generate(),
        ping=15,
        ping_message_factory=lambda: ServerSentEvent(comment="ping"),
    )


@router.get("/api/events/failed")
def api_failed_deliveries(
    request: Request,
    _auth: str = Depends(require_auth),
    limit: int = Query(50, ge=1, le=500),
) -> JSONResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    failures = get_failed_deliveries(db, limit=limit, scope_tags=scope_tags)
    return JSONResponse(content={"events": failures})
