"""Host API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import SqliteHostRepository
from cert_watch.middleware import require_auth, require_write
from cert_watch.routes._deps import _db_path
from cert_watch.routes.api._shared import _normalize_pagination, _pagination_links

logger = logging.getLogger("cert_watch.routes.api.hosts")

router = APIRouter()


@router.get("/api/hosts")
def api_list_hosts(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteHostRepository(db)
    total = repo.count_all()
    page, limit, pages, offset = _normalize_pagination(page, limit, total)
    page_hosts = repo.list_page(offset=offset, limit=limit)
    return JSONResponse(
        content={
            "hosts": [
                {
                    "id": h.id,
                    "hostname": h.hostname,
                    "port": h.port,
                    "tags": h.tags,
                    "scan_interval_hours": h.scan_interval_hours,
                    "owner_name": h.owner_name,
                    "owner_email": h.owner_email,
                    "owner_slack": h.owner_slack,
                    "renewal_status": h.renewal_status,
                    "notes": h.notes,
                    "added_at": h.added_at.isoformat(),
                }
                for h in page_hosts
            ],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": pages,
                **_pagination_links(request, "/api/hosts", page, limit, total),
            },
        }
    )


@router.patch("/api/hosts/{host_id}/owner")
async def api_update_host_owner(
    host_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    """Update owner/contact and renewal status for a host."""
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)

    valid_statuses = {"pending", "in_progress", "renewed"}
    renewal_status = body.get("renewal_status")
    if renewal_status is not None and renewal_status not in valid_statuses:
        return JSONResponse(
            content={"error": f"renewal_status must be one of {valid_statuses}"},
            status_code=400,
        )
    for field in ("owner_name", "owner_email", "owner_slack"):
        val = body.get(field)
        if val is not None and not isinstance(val, str):
            return JSONResponse(
                content={"error": f"{field} must be a string"},
                status_code=400,
            )
    owner_email = body.get("owner_email")
    if owner_email is not None and owner_email and "@" not in owner_email:
        return JSONResponse(content={"error": f"invalid email: {owner_email}"}, status_code=400)

    valid_methods = {"", "acme", "cert-manager", "manual"}
    renewal_method = body.get("renewal_method")
    if renewal_method is not None and renewal_method not in valid_methods:
        return JSONResponse(
            content={"error": f"renewal_method must be one of {valid_methods}"},
            status_code=400,
        )
    runbook_url = body.get("runbook_url")
    if runbook_url is not None:
        if not isinstance(runbook_url, str):
            return JSONResponse(
                content={"error": "runbook_url must be a string"},
                status_code=400,
            )
        from cert_watch.routes.api._shared import _runbook_url_error

        err = _runbook_url_error(runbook_url)
        if err:
            return JSONResponse(content={"error": err}, status_code=400)

    db = _db_path(request)
    repo = SqliteHostRepository(db)
    host = repo.get(host_id)
    if host is None:
        return JSONResponse(content={"error": "host not found"}, status_code=404)

    repo.update_owner(
        host_id,
        owner_name=body.get("owner_name"),
        owner_email=body.get("owner_email"),
        owner_slack=body.get("owner_slack"),
        renewal_status=renewal_status,
    )
    if renewal_method is not None or runbook_url is not None:
        repo.update_renewal(
            host_id,
            renewal_method=renewal_method,
            runbook_url=runbook_url,
        )
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="owner.update",
        target_type="host",
        target_id=host_id,
        detail={
            "owner_name": body.get("owner_name"),
            "owner_email": body.get("owner_email"),
            "owner_slack": body.get("owner_slack"),
            "renewal_status": renewal_status,
            "renewal_method": renewal_method,
        },
        source_ip=resolve_source_ip(request),
    )
    updated = repo.get(host_id)
    if updated is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="host not found")
    return JSONResponse(
        content={
            "id": host_id,
            "owner_name": updated.owner_name,
            "owner_email": updated.owner_email,
            "owner_slack": updated.owner_slack,
            "renewal_status": updated.renewal_status,
            "renewal_method": updated.renewal_method,
            "runbook_url": updated.runbook_url,
            "notes": updated.notes,
        }
    )


@router.patch("/api/hosts/{host_id}/notes")
async def api_update_host_notes(
    host_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteHostRepository(db)
    host = repo.get(host_id)
    if host is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
    notes = body.get("notes", "")
    if not isinstance(notes, str):
        return JSONResponse(content={"error": "notes must be a string"}, status_code=400)
    if len(notes) > 10000:
        return JSONResponse(content={"error": "notes too long (max 10000)"}, status_code=400)
    repo.update_notes(host_id, notes)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="host.update_notes",
        target_type="host",
        target_id=host_id,
        detail={"notes_length": len(notes)},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"id": host_id, "notes": notes})


@router.put("/api/hosts/{host_id}/tags")
async def api_set_host_tags(
    host_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteHostRepository(db)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
    from cert_watch.routes.api._shared import _tags_from_body

    tags = _tags_from_body(body)
    if tags is None:
        return JSONResponse(
            content={"error": "tags must be a string or list of strings"}, status_code=400
        )
    if not repo.set_tags(host_id, tags):
        return JSONResponse(content={"error": "not found"}, status_code=404)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="host.set_tags",
        target_type="host",
        target_id=host_id,
        detail={"tags": tags},
        source_ip=resolve_source_ip(request),
    )
    from cert_watch.tags import parse_tags

    return JSONResponse(content={"id": host_id, "tags": parse_tags(tags)})
