"""Host API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import JSONResponse

from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import admin_write_guard, require_auth, write_guard
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.database import SqliteHostRepository
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, acting_auth
from cert_watch.routes._scoped import scope_read_denied, scope_tags_from_auth
from cert_watch.routes.api._shared import (
    JsonBodyError,
    _normalize_pagination,
    _pagination_links,
    json_body,
    tags_from_json_body,
)
from cert_watch.services.host_management import (
    HostNotFoundError as ManagedHostNotFoundError,
)
from cert_watch.services.host_management import (
    HostSettingsUpdate,
    HostValidationError,
    create_hosts,
    import_hosts_csv,
    scan_all_hosts,
    update_expected_issuers,
    update_host_settings,
)
from cert_watch.services.host_management import (
    delete_host as delete_host_service,
)
from cert_watch.services.host_management import (
    scan_host_now as scan_host_now_service,
)
from cert_watch.services.host_ownership import (
    HostNotFoundError,
    HostOwnershipUpdate,
    HostOwnershipValidationError,
    update_host_ownership,
)
from cert_watch.services.resource_metadata import (
    ResourceMetadataNotFoundError,
    ResourceMetadataValidationError,
    update_host_notes,
    update_host_tags,
)

logger = logging.getLogger("cert_watch.routes.api.hosts")

router = APIRouter()
MAX_CSV_UPLOAD_BYTES = 10 * 1024 * 1024


def _service_error(exc: Exception, *, not_found: bool = False) -> JSONResponse:
    if isinstance(exc, ScopeDeniedError):
        return JSONResponse(status_code=403, content={"error": str(exc)})
    return JSONResponse(
        status_code=404 if not_found else 400,
        content={"error": str(exc)},
    )


@router.post("/api/hosts")
async def api_create_host(
    request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    try:
        body = json_body(await request.body())
        result = await create_hosts(
            _db_path(request),
            _get_settings(request),
            hostname=body.get("hostname", ""),
            port=body.get("port", 443),
            threshold_days=body.get("threshold_days"),
            tags=body.get("tags", ""),
            scan_interval_hours=body.get("scan_interval_hours"),
            common_ports=body.get("common_ports", False),
            notes=body.get("notes", ""),
            starttls_mode=body.get("starttls_mode", ""),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except (JsonBodyError, HostValidationError, ScopeDeniedError, TypeError) as exc:
        return _service_error(exc)
    return JSONResponse(
        status_code=201,
        content={"ids": list(result.host_ids), "scanned": result.scanned},
    )


@router.post("/api/hosts/import")
async def api_import_hosts(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
    _auth: str = Depends(write_guard),
) -> JSONResponse:
    content = await file.read(MAX_CSV_UPLOAD_BYTES + 1)
    if len(content) > MAX_CSV_UPLOAD_BYTES:
        return JSONResponse(
            status_code=400,
            content={"error": "CSV file too large (max 10 MB)"},
        )
    try:
        result = await import_hosts_csv(
            _db_path(request),
            _get_settings(request),
            content,
            file.filename or "unknown",
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except HostValidationError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    status = 201 if result.imported else 400 if result.errors else 200
    return JSONResponse(
        status_code=status,
        content={"imported": result.imported, "errors": list(result.errors)},
    )


@router.post("/api/hosts/scan")
async def api_scan_all_hosts(
    request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    scanned, failures = await scan_all_hosts(
        _db_path(request),
        _get_settings(request),
        auth=acting_auth(request),
        actor=resolve_actor(request),
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"scanned": scanned, "failures": failures})


@router.get("/api/hosts")
def api_list_hosts(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))

    if scope_tags:
        from cert_watch.database.connection import _connect
        from cert_watch.database.dashboard import _add_effective_tag_filter

        count_sql = "SELECT COUNT(*) FROM hosts h WHERE 1=1"
        count_sql, count_params = _add_effective_tag_filter(
            count_sql, [], scope_tags, col_cert=None, col_host="h.tags"
        )
        page_sql = "SELECT h.* FROM hosts h WHERE 1=1"
        page_sql, page_params = _add_effective_tag_filter(
            page_sql, [], scope_tags, col_cert=None, col_host="h.tags"
        )
        page_sql += " ORDER BY h.added_at LIMIT ? OFFSET ?"
        with _connect(db) as conn:
            total = conn.execute(count_sql, count_params).fetchone()[0]
        page, limit, pages, offset = _normalize_pagination(page, limit, total)
        with _connect(db) as conn:
            host_rows = conn.execute(page_sql, [*page_params, limit, offset]).fetchall()
        page_hosts = [SqliteHostRepository(db)._row_to_host(r) for r in host_rows]
    else:
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
                    "expected_issuers": h.expected_issuers,
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
    host_id: IdParam, request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    """Update owner/contact and renewal status for a host."""
    db = _db_path(request)
    raw = await request.body()

    def parse() -> HostOwnershipUpdate:
        body = json_body(raw)
        return HostOwnershipUpdate(
            owner_name=body.get("owner_name"),
            owner_email=body.get("owner_email"),
            owner_slack=body.get("owner_slack"),
            renewal_status=body.get("renewal_status"),
            renewal_method=body.get("renewal_method"),
            runbook_url=body.get("runbook_url"),
        )

    try:
        updated = update_host_ownership(
            db,
            host_id,
            parse,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc)})
    except JsonBodyError as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=400)
    except HostOwnershipValidationError as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=400)
    except HostNotFoundError:
        return JSONResponse(content={"error": "host not found"}, status_code=404)
    return JSONResponse(
        content={
            "id": updated.host_id,
            "owner_name": updated.owner_name,
            "owner_email": updated.owner_email,
            "owner_slack": updated.owner_slack,
            "renewal_status": updated.renewal_status,
            "renewal_method": updated.renewal_method,
            "runbook_url": updated.runbook_url,
            "notes": updated.notes,
        }
    )


@router.patch("/api/hosts/{host_id}/settings")
async def api_update_host_settings(
    host_id: IdParam, request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    try:
        body = json_body(await request.body())
        required = {"scan_interval_hours", "threshold_days", "renewal_status"}
        if not required <= set(body):
            raise JsonBodyError(
                "scan_interval_hours, threshold_days, and renewal_status are required"
            )
        updated = update_host_settings(
            _db_path(request),
            host_id,
            HostSettingsUpdate(
                body["scan_interval_hours"], body["threshold_days"], body["renewal_status"]
            ),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except (JsonBodyError, HostValidationError, ScopeDeniedError, TypeError) as exc:
        return _service_error(exc)
    except ManagedHostNotFoundError as exc:
        return _service_error(exc, not_found=True)
    return JSONResponse(
        content={
            "id": updated.id,
            "scan_interval_hours": updated.scan_interval_hours,
            "threshold_days": updated.threshold_days,
            "renewal_status": updated.renewal_status,
        }
    )


@router.patch("/api/hosts/{host_id}/notes")
async def api_update_host_notes(
    host_id: IdParam, request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    db = _db_path(request)
    raw = await request.body()
    try:
        updated_notes = update_host_notes(
            db,
            host_id,
            lambda: json_body(raw).get("notes", ""),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc)})
    except (JsonBodyError, ResourceMetadataValidationError) as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=400)
    except ResourceMetadataNotFoundError:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content={"id": host_id, "notes": updated_notes})


@router.put("/api/hosts/{host_id}/tags")
async def api_set_host_tags(
    host_id: IdParam, request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    db = _db_path(request)
    raw = await request.body()
    try:
        result = update_host_tags(
            db,
            host_id,
            lambda: tags_from_json_body(raw),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc)})
    except (JsonBodyError, ResourceMetadataValidationError) as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=400)
    except ResourceMetadataNotFoundError:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content={"id": host_id, "tags": list(result.tags)})


@router.get("/api/hosts/{host_id}/issuers")
def api_get_host_issuers(
    host_id: IdParam, request: Request, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Return the expected-issuer CN allowlist for a host (WI-007)."""
    db = _db_path(request)
    denied = scope_read_denied(request, db, host_id=host_id)
    if denied:
        return JSONResponse(content={"error": "host not found"}, status_code=404)
    repo = SqliteHostRepository(db)
    host = repo.get(host_id)
    if host is None:
        return JSONResponse(content={"error": "host not found"}, status_code=404)
    issuers = repo.get_expected_issuers(host_id)
    return JSONResponse(content={"id": host_id, "expected_issuers": issuers})


@router.put("/api/hosts/{host_id}/issuers")
async def api_set_host_issuers(
    host_id: IdParam, request: Request, _auth: str = Depends(admin_write_guard)
) -> JSONResponse:
    """Update the expected-issuer CN allowlist for a host (WI-007).

    Accepts ``{"issuers": ["R3", "R4"]}`` or ``{"issuers": "R3,R4"}``.
    Admin-gated because mis-configuration suppresses issuer drift detection.
    """
    try:
        body = json_body(await request.body())
        raw = body.get("issuers")
        if not isinstance(raw, (str, list)) or (
            isinstance(raw, list) and not all(isinstance(item, str) for item in raw)
        ):
            raise JsonBodyError("issuers must be a string or list of strings")
        issuers = update_expected_issuers(
            _db_path(request),
            host_id,
            raw,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
            audit_action="host.set_expected_issuers",
        )
    except (JsonBodyError, HostValidationError, ScopeDeniedError) as exc:
        return _service_error(exc)
    except ManagedHostNotFoundError as exc:
        return _service_error(exc, not_found=True)
    return JSONResponse(content={"id": host_id, "expected_issuers": list(issuers)})


@router.delete("/api/hosts/{host_id}")
async def api_delete_host(
    host_id: IdParam, request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    try:
        deleted = delete_host_service(
            _db_path(request),
            host_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return _service_error(exc)
    if not deleted:
        return JSONResponse(status_code=404, content={"error": "host not found"})
    return JSONResponse(content={"status": "deleted", "id": host_id})


@router.post("/api/hosts/{host_id}/scan")
async def api_scan_host(
    host_id: IdParam, request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    try:
        result = await scan_host_now_service(
            _db_path(request),
            host_id,
            _get_settings(request),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return _service_error(exc)
    except ManagedHostNotFoundError as exc:
        return _service_error(exc, not_found=True)
    status = 200 if result.status == "success" else 502
    return JSONResponse(
        status_code=status,
        content={"status": result.status, "error": result.error},
    )
