"""Alert and alert-group API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import (
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    _total_alerts,
    list_alerts_with_subject,
)
from cert_watch.middleware import require_auth, require_write
from cert_watch.routes._deps import _db_path
from cert_watch.routes.api._shared import (
    _alert_group_json,
    _normalize_pagination,
    _pagination_links,
    _validate_webhook_url,
)

logger = logging.getLogger("cert_watch.routes.api.alerts")

router = APIRouter()


@router.get("/api/alerts")
def api_list_alerts(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    total = _total_alerts(db)
    page, limit, pages, _offset = _normalize_pagination(page, limit, total)
    rows = list_alerts_with_subject(db, page=page, limit=limit)
    return JSONResponse(
        content={
            "alerts": rows,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": pages,
                **_pagination_links(request, "/api/alerts", page, limit, total),
            },
        }
    )


# ---------- Alert Groups ----------


@router.get("/api/alert-groups")
def api_list_alert_groups(request: Request, _auth: str = Depends(require_auth)) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    groups = repo.list_all()
    return JSONResponse(content={"groups": [_alert_group_json(g) for g in groups]})


@router.post("/api/alert-groups")
async def api_create_alert_group(
    request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)

    name = body.get("name")
    if not name or not isinstance(name, str):
        return JSONResponse(content={"error": "name is required"}, status_code=400)

    recipients_raw = body.get("recipients", [])
    match_tags_raw = body.get("match_tags", [])
    webhook_url = body.get("webhook_url", "")

    if not isinstance(recipients_raw, list) or not all(isinstance(r, str) for r in recipients_raw):
        return JSONResponse(
            content={"error": "recipients must be a list of strings"}, status_code=400
        )
    if not isinstance(match_tags_raw, list) or not all(isinstance(t, str) for t in match_tags_raw):
        return JSONResponse(
            content={"error": "match_tags must be a list of strings"}, status_code=400
        )
    if not isinstance(webhook_url, str):
        return JSONResponse(content={"error": "webhook_url must be a string"}, status_code=400)

    if webhook_url:
        err = _validate_webhook_url(webhook_url)
        if err:
            return err

    # Validate emails minimally
    for r in recipients_raw:
        if "@" not in r:
            return JSONResponse(content={"error": f"invalid email: {r}"}, status_code=400)

    repo = SqliteAlertGroupRepository(db)
    if repo.get_by_name(name):
        return JSONResponse(
            content={"error": f"alert group '{name}' already exists"}, status_code=409
        )

    group_id = repo.create(name, recipients_raw, match_tags_raw, webhook_url)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert_group.create",
        target_type="alert_group",
        target_id=group_id,
        detail={"name": name, "recipients": recipients_raw, "match_tags": match_tags_raw},
        source_ip=resolve_source_ip(request),
    )
    g = repo.get(group_id)
    return JSONResponse(content=_alert_group_json(g), status_code=201)


@router.get("/api/alert-groups/{group_id}")
def api_get_alert_group(
    request: Request, group_id: str, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    g = repo.get(group_id)
    if g is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content=_alert_group_json(g))


@router.patch("/api/alert-groups/{group_id}")
async def api_update_alert_group(
    group_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    if repo.get(group_id) is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)

    name = body.get("name")
    recipients_raw = body.get("recipients")
    match_tags_raw = body.get("match_tags")
    webhook_url = body.get("webhook_url")

    if name is not None and (not isinstance(name, str) or not name):
        return JSONResponse(content={"error": "name must be a non-empty string"}, status_code=400)
    if recipients_raw is not None:
        bad_list = not isinstance(recipients_raw, list) or not all(
            isinstance(r, str) for r in recipients_raw
        )
        if bad_list:
            return JSONResponse(
                content={"error": "recipients must be a list of strings"},
                status_code=400,
            )
        for r in recipients_raw:
            if "@" not in r:
                return JSONResponse(content={"error": f"invalid email: {r}"}, status_code=400)
    if match_tags_raw is not None:
        bad_tags = not isinstance(match_tags_raw, list) or not all(
            isinstance(t, str) for t in match_tags_raw
        )
        if bad_tags:
            return JSONResponse(
                content={"error": "match_tags must be a list of strings"},
                status_code=400,
            )
    if webhook_url is not None and not isinstance(webhook_url, str):
        return JSONResponse(content={"error": "webhook_url must be a string"}, status_code=400)
    if webhook_url:
        err = _validate_webhook_url(webhook_url)
        if err:
            return err

    # Check unique name on rename
    if name is not None:
        existing = repo.get_by_name(name)
        if existing and existing.id != group_id:
            return JSONResponse(
                content={"error": f"alert group '{name}' already exists"}, status_code=409
            )

    repo.update(
        group_id,
        name=name,
        recipients=recipients_raw,
        match_tags=match_tags_raw,
        webhook_url=webhook_url,
    )
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert_group.update",
        target_type="alert_group",
        target_id=group_id,
        detail={k: v for k, v in body.items() if v is not None},
        source_ip=resolve_source_ip(request),
    )
    g = repo.get(group_id)
    return JSONResponse(content=_alert_group_json(g))


@router.delete("/api/alert-groups/{group_id}")
async def api_delete_alert_group(
    group_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    g = repo.get(group_id)
    if g is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)

    repo.delete(group_id)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert_group.delete",
        target_type="alert_group",
        target_id=group_id,
        detail={"name": g.name},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"status": "deleted"})


@router.post("/api/alert-groups/{group_id}/certs/{cert_id}")
async def api_assign_cert_to_group(
    group_id: str, cert_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    group_repo = SqliteAlertGroupRepository(db)
    if group_repo.get(group_id) is None:
        return JSONResponse(content={"error": "group not found"}, status_code=404)
    cert_repo = SqliteCertificateRepository(db)
    if cert_repo.get_by_id(cert_id) is None:
        return JSONResponse(content={"error": "certificate not found"}, status_code=404)

    group_repo.assign_cert(group_id, cert_id)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert_group.assign_cert",
        target_type="alert_group",
        target_id=group_id,
        detail={"cert_id": cert_id},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"status": "assigned", "group_id": group_id, "cert_id": cert_id})


@router.delete("/api/alert-groups/{group_id}/certs/{cert_id}")
async def api_unassign_cert_from_group(
    group_id: str, cert_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    group_repo = SqliteAlertGroupRepository(db)
    if group_repo.get(group_id) is None:
        return JSONResponse(content={"error": "group not found"}, status_code=404)

    group_repo.unassign_cert(group_id, cert_id)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert_group.unassign_cert",
        target_type="alert_group",
        target_id=group_id,
        detail={"cert_id": cert_id},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"status": "unassigned", "group_id": group_id, "cert_id": cert_id})


@router.get("/api/certificates/{cert_id}/alert-routing")
def api_cert_alert_routing(
    request: Request, cert_id: str, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Preview which alert groups match a cert and the resolved recipients."""
    db = _db_path(request)
    cert_repo = SqliteCertificateRepository(db)
    cert = cert_repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)

    group_repo = SqliteAlertGroupRepository(db)
    effective = cert_repo.effective_tags(cert_id)
    manual_ids = set(group_repo.groups_for_cert_manual(cert_id))

    from cert_watch.alerts import resolve_group_recipients
    from cert_watch.tags import tags_match

    matched_groups: list[dict] = []
    for g in group_repo.list_all():
        if g.id in manual_ids:
            matched_groups.append({"id": g.id, "name": g.name, "reason": "manual"})
        elif tags_match(effective, g.match_tags):
            matched_groups.append({"id": g.id, "name": g.name, "reason": "tag"})

    recipients = resolve_group_recipients(db, cert_id)
    return JSONResponse(
        content={
            "cert_id": cert_id,
            "effective_tags": effective,
            "matched_groups": matched_groups,
            "recipients": recipients,
        }
    )
