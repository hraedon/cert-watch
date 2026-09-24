"""Alert and alert-group API endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.auth.guards import (
    admin_json_write_guard,
    admin_write_guard,
    require_admin,
    require_auth,
    write_guard,
)
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.database import (
    AlertStore,
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    _total_alerts,
    get_write_lock,
    list_alerts_with_subject,
)
from cert_watch.routes._deps import IdParam, _db_path, acting_auth
from cert_watch.routes._scoped import scope_read_denied, scope_tags_from_auth, superseded_json
from cert_watch.routes.api._shared import (
    JsonBodyError,
    _alert_group_json,
    _normalize_pagination,
    _pagination_links,
    _validate_webhook_url,
    json_body,
)
from cert_watch.services.alert_groups import (
    AlertGroupConflictError,
    AlertGroupNotFoundError,
    create_alert_group,
    delete_alert_group,
    update_alert_group,
)
from cert_watch.services.certificate_identity import (
    CertificateSupersededError,
    ensure_not_superseded,
    refuse_if_superseded,
)

logger = logging.getLogger("cert_watch.routes.api.alerts")

router = APIRouter()


@router.get("/api/alerts")
def api_list_alerts(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    total = _total_alerts(db, scope_tags=scope_tags)
    page, limit, pages, _offset = _normalize_pagination(page, limit, total)
    rows = list_alerts_with_subject(db, page=page, limit=limit, scope_tags=scope_tags)
    for row in rows:
        row.pop("historical_cert", None)  # Internal Activity presentation, not an API field.
        # Dispatch bookkeeping is internal state, not part of the public alert
        # representation.  The public status still exposes the new ``sending``
        # lifecycle state.
        for field in (
            "attempt_count",
            "next_attempt_at",
            "last_attempt_at",
            "lease_expires_at",
            "failure_reason",
        ):
            row.pop(field, None)
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


@router.post("/api/alerts/{alert_id}/retry")
def api_retry_failed_alert(
    request: Request,
    alert_id: IdParam,
    _auth: str = Depends(write_guard),
) -> JSONResponse:
    db = _db_path(request)
    try:
        with get_write_lock():
            retried = AlertStore(db).operator_retry(alert_id, auth=acting_auth(request))
    except ScopeDeniedError:
        record_audit(
            db,
            actor=resolve_actor(request),
            action="alert.retry_denied",
            target_type="alert",
            target_id=alert_id,
            detail={"reason": "scope_denied"},
            source_ip=resolve_source_ip(request),
        )
        return JSONResponse(content={"error": "alert not found"}, status_code=404)
    if not retried:
        from cert_watch.database import _connect

        with _connect(db) as conn:
            row = conn.execute(
                "SELECT status FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        if row is None:
            return JSONResponse(content={"error": "alert not found"}, status_code=404)
        return JSONResponse(
            content={"error": "only failed alerts can be retried"}, status_code=409
        )
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert.retry_failed",
        target_type="alert",
        target_id=alert_id,
        detail={"previous_status": "failed"},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"ok": True, "id": alert_id, "status": "pending"})


# ---------- Alert Groups ----------


@router.get("/api/alert-groups")
def api_list_alert_groups(request: Request, _auth: str = Depends(require_admin)) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    groups = repo.list_all()
    return JSONResponse(content={"groups": [_alert_group_json(g) for g in groups]})


@router.post("/api/alert-groups")
async def api_create_alert_group(
    request: Request, _auth: str = Depends(admin_json_write_guard)
) -> JSONResponse:
    db = _db_path(request)
    try:
        body = json_body(await request.body())
    except JsonBodyError as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=400)

    name = body.get("name")
    if not name or not isinstance(name, str):
        return JSONResponse(content={"error": "name is required"}, status_code=400)

    recipients_raw = body.get("recipients", [])
    match_tags_raw = body.get("match_tags", [])
    webhook_url = body.get("webhook_url", "")
    threshold_days = body.get("threshold_days")
    digest_cadence_days = body.get("digest_cadence_days", 7)

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
    if threshold_days is not None and (not isinstance(threshold_days, int) or threshold_days < 1):
        return JSONResponse(
            content={"error": "threshold_days must be a positive integer or null"},
            status_code=400,
        )
    if not isinstance(digest_cadence_days, int) or digest_cadence_days < 1:
        return JSONResponse(
            content={"error": "digest_cadence_days must be a positive integer"},
            status_code=400,
        )

    if webhook_url:
        err = _validate_webhook_url(webhook_url)
        if err:
            return err

    # Validate emails minimally
    for r in recipients_raw:
        if "@" not in r:
            return JSONResponse(content={"error": f"invalid email: {r}"}, status_code=400)

    try:
        group = create_alert_group(
            db,
            name=name,
            recipients=recipients_raw,
            match_tags=match_tags_raw,
            webhook_url=webhook_url,
            threshold_days=threshold_days, digest_cadence_days=digest_cadence_days,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except AlertGroupConflictError as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=409)
    return JSONResponse(content=_alert_group_json(group), status_code=201)


@router.get("/api/alert-groups/{group_id}")
def api_get_alert_group(
    request: Request, group_id: IdParam, _auth: str = Depends(require_admin)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    g = repo.get(group_id)
    if g is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content=_alert_group_json(g))


@router.patch("/api/alert-groups/{group_id}")
async def api_update_alert_group(
    group_id: IdParam, request: Request, _auth: str = Depends(admin_json_write_guard)
) -> JSONResponse:
    db = _db_path(request)
    try:
        body = json_body(await request.body())
    except JsonBodyError as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=400)

    name = body.get("name")
    recipients_raw = body.get("recipients")
    match_tags_raw = body.get("match_tags")
    webhook_url = body.get("webhook_url")
    threshold_days = body.get("threshold_days", SqliteAlertGroupRepository._UNSET)
    digest_cadence_days = body.get("digest_cadence_days")

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
    if threshold_days is not SqliteAlertGroupRepository._UNSET and threshold_days is not None and (
        not isinstance(threshold_days, int) or threshold_days < 1
    ):
        return JSONResponse(
            content={"error": "threshold_days must be a positive integer or null"},
            status_code=400,
        )
    if digest_cadence_days is not None and (
        not isinstance(digest_cadence_days, int) or digest_cadence_days < 1
    ):
        return JSONResponse(
            content={"error": "digest_cadence_days must be a positive integer"},
            status_code=400,
        )

    try:
        group = update_alert_group(
            db,
            group_id,
            name=name,
            recipients=recipients_raw,
            match_tags=match_tags_raw,
            webhook_url=webhook_url,
            threshold_days=threshold_days,
            digest_cadence_days=digest_cadence_days,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except AlertGroupNotFoundError:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    except AlertGroupConflictError as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=409)
    return JSONResponse(content=_alert_group_json(group))


@router.delete("/api/alert-groups/{group_id}")
async def api_delete_alert_group(
    group_id: IdParam, request: Request, _auth: str = Depends(admin_write_guard)
) -> JSONResponse:
    db = _db_path(request)
    try:
        delete_alert_group(
            db,
            group_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except AlertGroupNotFoundError:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content={"status": "deleted"})


@router.post("/api/alert-groups/{group_id}/certs/{cert_id}")
async def api_assign_cert_to_group(
    group_id: IdParam, cert_id: IdParam, request: Request, _auth: str = Depends(admin_write_guard)
) -> JSONResponse:
    db = _db_path(request)
    group_repo = SqliteAlertGroupRepository(db)
    cert_repo = SqliteCertificateRepository(db)
    with get_write_lock():
        if group_repo.get(group_id) is None:
            return JSONResponse(content={"error": "group not found"}, status_code=404)
        auth = acting_auth(request)
        try:
            refuse_if_superseded(db, cert_id, auth=auth)
            if cert_repo.get_by_id(cert_id) is None:
                return JSONResponse(content={"error": "certificate not found"}, status_code=404)
            # All re-checked inside the write transaction: a renewal, or a
            # delete of the group or the certificate by another connection,
            # can't land between the checks and the insert.
            outcome = group_repo.assign_cert(
                group_id,
                cert_id,
                guard=lambda conn: ensure_not_superseded(conn, cert_id, auth=auth),
                require_existing=True,
            )
        except CertificateSupersededError as exc:
            return superseded_json(exc)
        if outcome != "assigned":
            return JSONResponse(content={"error": outcome.replace("_", " ")}, status_code=404)
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
    group_id: IdParam, cert_id: IdParam, request: Request, _auth: str = Depends(admin_write_guard)
) -> JSONResponse:
    db = _db_path(request)
    group_repo = SqliteAlertGroupRepository(db)
    with get_write_lock():
        if group_repo.get(group_id) is None:
            return JSONResponse(content={"error": "group not found"}, status_code=404)
        # A renewal moves the assignment to the successor; removing it by the
        # old id would delete nothing while the group keeps receiving alerts.
        auth = acting_auth(request)
        try:
            removed = group_repo.unassign_cert(
                group_id,
                cert_id,
                guard=lambda conn: ensure_not_superseded(conn, cert_id, auth=auth),
            )
        except CertificateSupersededError as exc:
            return superseded_json(exc)
        if removed == "group_not_found":
            return JSONResponse(content={"error": "group not found"}, status_code=404)
        if removed != "unassigned":
            return JSONResponse(
                content={"error": "certificate is not assigned to this group"},
                status_code=404,
            )
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
    request: Request, cert_id: IdParam, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Preview which alert groups match a cert and the resolved recipients."""
    db = _db_path(request)
    denied = scope_read_denied(request, db, cert_id=cert_id)
    if denied:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    cert_repo = SqliteCertificateRepository(db)
    cert = cert_repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)

    # Alert-group routing applies only to leaf certificates — the batch
    # resolver (_resolve_group_config) filters on is_leaf=1. Return an empty
    # preview for chain/intermediate certs so matched_groups and recipients
    # stay consistent (WI-085).
    if not cert.is_leaf:
        return JSONResponse(content={
            "cert_id": cert_id,
            "effective_tags": cert_repo.effective_tags(cert_id),
            "matched_groups": [],
            "recipients": [],
            "note": "alert routing applies only to leaf certificates",
        })

    group_repo = SqliteAlertGroupRepository(db)
    effective = cert_repo.effective_tags(cert_id)
    manual_ids = set(group_repo.groups_for_cert_manual(cert_id))

    from cert_watch.alerting.routing import resolve_group_recipients
    from cert_watch.tags import tags_match

    matched_groups: list[dict[str, Any]] = []
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
