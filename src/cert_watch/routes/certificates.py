"""Certificate detail, delete, upload, and trust anchor routes."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import (
    admin_form_guard,
    get_auth_context,
    write_form_guard,
)
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.chain_guidance import describe_chain
from cert_watch.database import (
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteTrustAnchorRepository,
    _connect,
    _row_to_cert,
    distinct_tags,
    get_renewal_history,
)
from cert_watch.filters import issuer_cn
from cert_watch.presenters.certificate_detail import present_certificate_technical_details
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, acting_auth, get_templates
from cert_watch.routes._scoped import (
    scope_read_denied,
    scope_tags_from_auth,
    tags_with_scope,
)
from cert_watch.routes.hosts import endpoint_settings_writable
from cert_watch.scan_freshness import ScanEvidence, load_scan_evidence
from cert_watch.security.csrf import get_csrf_context
from cert_watch.security.ratelimit import _extract_client_ip, check_rate_limit
from cert_watch.services.certificate_management import (
    CertificateValidationError,
    upload_certificate_bytes,
)
from cert_watch.services.certificate_management import (
    add_trust_anchor as add_trust_anchor_service,
)
from cert_watch.services.certificate_management import (
    delete_certificate as delete_certificate_service,
)
from cert_watch.services.certificate_management import (
    delete_trust_anchor as delete_trust_anchor_service,
)
from cert_watch.services.host_ownership import (
    HostNotFoundError,
    HostOwnershipTargetError,
    HostOwnershipUpdate,
    HostOwnershipValidationError,
    resolve_host_ownership_target,
    update_host_ownership,
)
from cert_watch.services.resource_metadata import (
    ResourceMetadataNotFoundError,
    ResourceMetadataValidationError,
)
from cert_watch.services.resource_metadata import (
    update_certificate_tags as persist_certificate_tags,
)
from cert_watch.tags import parse_tags

logger = logging.getLogger("cert_watch.routes.certificates")

router = APIRouter()

templates = get_templates()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _detail_scan_evidence(request: Request, host_id: str) -> ScanEvidence | None:
    if not host_id:
        return None
    settings = _get_settings(request)
    return load_scan_evidence(
        _db_path(request), host_id=host_id, hour=settings.sched_hour, minute=settings.sched_min,
    ).get(host_id)


@router.get("/certificates/{cert_id}", response_class=HTMLResponse, response_model=None)
def certificate_detail(request: Request, cert_id: IdParam) -> HTMLResponse | RedirectResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        # No cert — maybe this is a pending host (scan failed, no cert stored yet).
        host_repo = SqliteHostRepository(db)
        host = host_repo.get(cert_id)
        if host is not None:
            denied = scope_read_denied(request, db, host_id=cert_id)
            if denied:
                return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
            # Get latest scan status/error for this host
            with _connect(db) as conn:
                scan_row = conn.execute(
                    "SELECT status, scanned_at, error_message FROM scan_history "
                    "WHERE hostname = ? AND port = ? "
                    "ORDER BY scanned_at DESC LIMIT 1",
                    (host.hostname, host.port),
                ).fetchone()
            csrf_ctx = get_csrf_context(request)
            auth_ctx = get_auth_context(request)
            settings = getattr(request.app.state, "settings", None)
            slack_configured = (
                getattr(settings, "webhook_kind", "") == "slack" if settings else False
            )
            # Pending host: same detail template, degraded (cert is None).
            rm = host.renewal_method or ""
            rm_label = {"acme": "ACME", "cert-manager": "cert-manager", "manual": "Manual"}.get(
                rm, rm.capitalize() if rm else ""
            )
            rm_indicator = (
                "automation configured"
                if rm in ("acme", "cert-manager")
                else ("requires manual action" if rm == "manual" else "")
            )
            return templates.TemplateResponse(
                request=request,
                name="certificate_detail.html",
                context={
                    "cert": None,
                    "cert_id": cert_id,
                    "subject_cn": f"{host.hostname}:{host.port}",
                    "host_id": host.id,
                    "hostname": host.hostname,
                    "port": host.port,
                    "host_info": {
                        "owner_name": host.owner_name or None,
                        "owner_email": host.owner_email or None,
                        "owner_slack": host.owner_slack or None,
                        "renewal_method": host.renewal_method or "",
                        "runbook_url": host.runbook_url or None,
                        "notes": host.notes or "",
                        "tags": host.tags or "",
                        "threshold_days": host.threshold_days,
                        "scan_interval_hours": host.scan_interval_hours,
                        "renewal_status": host.renewal_status,
                        "expected_issuers": host.expected_issuers,
                        "settings_writable": endpoint_settings_writable(request, db, host.id),
                    },
                    "renewal_method_label": rm_label,
                    "renewal_method_indicator": rm_indicator,
                    "all_tags": distinct_tags(db, scope_tags=scope_tags),
                    "scan_status": scan_row["status"] if scan_row else None,
                    "scan_error": scan_row["error_message"] if scan_row else None,
                    "scan_at": scan_row["scanned_at"] if scan_row else None,
                    "scan_evidence": _detail_scan_evidence(request, host.id),
                    **auth_ctx,
                    **csrf_ctx,
                    "active_page": "browse",
                    "version": __version__,
                    "commit": __commit__,
                    "slack_configured": slack_configured,
                },
            )
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)

    denied = scope_read_denied(request, db, cert_id=cert_id)
    if denied:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)

    from cryptography.exceptions import UnsupportedAlgorithm

    # Get chain (non-leaf certs with this cert as parent)
    with _connect(db) as conn:
        chain_rows = conn.execute(
            "SELECT * FROM certificates WHERE parent_cert_id = ? AND is_leaf = 0",
            (cert_id,),
        ).fetchall()

    # Determine chain status
    from cert_watch.cert_chain import chain_status as _chain_status

    anchors = SqliteTrustAnchorRepository(db).list_entries()
    chain_certs_objects = [_row_to_cert(cr) for cr in chain_rows]
    cs = _chain_status(cert, chain_certs_objects, anchors)
    technical_view = present_certificate_technical_details(
        cert,
        [
            (row["id"], chain_cert)
            for row, chain_cert in zip(chain_rows, chain_certs_objects, strict=True)
        ],
        cs,
    )

    # Get host info if scanned
    hostname = ""
    port = 443
    with _connect(db) as conn:
        host_row = conn.execute(
            "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        if host_row:
            hostname = host_row["hostname"] or ""
            port = host_row["port"] or 443

    # Get host info for operation summary
    host_info = None
    host_id = ""
    renewal_method_label = ""
    renewal_method_indicator = ""
    if hostname:
        with _connect(db) as conn:
            host_row = conn.execute(
                "SELECT * FROM hosts WHERE hostname = ? AND port = ?",
                (hostname, port),
            ).fetchone()
        if host_row:
            h = dict(host_row)
            host_id = h.get("id", "")
            host_info = {
                "owner_name": h.get("owner_name") or None,
                "owner_email": h.get("owner_email") or None,
                "owner_slack": h.get("owner_slack") or None,
                "renewal_status": h.get("renewal_status", "pending"),
                "renewal_method": h.get("renewal_method", ""),
                "runbook_url": h.get("runbook_url") or None,
                "notes": h.get("notes", ""),
                "tags": h.get("tags", ""),
                "threshold_days": h.get("threshold_days"),
                "scan_interval_hours": h.get("scan_interval_hours"),
                "expected_issuers": h.get("expected_issuers", ""),
                "settings_writable": endpoint_settings_writable(request, db, host_id),
            }
            rm = h.get("renewal_method", "")
            if rm == "acme":
                renewal_method_label = "ACME"
                renewal_method_indicator = "automation configured"
            elif rm == "cert-manager":
                renewal_method_label = "cert-manager"
                renewal_method_indicator = "automation configured"
            elif rm == "manual":
                renewal_method_label = "Manual"
                renewal_method_indicator = "requires manual action"
            elif rm:
                renewal_method_label = rm.capitalize()

    # Get renewal history
    renewal_history = get_renewal_history(db, cert_id)

    # Get drift events from cert_history (compare consecutive entries)
    drift_events = []
    if hostname:
        from cert_watch.database import list_cert_history

        history_entries = list_cert_history(db, hostname, port, limit=50)
        for i in range(len(history_entries) - 1):
            curr = history_entries[i]
            prev = history_entries[i + 1]
            changes = []
            if (
                curr.get("issuer") and prev.get("issuer")
                and curr["issuer"] != prev["issuer"]
            ):
                prev_issuer = issuer_cn(prev["issuer"])
                curr_issuer = issuer_cn(curr["issuer"])
                changes.append({
                    "field": "Issuer changed",
                    "change": f"{prev_issuer} → {curr_issuer}",
                    "sev": "high",
                })
            if (
                curr.get("key_algo") and prev.get("key_algo")
                and curr["key_algo"] != prev["key_algo"]
            ):
                changes.append({
                    "field": "Key algorithm changed",
                    "change": f'{prev["key_algo"]} → {curr["key_algo"]}',
                    "sev": "high",
                })
            if (
                curr.get("sig_algo") and prev.get("sig_algo")
                and curr["sig_algo"] != prev["sig_algo"]
            ):
                curr_sig = (curr["sig_algo"] or "").lower()
                prev_sig = (prev["sig_algo"] or "").lower()
                is_downgrade = "sha1" in curr_sig and "sha1" not in prev_sig
                changes.append({
                    "field": "Signature algorithm changed",
                    "change": f'{prev["sig_algo"]} → {curr["sig_algo"]}',
                    "sev": "high" if is_downgrade else "info",
                })
            if (
                curr.get("posture_grade") and prev.get("posture_grade")
                and curr["posture_grade"] != prev["posture_grade"]
            ):
                from cert_watch.posture import GRADE_WORST_ORDER

                grade_order = GRADE_WORST_ORDER
                curr_g = grade_order.get(curr["posture_grade"], 0)
                prev_g = grade_order.get(prev["posture_grade"], 0)
                if curr_g > prev_g:
                    changes.append({
                        "field": "Posture grade dropped",
                        "change": (
                            f'{prev["posture_grade"]} '
                            f'→ {curr["posture_grade"]}'
                        ),
                        "sev": "high",
                    })
            for change in changes:
                change["when"] = curr.get("scanned_at", "")[:10]
                drift_events.append(change)

    # Get posture evaluation
    from cert_watch.database import get_posture_for_cert
    from cert_watch.posture import evaluate_posture

    _posture = get_posture_for_cert(db, cert_id)
    posture_data: dict[str, Any] | None = None
    if _posture:
        posture_data = _posture
    else:
        try:
            result = evaluate_posture(
                cert=cert,
                chain_status=cs,
                chain_incomplete=False,
            )
            posture_data = {
                "grade": result.grade,
                "findings": [
                    {"check": f.check, "status": f.status, "message": f.message}
                    for f in result.findings
                ],
                "protocol_version": result.protocol_version,
                "ocsp_stapling": result.ocsp_stapling,
                "hsts": result.hsts,
                "must_staple": result.must_staple,
            }
        except (ValueError, TypeError, UnsupportedAlgorithm):
            logger.exception("posture evaluation failed for cert %s", cert_id)

    csrf_ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)
    from datetime import UTC, datetime

    settings = getattr(request.app.state, "settings", None)
    slack_configured = (
        getattr(settings, "webhook_kind", "") == "slack" if settings else False
    )
    certificate_alerts = sorted(
        SqliteAlertRepository(db).list_for_cert(cert_id),
        key=lambda alert: alert.created_at,
        reverse=True,
    )[:5]

    return templates.TemplateResponse(
        request=request,
        name="certificate_detail.html",
        context={
            "cert": cert,
            "cert_id": cert_id,
            "all_tags": distinct_tags(db, scope_tags=scope_tags),
            "version": __version__,
            "commit": __commit__,
            **auth_ctx,
            "active_page": "browse",
            **technical_view.template_context(),
            "chain_status": cs,
            "chain_guidance": describe_chain(cert, chain_certs_objects, cs),
            "chain_posture_changed": bool(
                _posture and _posture.get("chain_status") != cs
            ),
            "hostname": hostname,
            "port": port,
            "host_id": host_id,
            "scan_evidence": (
                _detail_scan_evidence(request, host_id) if cert.source == "scanned" else None
            ),
            "host_info": host_info,
            "cert_tags": parse_tags(repo.get_tags(cert_id)),
            "effective_tags": repo.effective_tags(cert_id),
            "renewal_history": renewal_history,
            "renewal_method_label": renewal_method_label,
            "renewal_method_indicator": renewal_method_indicator,
            "now": datetime.now(UTC),
            "posture": posture_data,
            "drift_events": drift_events,
            "certificate_alerts": certificate_alerts,
            "slack_configured": slack_configured,
            **csrf_ctx,
        },
    )


@router.post("/certificates/{cert_id}/delete")
async def delete_certificate(
    request: Request, cert_id: IdParam, _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    db = _db_path(request)
    try:
        delete_certificate_service(
            db,
            cert_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    logger.info("deleted certificate %s (cascade)", cert_id)
    return RedirectResponse(url="/", status_code=303)


# Note: POST /certificates/{id}/notes was removed (UI-INVENTORY V1). Notes are
# a host-scoped concept now — the single write surface is POST /hosts/{id}/notes.

@router.post("/certificates/{cert_id}/tags")
async def update_certificate_tags(
    request: Request, cert_id: IdParam, tags: str = Form(""),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    db = _db_path(request)
    try:
        persist_certificate_tags(
            db,
            cert_id,
            tags,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except ResourceMetadataValidationError as exc:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote(str(exc))}", status_code=303,
        )
    except ResourceMetadataNotFoundError:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    logger.info("updated tags for certificate %s", cert_id)
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=303)


@router.post("/certificates/{cert_id}/owner")
async def update_certificate_owner(
    request: Request,
    cert_id: IdParam,
    owner_name: str = Form(""),
    owner_email: str = Form(""),
    owner_slack: str = Form(""),
    renewal_method: str = Form(""),
    runbook_url: str = Form(""),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    if not check_rate_limit(f"cert_owner:{_extract_client_ip(request)}", 30, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path(request)

    try:
        target = resolve_host_ownership_target(db, cert_id)
    except HostOwnershipTargetError as exc:
        if exc.reason == "resource_not_found":
            return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
        message = (
            "no host associated" if exc.reason == "no_host_associated" else "host not found"
        )
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote(message)}", status_code=303,
        )

    host_id = target.host_id
    try:
        update_host_ownership(
            db,
            target,
            HostOwnershipUpdate(
                owner_name=owner_name,
                owner_email=owner_email,
                owner_slack=owner_slack,
                renewal_method=renewal_method,
                runbook_url=runbook_url,
            ),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except HostOwnershipValidationError as exc:
        message = "invalid renewal method" if exc.field == "renewal_method" else str(exc)
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote(message)}", status_code=303,
        )
    except HostNotFoundError:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote('host not found')}", status_code=303,
        )
    logger.info("updated owner for host %s via certificate %s", host_id, cert_id)
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=303)


@router.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008 — FastAPI dependency injection pattern
    password: str | None = Form(None),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    if not check_rate_limit(f"upload:{_extract_client_ip(request)}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        upload_certificate_bytes(
            _db_path(request),
            content,
            file.filename or "uploaded",
            password,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
            tags=tags_with_scope(request, ""),
        )
    except (CertificateValidationError, ScopeDeniedError) as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url="/", status_code=303)


@router.post("/trust-anchors")
async def add_trust_anchor(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
    _auth: str = Depends(admin_form_guard),
) -> RedirectResponse:
    # #65: a trust anchor changes chain validation for the whole fleet, so it
    # is admin-only (like the /settings/trust-anchors page), not write-gated.
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        add_trust_anchor_service(
            _db_path(request),
            content,
            file.filename or "uploaded",
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except CertificateValidationError as exc:
        return RedirectResponse(
            url=f"/settings/trust-anchors?error={quote(str(exc))}", status_code=303,
        )
    return RedirectResponse(url="/settings/trust-anchors?saved=1", status_code=303)


@router.post("/trust-anchors/{anchor_id}/delete")
async def delete_trust_anchor(
    request: Request, anchor_id: IdParam,
    _auth: str = Depends(admin_form_guard),  # #65: admin-only
) -> RedirectResponse:
    delete_trust_anchor_service(
        _db_path(request),
        anchor_id,
        auth=acting_auth(request),
        actor=resolve_actor(request),
        source_ip=resolve_source_ip(request),
    )
    logger.info("deleted trust anchor %s", anchor_id)
    return RedirectResponse(url="/settings/trust-anchors?saved=1", status_code=303)
