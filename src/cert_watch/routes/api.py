"""REST API (JSON) endpoints."""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from cert_watch.alerts import Alert, resolve_group_recipients, send_webhook
from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    _total_alerts,
    count_dashboard_leaves,
    distinct_tags,
    list_alerts_with_subject,
    list_calendar,
    list_cert_history,
    list_dashboard_rows,
    list_grade_trends,
    list_tls_version_trends,
)
from cert_watch.middleware import require_auth, require_write
from cert_watch.tags import format_tags, parse_tags

logger = logging.getLogger("cert_watch.routes.api")

_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _csv_safe(value: str) -> str:
    if value and str(value)[0] in _CSV_DANGEROUS_PREFIXES:
        return "'" + str(value)
    return str(value)


router = APIRouter()


def _tags_from_body(body: object) -> str | None:
    """Extract tags from a request body as a normalized csv string.

    Accepts ``{"tags": ["a", "b"]}`` or ``{"tags": "a,b"}``. Returns None when
    the shape is invalid (caller turns that into a 400).
    """
    if not isinstance(body, dict) or "tags" not in body:
        return None
    raw = body["tags"]
    if isinstance(raw, str):
        return format_tags(parse_tags(raw))
    if isinstance(raw, list) and all(isinstance(t, str) for t in raw):
        return format_tags(raw)
    return None


def _pagination_links(request: Request, path: str, page: int, limit: int, total: int) -> dict:
    """Build HATEOAS pagination links for a JSON API response."""
    pages = (total + limit - 1) // limit if limit else 0
    base = str(request.base_url).rstrip("/") + path
    links: dict[str, str | None] = {"self": f"{base}?page={page}&limit={limit}"}
    links["next"] = f"{base}?page={page + 1}&limit={limit}" if page < pages else None
    links["prev"] = f"{base}?page={page - 1}&limit={limit}" if page > 1 else None
    return links


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _db_path(request: Request) -> Path:
    return _get_settings(request).db_path


def _validate_webhook_url(url: str) -> JSONResponse | None:
    import socket

    from cert_watch.scan import _ALWAYS_BLOCKED_NETWORKS, _PRIVATE_NETWORKS

    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        return JSONResponse(content={"error": "webhook_url must use http(s)"}, status_code=400)
    if not parsed.hostname:
        return JSONResponse(content={"error": "webhook_url must have a hostname"}, status_code=400)
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return JSONResponse(
                content={"error": "webhook_url must not point to private/local"},
                status_code=400,
            )
    except ValueError:
        try:
            infos = socket.getaddrinfo(parsed.hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            host = parsed.hostname
            return JSONResponse(
                content={"error": f"webhook_url hostname '{host}' could not be resolved"},
                status_code=400,
            )
        for _family, _type, _proto, _canon, sockaddr in infos:
            ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if any(resolved_ip in net for net in _ALWAYS_BLOCKED_NETWORKS):
                return JSONResponse(
                    content={"error": "webhook_url must not point to private/local"},
                    status_code=400,
                )
            if any(resolved_ip in net for net in _PRIVATE_NETWORKS):
                return JSONResponse(
                    content={"error": "webhook_url must not point to private/local"},
                    status_code=400,
                )
    return None


# ---------- Certificates ----------


@router.get("/api/certificates")
def api_list_certificates(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = count_dashboard_leaves(db)
    rows = list_dashboard_rows(db, page=page, per_page=limit)
    pages = (total + limit - 1) // limit if limit else 0
    return JSONResponse(
        content={
            "certificates": rows,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": pages,
                **_pagination_links(request, "/api/certificates", page, limit, total),
            },
        }
    )


@router.get("/api/certificates/{cert_id}")
def api_get_certificate(
    request: Request, cert_id: str, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(
        content={
            "id": cert_id,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "not_before": cert.not_before.isoformat(),
            "not_after": cert.not_after.isoformat(),
            "san_dns_names": cert.san_dns_names,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "is_leaf": cert.is_leaf,
            "days_until_expiry": cert.days_until_expiry(),
            "notes": cert.notes,
            "tags": parse_tags(repo.get_tags(cert_id)),
            "effective_tags": repo.effective_tags(cert_id),
        }
    )


@router.get("/api/certificates/{cert_id}/pem")
def api_download_pem(
    request: Request, cert_id: str, _auth: str = Depends(require_auth)
) -> PlainTextResponse:
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return PlainTextResponse("not found", status_code=404)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        x509_cert = x509.load_der_x509_certificate(cert.raw_der)
        pem = x509_cert.public_bytes(Encoding.PEM)
    except Exception:
        return PlainTextResponse("cannot encode certificate", status_code=500)
    filename = f"cert-{cert_id[:8]}.pem"
    return PlainTextResponse(
        pem.decode(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.patch("/api/certificates/{cert_id}/notes")
async def api_update_notes(
    cert_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
    notes = body.get("notes", "")
    if not isinstance(notes, str):
        return JSONResponse(content={"error": "notes must be a string"}, status_code=400)
    if len(notes) > 10000:
        return JSONResponse(content={"error": "notes too long (max 10000)"}, status_code=400)
    repo.update_notes(cert_id, notes)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="cert.update_notes",
        target_type="certificate",
        target_id=cert_id,
        detail={"notes_length": len(notes)},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"id": cert_id, "notes": notes})


@router.get("/api/certificates/{cert_id}/history")
def api_cert_history(
    request: Request, cert_id: str, _auth: str = Depends(require_auth), limit: int = 365
) -> JSONResponse:
    db = _db_path(request)
    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        row = conn.execute(
            "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
    if row is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    history = list_cert_history(db, row["hostname"], row["port"], limit=min(max(limit, 1), 1000))
    return JSONResponse(content={"cert_id": cert_id, "history": history})


# ---------- Tags (plan 013) ----------


@router.get("/api/tags")
def api_list_tags(request: Request, _auth: str = Depends(require_auth)) -> JSONResponse:
    return JSONResponse(content={"tags": distinct_tags(_db_path(request))})


@router.put("/api/certificates/{cert_id}/tags")
async def api_set_cert_tags(
    cert_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteCertificateRepository(db)
    if repo.get_by_id(cert_id) is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
    tags = _tags_from_body(body)
    if tags is None:
        return JSONResponse(
            content={"error": "tags must be a string or list of strings"}, status_code=400
        )
    repo.set_tags(cert_id, tags)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="cert.set_tags",
        target_type="certificate",
        target_id=cert_id,
        detail={"tags": tags},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(
        content={
            "id": cert_id,
            "tags": parse_tags(tags),
            "effective_tags": repo.effective_tags(cert_id),
        }
    )


@router.put("/api/hosts/{host_id}/tags")
async def api_set_host_tags(
    host_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteHostRepository(db)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
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
    return JSONResponse(content={"id": host_id, "tags": parse_tags(tags)})


# ---------- Hosts ----------


@router.get("/api/hosts")
def api_list_hosts(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteHostRepository(db)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = repo.count_all()
    offset = (page - 1) * limit
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
                    "added_at": h.added_at.isoformat(),
                }
                for h in page_hosts
            ],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit else 0,
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
    except Exception:
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
    if runbook_url is not None and not isinstance(runbook_url, str):
        return JSONResponse(
            content={"error": "runbook_url must be a string"},
            status_code=400,
        )

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
    return JSONResponse(
        content={
            "id": host_id,
            "owner_name": updated.owner_name,
            "owner_email": updated.owner_email,
            "owner_slack": updated.owner_slack,
            "renewal_status": updated.renewal_status,
            "renewal_method": updated.renewal_method,
            "runbook_url": updated.runbook_url,
        }
    )


# ---------- Alerts ----------


@router.get("/api/alerts")
def api_list_alerts(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = _total_alerts(db)
    rows = list_alerts_with_subject(db, page=page, limit=limit)
    return JSONResponse(
        content={
            "alerts": rows,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit else 0,
                **_pagination_links(request, "/api/alerts", page, limit, total),
            },
        }
    )


# ---------- Alert Groups (Plan 015) ----------


def _alert_group_json(g) -> dict:
    return {
        "id": g.id,
        "name": g.name,
        "recipients": g.recipients,
        "match_tags": g.match_tags,
        "webhook_url": g.webhook_url,
        "created_at": g.created_at.isoformat(),
    }


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


# ---------- Exports ----------


@router.get("/api/export/certificates.csv")
def api_export_certificates_csv(
    request: Request, _auth: str = Depends(require_auth)
) -> PlainTextResponse:
    """Export all certificates as CSV for compliance reporting."""
    db = _db_path(request)
    rows = list_dashboard_rows(db)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "host",
            "source",
            "subject",
            "issuer",
            "not_after",
            "days_remaining",
            "urgency",
            "chain_valid",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                _csv_safe(r["host"]),
                _csv_safe(r["source"]),
                _csv_safe(r["subject"]),
                _csv_safe(r["issuer"]),
                _csv_safe(r["not_after"]),
                _csv_safe(r["days_remaining"]),
                _csv_safe(r["urgency"]),
                _csv_safe(r.get("chain_valid", "")),
            ]
        )
        for chain in r.get("chain", []):
            writer.writerow(
                [
                    _csv_safe(r["host"]),
                    _csv_safe(r["source"]),
                    _csv_safe(chain["subject"]),
                    _csv_safe(chain["issuer"]),
                    _csv_safe(chain["not_after"]),
                    _csv_safe(chain["days_remaining"]),
                    _csv_safe(chain["urgency"]),
                    "",
                ]
            )
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=certificates.csv"},
    )


@router.get("/api/export/certificates.json")
def api_export_certificates_json(
    request: Request, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Export all certificates as JSON for compliance reporting."""
    db = _db_path(request)
    rows = list_dashboard_rows(db)
    return JSONResponse(
        content={"certificates": rows},
        headers={"Content-Disposition": "attachment; filename=certificates.json"},
    )


# ---------- Reports (Plan 017 A2) ----------


@router.get("/api/reports/inventory.csv")
def api_report_inventory_csv(
    request: Request, _auth: str = Depends(require_auth)
) -> PlainTextResponse:
    """Full certificate inventory as CSV for audit/compliance reporting."""
    db = _db_path(request)
    rows = list_dashboard_rows(db)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "host",
            "port",
            "source",
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "days_remaining",
            "urgency",
            "chain_valid",
            "fingerprint_sha256",
            "tags",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                _csv_safe(r.get("host", "")),
                _csv_safe(r.get("port", "")),
                _csv_safe(r.get("source", "")),
                _csv_safe(r.get("subject", "")),
                _csv_safe(r.get("issuer", "")),
                _csv_safe(r.get("not_before", "")),
                _csv_safe(r.get("not_after", "")),
                _csv_safe(r.get("days_remaining", "")),
                _csv_safe(r.get("urgency", "")),
                _csv_safe(r.get("chain_valid", "")),
                _csv_safe(r.get("fingerprint_sha256", "")),
                _csv_safe(r.get("tags", "")),
            ]
        )
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inventory.csv"},
    )


@router.get("/api/reports/expiring.csv")
def api_report_expiring_csv(
    request: Request,
    _auth: str = Depends(require_auth),
    days: int = 30,
) -> PlainTextResponse:
    """Certificates expiring within *days* days as CSV."""
    days = max(1, min(days, 365))
    db = _db_path(request)
    rows = list_dashboard_rows(db)
    expiring = [
        r
        for r in rows
        if isinstance(r.get("days_remaining"), (int, float)) and r["days_remaining"] <= days
    ]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "host",
            "port",
            "subject",
            "issuer",
            "not_after",
            "days_remaining",
            "urgency",
            "owner",
            "tags",
        ]
    )
    for r in expiring:
        writer.writerow(
            [
                _csv_safe(r.get("host", "")),
                _csv_safe(r.get("port", "")),
                _csv_safe(r.get("subject", "")),
                _csv_safe(r.get("issuer", "")),
                _csv_safe(r.get("not_after", "")),
                _csv_safe(r.get("days_remaining", "")),
                _csv_safe(r.get("urgency", "")),
                _csv_safe(r.get("owner_name", "")),
                _csv_safe(r.get("tags", "")),
            ]
        )
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=expiring-{days}d.csv"},
    )


# ---------- Webhook test ----------


@router.post("/api/webhook/test")
async def api_webhook_test(request: Request, _auth: str = Depends(require_write)) -> JSONResponse:
    """Send a test payload to the configured webhook URL."""
    settings = _get_settings(request)
    webhook_cfg = settings.build_webhook_config()
    if webhook_cfg is None:
        return JSONResponse(
            content={"error": "webhook not configured (set ALERT_WEBHOOK_URL)"},
            status_code=400,
        )

    test_alert = Alert(
        cert_id="test-00000000",
        alert_type="test",
        status="pending",
        message="[cert-watch] Webhook test — verify your webhook configuration.",
        threshold_days=0,
    )
    success = send_webhook(test_alert, webhook_cfg)
    if success:
        return JSONResponse(content={"status": "ok", "message": "webhook test delivered"})
    return JSONResponse(
        content={
            "status": "error",
            "message": test_alert.error_message or "webhook delivery failed",
        },
        status_code=502,
    )


@router.get("/api/ct/reconciliation")
def ct_reconciliation(request: Request, _auth: str = Depends(require_auth), domain: str = ""):
    """CT reconciliation: compare CT log entries against tracked hosts.

    Query params:
      domain (required): base domain to check (e.g. "example.com")

    Returns JSON with tracked/ct hostnames, coverage percentage, and gaps.
    """
    if not domain:
        return JSONResponse(
            content={"error": "domain query parameter is required"},
            status_code=400,
        )
    s = _get_settings(request)
    from cert_watch.ct_monitor import ct_reconciliation as ct_recon

    result = ct_recon(s.db_path, domain)
    return JSONResponse(
        content={
            "domain": result.domain,
            "tracked_hostnames": result.tracked_hostnames,
            "ct_hostnames": result.ct_hostnames,
            "ct_only_hostnames": result.ct_only_hostnames,
            "tracked_only_hostnames": result.tracked_only_hostnames,
            "coverage_pct": result.coverage_pct,
            "error": result.error or None,
        }
    )


@router.get("/api/pivot/{pivot}/{group_key:path}")
def api_pivot_group_entries(
    request: Request, pivot: str, group_key: str, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Return entries for a single pivot group (lazy-loaded, BC-048).

    Used by the dashboard to load group details on expand without
    materializing the full inventory.
    """
    if pivot not in ("issuer", "owner", "renewal_method"):
        return JSONResponse(
            content={"error": f"invalid pivot: {pivot}"},
            status_code=400,
        )
    db = _db_path(request)
    from cert_watch.database import get_pivot_group_entries

    entries = get_pivot_group_entries(db, pivot, group_key)
    # Strip internal _pivot_key field
    for e in entries:
        e.pop("_pivot_key", None)
    return JSONResponse(
        content={
            "pivot": pivot,
            "group_key": group_key,
            "entries": entries,
        }
    )


# ---------- Trends (Plan 016) ----------


@router.get("/api/trends/tls-versions")
def api_tls_version_trends(
    request: Request, _auth: str = Depends(require_auth), days: int = 30
) -> JSONResponse:
    db = _db_path(request)
    trends = list_tls_version_trends(db, days=min(max(days, 1), 365))
    return JSONResponse(content={"days": days, "trends": trends})


@router.get("/api/trends/grades")
def api_grade_trends(
    request: Request, _auth: str = Depends(require_auth), days: int = 30
) -> JSONResponse:
    db = _db_path(request)
    trends = list_grade_trends(db, days=min(max(days, 1), 365))
    return JSONResponse(content={"days": days, "trends": trends})


# ---------- Calendar (Plan 016 Slice 4) ----------


@router.get("/api/calendar")
def api_calendar(
    request: Request,
    _auth: str = Depends(require_auth),
    bucket: str = "month",
    from_date: str | None = None,
    to_date: str | None = None,
) -> JSONResponse:
    if bucket not in ("day", "week", "month"):
        bucket = "month"
    db = _db_path(request)
    buckets = list_calendar(db, from_date=from_date, to_date=to_date, bucket=bucket)
    return JSONResponse(content={"bucket": bucket, "buckets": buckets})
