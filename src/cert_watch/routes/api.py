"""REST API (JSON) endpoints."""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from cert_watch.alerts import Alert, send_webhook
from cert_watch.auth import SESSION_COOKIE, NoAuthProvider, validate_session
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    count_dashboard_leaves,
    list_alerts_with_subject,
    list_dashboard_rows,
)
from cert_watch.middleware import check_csrf

logger = logging.getLogger("cert_watch.routes.api")

router = APIRouter()


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


# ---------- Certificates ----------


@router.get("/api/certificates")
def api_list_certificates(request: Request, page: int = 1, limit: int = 50) -> JSONResponse:
    db = _db_path(request)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = count_dashboard_leaves(db)
    rows = list_dashboard_rows(db, page=page, per_page=limit)
    pages = (total + limit - 1) // limit if limit else 0
    return JSONResponse(content={
        "certificates": rows,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": pages,
            **_pagination_links(request, "/api/certificates", page, limit, total),
        },
    })


@router.get("/api/certificates/{cert_id}")
def api_get_certificate(request: Request, cert_id: str) -> JSONResponse:
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content={
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
    })


@router.patch("/api/certificates/{cert_id}/notes")
async def api_update_notes(cert_id: str, request: Request) -> JSONResponse:
    # BC-012: PATCH notes requires auth and CSRF when authentication is enabled
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is not None and not isinstance(auth, NoAuthProvider):
        token = request.cookies.get(SESSION_COOKIE, "")
        username = validate_session(token)
        if not username:
            return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
        csrf_err = await check_csrf(request)
        if csrf_err:
            return JSONResponse(content={"error": csrf_err}, status_code=403)
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
    return JSONResponse(content={"id": cert_id, "notes": notes})


# ---------- Hosts ----------


@router.get("/api/hosts")
def api_list_hosts(request: Request, page: int = 1, limit: int = 50) -> JSONResponse:
    db = _db_path(request)
    hosts = SqliteHostRepository(db).list_all()
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = len(hosts)
    start = (page - 1) * limit
    end = start + limit
    page_hosts = hosts[start:end]
    return JSONResponse(content={
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
    })


@router.patch("/api/hosts/{host_id}/owner")
async def api_update_host_owner(host_id: str, request: Request) -> JSONResponse:
    """Update owner/contact and renewal status for a host."""
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is not None and not isinstance(auth, NoAuthProvider):
        token = request.cookies.get(SESSION_COOKIE, "")
        username = validate_session(token)
        if not username:
            return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
        csrf_err = await check_csrf(request)
        if csrf_err:
            return JSONResponse(content={"error": csrf_err}, status_code=403)
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
    updated = repo.get(host_id)
    return JSONResponse(content={
        "id": host_id,
        "owner_name": updated.owner_name,
        "owner_email": updated.owner_email,
        "owner_slack": updated.owner_slack,
        "renewal_status": updated.renewal_status,
    })


# ---------- Alerts ----------


@router.get("/api/alerts")
def api_list_alerts(request: Request, page: int = 1, limit: int = 50) -> JSONResponse:
    db = _db_path(request)
    rows = list_alerts_with_subject(db)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = len(rows)
    start = (page - 1) * limit
    end = start + limit
    page_rows = rows[start:end]
    return JSONResponse(content={
        "alerts": page_rows,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit if limit else 0,
            **_pagination_links(request, "/api/alerts", page, limit, total),
        },
    })


# ---------- Exports ----------


@router.get("/api/export/certificates.csv")
def api_export_certificates_csv(request: Request) -> PlainTextResponse:
    """Export all certificates as CSV for compliance reporting."""
    db = _db_path(request)
    rows = list_dashboard_rows(db)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "host", "source", "subject", "issuer", "not_after",
        "days_remaining", "urgency", "chain_valid", "leaf_subject",
        "leaf_issuer", "leaf_not_after",
    ])
    for r in rows:
        writer.writerow([
            r["host"],
            r["source"],
            r["subject"],
            r["issuer"],
            r["not_after"],
            r["days_remaining"],
            r["urgency"],
            r.get("chain_valid", ""),
            r["subject"],
            r["issuer"],
            r["not_after"],
        ])
        for chain in r.get("chain", []):
            writer.writerow([
                r["host"],
                r["source"],
                chain["subject"],
                chain["issuer"],
                chain["not_after"],
                chain["days_remaining"],
                chain["urgency"],
                "",
                r["subject"],
                r["issuer"],
                r["not_after"],
            ])
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=certificates.csv"},
    )


@router.get("/api/export/certificates.json")
def api_export_certificates_json(request: Request) -> JSONResponse:
    """Export all certificates as JSON for compliance reporting."""
    db = _db_path(request)
    rows = list_dashboard_rows(db)
    return JSONResponse(
        content={"certificates": rows},
        headers={"Content-Disposition": "attachment; filename=certificates.json"},
    )


# ---------- Webhook test ----------


@router.post("/api/webhook/test")
async def api_webhook_test(request: Request) -> JSONResponse:
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
