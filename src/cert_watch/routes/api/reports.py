"""Report and export API endpoints."""

from __future__ import annotations

import csv
import io
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from cert_watch import __commit__, __version__
from cert_watch.compliance import build_compliance_report, report_to_csv_rows, report_to_dict
from cert_watch.database import list_dashboard_page
from cert_watch.middleware import require_auth
from cert_watch.readiness import build_readiness_report, readiness_report_to_dict
from cert_watch.routes._deps import _csv_safe, _db_path
from cert_watch.routes._scoped import enforce_scope_tag, scope_tags_from_auth
from cert_watch.routes.api._shared import compliance_signing_key

logger = logging.getLogger("cert_watch.routes.api.reports")

router = APIRouter()


@router.get("/api/export/certificates.csv")
def api_export_certificates_csv(
    request: Request, _auth: str = Depends(require_auth)
) -> PlainTextResponse:
    """Export all certificates as CSV for compliance reporting."""
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    rows, _ = list_dashboard_page(db, per_page=100000, scope_tags=scope_tags)
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
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    rows, _ = list_dashboard_page(db, per_page=100000, scope_tags=scope_tags)
    return JSONResponse(
        content={"certificates": rows},
        headers={"Content-Disposition": "attachment; filename=certificates.json"},
    )


@router.get("/api/reports/inventory.csv")
def api_report_inventory_csv(
    request: Request, _auth: str = Depends(require_auth)
) -> PlainTextResponse:
    """Full certificate inventory as CSV for audit/compliance reporting."""
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    rows, _ = list_dashboard_page(db, per_page=100000, scope_tags=scope_tags)
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
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    rows, _ = list_dashboard_page(db, per_page=100000, scope_tags=scope_tags)
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


@router.get("/api/reports/compliance.json")
def api_compliance_report_json(
    request: Request,
    _auth: str = Depends(require_auth),
    tag: str = "",
) -> JSONResponse:
    db = _db_path(request)
    denied = enforce_scope_tag(request, tag)
    if denied:
        return JSONResponse(content={"error": denied}, status_code=403)
    signing_key = compliance_signing_key(request)
    report = build_compliance_report(
        db,
        scope_tag=tag,
        version=__version__,
        commit=__commit__,
        signing_key=signing_key,
    )
    return JSONResponse(
        content=report_to_dict(report),
        headers={"Content-Disposition": "attachment; filename=compliance-report.json"},
    )


@router.get("/api/reports/compliance.csv")
def api_compliance_report_csv(
    request: Request,
    _auth: str = Depends(require_auth),
    tag: str = "",
) -> PlainTextResponse:
    db = _db_path(request)
    denied = enforce_scope_tag(request, tag)
    if denied:
        return PlainTextResponse(denied, status_code=403)
    signing_key = compliance_signing_key(request)
    report = build_compliance_report(
        db,
        scope_tag=tag,
        version=__version__,
        commit=__commit__,
        signing_key=signing_key,
    )
    output = io.StringIO()
    writer = csv.writer(output)
    for row in report_to_csv_rows(report):
        writer.writerow(row)
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=compliance-report.csv"},
    )


@router.get("/api/readiness.json")
def api_readiness_report_json(
    request: Request, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)
    report = build_readiness_report(db)
    return JSONResponse(
        content=readiness_report_to_dict(report),
        headers={"Content-Disposition": "attachment; filename=readiness-report.json"},
    )
