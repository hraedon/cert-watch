"""Insights, trends, and webhook test API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.alerts import Alert, send_webhook
from cert_watch.database import (
    list_calendar,
    list_grade_trends,
    list_tls_version_trends,
)
from cert_watch.middleware import require_auth, require_write
from cert_watch.routes._deps import _db_path, _get_settings

logger = logging.getLogger("cert_watch.routes.api.insights")

router = APIRouter()


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


@router.get("/api/pivot/{pivot}/{group_key:path}")
def api_pivot_group_entries(
    request: Request, pivot: str, group_key: str, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Return entries for a single pivot group (lazy-loaded).

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


# ---------- Trends ----------


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


# ---------- Calendar ----------


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
