"""Insights, trends, and webhook test API endpoints."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.alerting.transports.webhook import send_webhook
from cert_watch.auth.guards import require_auth, write_guard
from cert_watch.database import (
    Alert,
    list_calendar,
    list_grade_trends,
    list_tls_version_trends,
)
from cert_watch.routes._deps import _db_path, _get_settings
from cert_watch.routes._scoped import scope_tags_from_auth

logger = logging.getLogger("cert_watch.routes.api.insights")

router = APIRouter()


@router.post("/api/webhook/test")
async def api_webhook_test(request: Request, _auth: str = Depends(write_guard)) -> JSONResponse:
    """Send a test payload to the configured webhook URL."""
    settings = _get_settings(request)
    # Configuration validation resolves the destination host, and delivery is
    # synchronous HTTP I/O; neither belongs on the request event-loop thread.
    webhook_cfg = await asyncio.to_thread(settings.build_webhook_config)
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
    result = await asyncio.to_thread(send_webhook, test_alert, webhook_cfg)
    if result:
        return JSONResponse(content={"status": "ok", "message": "webhook test delivered"})
    return JSONResponse(
        content={
            "status": "error",
            "message": result.operator_message or "webhook delivery failed",
        },
        status_code=502,
    )


PIVOT_PAGE_SIZE = 100
PIVOT_PAGE_MAX = 500


@router.get("/api/pivot/{pivot}/{group_key:path}")
def api_pivot_group_entries(
    request: Request,
    pivot: str,
    group_key: str,
    _auth: str = Depends(require_auth),
    page: int = 1,
    per_page: int = PIVOT_PAGE_SIZE,
) -> JSONResponse:
    """Return one page of a pivot group's entries (lazy-loaded).

    Used by the dashboard to load group details on expand without
    materializing the full inventory; a large group is paged (``page``,
    ``per_page`` up to 500) and ``total``/``has_more`` tell the client whether
    to offer more.
    """
    if pivot not in ("issuer", "owner", "renewal_method"):
        return JSONResponse(
            content={"error": f"invalid pivot: {pivot}"},
            status_code=400,
        )
    page = max(page, 1)
    per_page = min(max(per_page, 1), PIVOT_PAGE_MAX)
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    from cert_watch.database import get_pivot_group_page

    entries, total = get_pivot_group_page(
        db, pivot, group_key, scope_tags=scope_tags, page=page, per_page=per_page
    )
    # Strip internal _pivot_key field; add the label so the JS consumer
    # doesn't duplicate the status rule (WI-071). The row keeps the urgency
    # it was built with -- the one rule the group's count used. Recomputing
    # it from the leaf's days here called a row with an expired intermediate
    # Healthy inside a group counted as Expired (#113 review).
    from cert_watch.filters import urgency_label

    for e in entries:
        e.pop("_pivot_key", None)
        e["urgency_label"] = urgency_label(e.get("urgency") or "gray")
    return JSONResponse(
        content={
            "pivot": pivot,
            "group_key": group_key,
            "entries": entries,
            "total": total,
            "page": page,
            "per_page": per_page,
            "has_more": (page - 1) * per_page + len(entries) < total,
        }
    )


# ---------- Trends ----------


@router.get("/api/trends/tls-versions")
def api_tls_version_trends(
    request: Request, _auth: str = Depends(require_auth), days: int = 30
) -> JSONResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    trends = list_tls_version_trends(db, days=min(max(days, 1), 365), scope_tags=scope_tags)
    return JSONResponse(content={"days": days, "trends": trends})


@router.get("/api/trends/grades")
def api_grade_trends(
    request: Request, _auth: str = Depends(require_auth), days: int = 30
) -> JSONResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    trends = list_grade_trends(db, days=min(max(days, 1), 365), scope_tags=scope_tags)
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
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    buckets = list_calendar(
        db, from_date=from_date, to_date=to_date, bucket=bucket, scope_tags=scope_tags
    )
    return JSONResponse(content={"bucket": bucket, "buckets": buckets})
