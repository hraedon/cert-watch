"""Alerts view route."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from cert_watch import __commit__, __version__
from cert_watch.alerting.evidence import FAILURE_LABELS
from cert_watch.alerting.model import (
    UNDELIVERED_AFTER_HOURS,
    delivery_is_configured,
    normalize_channel,
)
from cert_watch.database import (
    _count_alerts_by_filter,
    list_alerts_with_subject,
)
from cert_watch.database.delivery_evidence import latest_outcomes, list_attempts
from cert_watch.middleware import get_auth_context, get_csrf_context
from cert_watch.routes._deps import _db_path, _get_settings, get_templates
from cert_watch.routes._scoped import scope_tags_from_auth

logger = logging.getLogger("cert_watch.routes.alerts_view")

router = APIRouter()

templates = get_templates()


def _undelivered_ids(rows: list[dict[str, Any]], *, delivery_configured: bool = True) -> set[str]:
    """Queued alerts or stale sending leases that are still undelivered.

    Derived at render time rather than stored on the row. ``process_pending``
    defers precisely when the database refuses a write, so the reason cannot be
    persisted at the moment it is known -- the store that would hold it is the
    one that is down. Reads still work, and age is enough: `pending` past the
    window means no transport accepted it, whatever the cause. That also covers
    a scheduler that has simply stopped flushing, which no delivery-side marker
    would ever record.

    "Missed the cycle that should have sent it" presupposes such a cycle. With
    no transport configured there is none, so nothing here is late; the rows
    still render as ``Recorded: pending`` and the tab says once, at the top,
    that nothing is configured to send them.
    """
    if not delivery_configured:
        return set()
    cutoff = datetime.now(UTC) - timedelta(hours=UNDELIVERED_AFTER_HOURS)
    now = datetime.now(UTC)
    stale: set[str] = set()
    for row in rows:
        status = row.get("status")
        raised = _parse_timestamp(row.get("created_at"))
        lease_expires = _parse_timestamp(row.get("lease_expires_at"))
        if (
            status == "pending"
            and raised is not None
            and raised <= cutoff
        ) or (
            status == "sending"
            and (lease_expires is None or lease_expires <= now)
        ):
            stale.add(row["id"])
    return stale


def _parse_timestamp(value: object) -> datetime | None:
    """An unparseable timestamp must not promote an alert to undelivered."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


@router.get("/alerts", response_class=HTMLResponse)
def alerts_view(
    request: Request,
    page: int = 1,
    filter_type: str = "all",
    saved: str = "",
    warning: str = "",
    error: str = "",
) -> HTMLResponse:
    db = _db_path(request)
    per_page = 50
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    counts = _count_alerts_by_filter(db, scope_tags=scope_tags)
    unread_only = filter_type == "unread"
    critical_only = filter_type == "critical"
    warning_only = filter_type == "warning"
    rows = list_alerts_with_subject(
        db,
        page=page,
        limit=per_page,
        unread_only=unread_only,
        critical_only=critical_only,
        warning_only=warning_only,
        scope_tags=scope_tags,
    )
    total = counts.get(filter_type, counts["all"])
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))

    auth = get_auth_context(request)
    # Recipient evidence is admin-only, and IDs come exclusively from the
    # existing scope-filtered page. Do not preload this data for other viewers.
    attempts = list_attempts(db, [row["id"] for row in rows]) if auth["is_admin"] else {}
    for alert_attempts in attempts.values():
        for attempt in alert_attempts:
            attempt["channel"] = normalize_channel(attempt["channel"])
    outcomes = latest_outcomes(db, [row["id"] for row in rows])
    delivery_configured = delivery_is_configured(_get_settings(request))
    undelivered = _undelivered_ids(rows, delivery_configured=delivery_configured)

    return templates.TemplateResponse(
        request=request,
        name="activity.html",
        context={
            "alerts": rows,
            "delivery_attempts": attempts,
            "delivery_outcomes": outcomes,
            "undelivered_alert_ids": undelivered,
            "alert_delivery_configured": delivery_configured,
            "delivery_failure_labels": FAILURE_LABELS,
            "version": __version__, "commit": __commit__,
            **auth,
            **get_csrf_context(request),
            "active_page": "activity",
            "tab": "alerts",
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "filter_type": filter_type,
            "alert_counts": counts,
            "saved": saved,
            "warning": warning,
            "error": error,
        },
    )
