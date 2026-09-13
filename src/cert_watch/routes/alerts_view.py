"""Alerts view route."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from cert_watch import __commit__, __version__
from cert_watch.alert_delivery import FAILURE_LABELS
from cert_watch.alerts import UNDELIVERED_AFTER_HOURS
from cert_watch.database import (
    _count_alerts_by_filter,
    list_alerts_with_subject,
)
from cert_watch.database.delivery_evidence import latest_outcomes, list_attempts
from cert_watch.middleware import get_auth_context, get_csrf_context
from cert_watch.routes._deps import _db_path, get_templates
from cert_watch.routes._scoped import scope_tags_from_auth

logger = logging.getLogger("cert_watch.routes.alerts_view")

router = APIRouter()

templates = get_templates()


def _undelivered_ids(rows: list[dict[str, Any]]) -> set[str]:
    """Pending alerts that have missed the cycle that should have sent them.

    Derived at render time rather than stored on the row. ``process_pending``
    defers precisely when the database refuses a write, so the reason cannot be
    persisted at the moment it is known -- the store that would hold it is the
    one that is down. Reads still work, and age is enough: `pending` past the
    window means no transport accepted it, whatever the cause. That also covers
    a scheduler that has simply stopped flushing, which no delivery-side marker
    would ever record.
    """
    cutoff = datetime.now(UTC) - timedelta(hours=UNDELIVERED_AFTER_HOURS)
    stale: set[str] = set()
    for row in rows:
        if row.get("status") != "pending":
            continue
        raised = _parse_timestamp(row.get("created_at"))
        if raised is not None and raised <= cutoff:
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
    outcomes = latest_outcomes(db, [row["id"] for row in rows])
    undelivered = _undelivered_ids(rows)

    return templates.TemplateResponse(
        request=request,
        name="activity.html",
        context={
            "alerts": rows,
            "delivery_attempts": attempts,
            "delivery_outcomes": outcomes,
            "undelivered_alert_ids": undelivered,
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
        },
    )
