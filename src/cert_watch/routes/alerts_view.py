"""Alerts view route."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from cert_watch import __commit__, __version__
from cert_watch.alert_delivery import FAILURE_LABELS
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

    return templates.TemplateResponse(
        request=request,
        name="activity.html",
        context={
            "alerts": rows,
            "delivery_attempts": attempts,
            "delivery_outcomes": outcomes,
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
