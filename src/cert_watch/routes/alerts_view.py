"""Alerts view route."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from cert_watch import __commit__, __version__
from cert_watch.database import (
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    _count_alerts_by_filter,
    list_alerts_with_subject,
)
from cert_watch.middleware import get_auth_context, get_csrf_context
from cert_watch.routes._deps import _db_path, get_templates
from cert_watch.routes._scoped import scope_tags_from_auth
from cert_watch.tags import tags_match

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

    # Resolve alert-group routing names for each alert's cert
    group_repo = SqliteAlertGroupRepository(db)
    cert_repo = SqliteCertificateRepository(db)
    all_groups = group_repo.list_all()
    _group_cache: dict[str, str | None] = {}

    for a in rows:
        cert_id = a.get("cert_id") or ""
        if not cert_id:
            a["group_name"] = None
            continue
        if cert_id not in _group_cache:
            effective = cert_repo.effective_tags(cert_id)
            manual_ids = set(group_repo.groups_for_cert_manual(cert_id))
            matched = None
            for g in all_groups:
                if g.id in manual_ids or tags_match(effective, g.match_tags):
                    matched = g.name
                    break
            _group_cache[cert_id] = matched
        a["group_name"] = _group_cache.get(cert_id)

    # BC-130: reflect the channels that are actually configured rather than
    # hardcoding Email + Webhook chips on every alert.
    settings = getattr(request.app.state, "settings", None)
    alert_channels: list[str] = []
    if settings is not None:
        if settings.smtp_host and settings.alert_from and settings.alert_recipients:
            alert_channels.append("email")
        if settings.webhook_url:
            alert_channels.append("webhook")

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "alerts": rows,
            "alert_channels": alert_channels,
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "alerts",
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "filter_type": filter_type,
            "alert_counts": counts,
            "saved": saved,
        },
    )
