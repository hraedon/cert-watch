"""Dashboard and alert action routes."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.attention import build_attention_queue
from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import (
    AlertRepository,
    ScopedAlertRepository,
    SqliteAlertRepository,
    dashboard_urgency_stats,
    distinct_tags,
    get_posture_grades_for_certs,
    get_write_lock,
    list_calendar,
    list_dashboard_grouped_page,
    list_dashboard_page,
    list_fleet_pivot,
    pivot_urgency_stats,
)
from cert_watch.database.connection import _connect
from cert_watch.middleware import (
    _extract_client_ip,
    check_rate_limit,
    get_auth_context,
    get_csrf_context,
    require_write,
    require_write_form,
)
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, get_templates
from cert_watch.routes._scoped import scope_tags_from_auth, scope_write_denied

logger = logging.getLogger("cert_watch.routes.dashboard")

router = APIRouter()

templates = get_templates()


# Query params that belong to the inventory table (now at /browse). A request
# for / carrying any of them is a legacy bookmark — redirect to /browse.
_BROWSE_PARAMS = {"q", "urgency", "source", "sort_by", "sort_order", "page", "grouped", "view"}


@router.get("/", response_model=None)
def home(
    request: Request,
    error: str | None = None,
    warning: str | None = None,
    saved: str | None = None,
) -> HTMLResponse | RedirectResponse:
    if _BROWSE_PARAMS & set(request.query_params):
        return RedirectResponse(url=f"/browse?{request.query_params}", status_code=307)

    db = _db_path(request)
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = scope_tags_from_auth(auth_ctx)

    items = build_attention_queue(db, scope_tags=scope_tags)
    stats = dashboard_urgency_stats(db, scope_tags=scope_tags)

    # Next-12-weeks horizon with storm markers (same bucket query as the
    # calendar view on /browse).
    horizon = list_calendar(db, bucket="week", scope_tags=scope_tags)
    _now = datetime.now(UTC)
    _week_start = _now - timedelta(days=_now.weekday())
    current_week_start = _week_start.strftime("%Y-%m-%d")
    next_week_start = (_week_start + timedelta(days=7)).strftime("%Y-%m-%d")
    horizon = [b for b in horizon if b["bucket_start"] >= current_week_start][:12]
    storms = 0
    for b in horizon:
        bs = b["bucket_start"]
        if bs <= current_week_start:
            b["tone"] = "t-crit"
        elif bs <= next_week_start:
            b["tone"] = "t-warn"
        else:
            b["tone"] = ""
        if b.get("count", 0) >= 3:
            storms += 1

    csrf_ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={
            "queue": items,
            "stats": stats,
            "horizon": horizon,
            "current_week_start": current_week_start,
            "horizon_storms": storms,
            "version": __version__, "commit": __commit__,
            "error": error,
            "warning": warning,
            "saved": saved,
            **auth_ctx,
            "active_page": "home",
            **csrf_ctx,
        },
    )


@router.get("/browse", response_class=HTMLResponse)
def dashboard(
    request: Request,
    error: str | None = None,
    warning: str | None = None,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    grouped: int = 1,
    view: str = "",
) -> HTMLResponse:
    db = _db_path(request)

    # Tag-scoped access control: scoped users see only objects whose effective
    # tags include one of their scope tags. Admins with an empty scope see all.
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = scope_tags_from_auth(auth_ctx)

    # Pivot views use SQL-level aggregation (BC-048)
    pivot_groups = None
    pivot_stats = None
    if view in ("issuer", "owner", "renewal_method"):
        pivot_groups = list_fleet_pivot(db, view, scope_tags=scope_tags)

    # Calendar view: weekly expiry buckets (absorbed from the old /insights)
    calendar_data = None
    current_week_start = ""
    calendar_storms = 0
    if view == "calendar":
        calendar_data = list_calendar(db, bucket="week", scope_tags=scope_tags)
        _now = datetime.now(UTC)
        _week_start = _now - timedelta(days=_now.weekday())
        current_week_start = _week_start.strftime("%Y-%m-%d")
        next_week_start = (_week_start + timedelta(days=7)).strftime("%Y-%m-%d")
        for b in calendar_data:
            bs = b.get("bucket_start", "")
            if bs <= current_week_start:
                b["tone"] = "t-crit"
            elif bs <= next_week_start:
                b["tone"] = "t-warn"
            else:
                b["tone"] = ""
            if b.get("count", 0) >= 3:
                calendar_storms += 1

    per_page = 25
    page_entries: list[dict[str, Any]] = []
    if calendar_data is not None:
        total = sum(b.get("count", 0) for b in calendar_data)
        total_pages = 1
        # Same stats source as the inventory table, so the strip doesn't
        # change numbers when the user switches to the calendar view.
        pivot_stats = dashboard_urgency_stats(db, scope_tags=scope_tags)
    elif pivot_groups:
        # Pivot view: compute stats from SQL (no full inventory load)
        total = sum(g["count"] for g in pivot_groups)
        total_pages = 1
        # Urgency distribution via targeted SQL (julianday-safe and tag-scoped to
        # match the grouped rows above; see pivot_urgency_stats for the rationale).
        # Pending hosts (no cert = gray) are not counted in urgency buckets.
        pivot_stats = pivot_urgency_stats(db, scope_tags=scope_tags)
    elif grouped:
        # Grouped path: grouping by leaf fingerprint with worst urgency +
        # host count, filtered/sorted — SQL-level pagination (BC-073).
        page_entries, total = list_dashboard_grouped_page(
            db, q=q, urgency=urgency, source=source,
            sort_by=sort_by, sort_order=sort_order,
            page=page, per_page=per_page,
            scope_tags=scope_tags,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))
    else:
        # Fast path: no grouping, no pivot — SQL-level pagination (BC-073).
        page_entries, total = list_dashboard_page(
            db, q=q, urgency=urgency, source=source,
            sort_by=sort_by, sort_order=sort_order,
            page=page, per_page=per_page,
            scope_tags=scope_tags,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))

    if pivot_stats is None:
        pivot_stats = dashboard_urgency_stats(
            db, q=q, source=source, scope_tags=scope_tags
        )

    csrf_ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)

    display_entries = [] if (pivot_groups or calendar_data is not None) else page_entries
    cert_ids = [e["id"] for e in display_entries if e.get("id")]
    posture_grades = get_posture_grades_for_certs(db, cert_ids) if cert_ids else {}

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "entries": display_entries,
            "all_tags": distinct_tags(db),
            "pivot_groups": pivot_groups,
            "pivot_stats": pivot_stats,
            "pivot_view": view if (pivot_groups or calendar_data is not None) else "",
            "calendar_data": calendar_data,
            "current_week_start": current_week_start,
            "calendar_storms": calendar_storms,
            "version": __version__, "commit": __commit__,
            "error": error,
            "warning": warning,
            **auth_ctx,
            "active_page": "browse",
            "filter_q": q or "",
            "filter_urgency": urgency or "",
            "filter_source": source or "",
            "sort_by": sort_by,
            "sort_order": sort_order,
            "page": page,
            "total_pages": total_pages,
            "total_entries": total,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "grouped": grouped,
            "posture_grades": posture_grades,
            **csrf_ctx,
        },
    )


@router.post("/api/alerts/{alert_id}/read", response_model=None)
async def mark_alert_read(
    request: Request,
    alert_id: IdParam,
    _auth: str = Depends(require_write),
) -> dict[str, Any] | JSONResponse:
    """Mark an alert as read."""
    db = _db_path(request)
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT cert_id FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "alert not found"}
        denied = scope_write_denied(request, db, cert_id=row["cert_id"])
        if denied:
            return JSONResponse({"ok": False, "error": denied}, status_code=403)
    with get_write_lock(), _connect(db) as conn:
        cur = conn.execute(
            "UPDATE alerts SET read = 1 WHERE id = ?",
            (alert_id,),
        )
        conn.commit()
    return {"ok": True, "id": alert_id, "updated": cur.rowcount > 0}


@router.post("/alerts/flush")
async def flush_alert_queue(request: Request) -> RedirectResponse:
    """Flush the pending alert queue: trigger immediate send via process_pending()."""
    write_err = await require_write_form(request)
    if write_err:
        return write_err

    if not check_rate_limit(f"flush_alerts:{_extract_client_ip(request)}", 3, 300):
        return RedirectResponse(
            url="/alerts?error=rate+limited%3A+too+many+flush+requests",
            status_code=303,
        )
    db = _db_path(request)
    s = _get_settings(request)

    # Tag-scoped access control: filter alerts by user's scope tags
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = scope_tags_from_auth(auth_ctx)

    # Scoped users flush only their in-scope alerts; everyone else flushes all.
    alert_repo: AlertRepository = (
        ScopedAlertRepository(db, scope_tags)
        if scope_tags
        else SqliteAlertRepository(db)
    )

    alert_config = s.build_alert_config() if s.smtp_host else None
    webhook_config = s.build_webhook_config() if s.webhook_url else None
    from cert_watch.alerts import process_pending

    result = process_pending(alert_repo, alert_config, webhook_config)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert.flush_queue",
        target_type="alert",
        target_id="all",
        detail=result,
        source_ip=resolve_source_ip(request),
    )
    sent = result["sent"]
    failed = result["failed"]
    if failed > 0:
        return RedirectResponse(
            url=f"/alerts?warning={quote(f'Flushed {sent} alert(s), {failed} failed')}",
            status_code=303,
        )
    return RedirectResponse(
        url=f"/alerts?saved={quote(f'{sent} alert(s) sent')}",
        status_code=303,
    )


@router.post("/alerts/mark-all-read")
async def mark_all_alerts_read(request: Request) -> RedirectResponse:
    """Mark all unread alerts as read."""
    write_err = await require_write_form(request)
    if write_err:
        return write_err

    if not check_rate_limit(f"mark_all_read:{_extract_client_ip(request)}", 10, 300):
        return RedirectResponse(
            url="/alerts?error=rate+limited%3A+too+many+mark-all-read+requests",
            status_code=303,
        )
    db = _db_path(request)

    # Tag-scoped access control (WI-078): a scoped user only clears alerts inside
    # their team scope; admins / unscoped users clear everything.
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = scope_tags_from_auth(auth_ctx)

    with get_write_lock():
        count = SqliteAlertRepository(db).mark_all_read(scope_tags)

    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert.mark_all_read",
        target_type="alert",
        target_id="all",
        detail={"count": count},
        source_ip=resolve_source_ip(request),
    )
    plural = "alert" if count == 1 else "alerts"
    return RedirectResponse(
        url=f"/alerts?saved={quote(f'{count} {plural} marked as read')}",
        status_code=303,
    )
