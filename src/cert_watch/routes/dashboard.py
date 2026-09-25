"""Dashboard and alert action routes."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from cert_watch import __commit__, __version__
from cert_watch.attention import attention_queue_page
from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.auth.guards import get_auth_context, write_form_guard
from cert_watch.auth.scope import ScopeDeniedError, writable_scope_tags
from cert_watch.database import (
    AlertStore,
    dashboard_axis_stats,
    dashboard_inventory_count,
    get_write_lock,
    list_calendar,
)
from cert_watch.database.chain_status_cache import prepare_status
from cert_watch.database.connection import _connect
from cert_watch.presenters.browse import present_browse
from cert_watch.presenters.home import present_home
from cert_watch.routes._deps import (
    IdParam,
    _db_path,
    _get_settings,
    acting_auth,
    get_templates,
)
from cert_watch.routes._scoped import scope_tags_from_auth
from cert_watch.scan_freshness import load_scan_evidence, summarize_scan_evidence
from cert_watch.security.csrf import get_csrf_context
from cert_watch.security.ratelimit import _extract_client_ip, check_rate_limit
from cert_watch.services.alert_state import mark_all_alerts_read as mark_all_alerts_read_service
from cert_watch.services.browse_page import load_browse_page
from cert_watch.status_model import (
    AxisSettings,
    invalid_status_filters,
    prepare_status_model_context,
)

logger = logging.getLogger("cert_watch.routes.dashboard")

router = APIRouter()

templates = get_templates()


# Query params that belong to the inventory table (now at /browse). A request
# for / carrying any of them is a legacy bookmark — redirect to /browse.
_BROWSE_PARAMS = {
    "q", "urgency", "source", "condition", "monitoring", "renewal", "delivery",
    "sort_by", "sort_order", "page", "grouped", "view",
}


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

    settings = _get_settings(request)
    scan_evidence = load_scan_evidence(
        db, scope_tags=scope_tags, hour=settings.sched_hour, minute=settings.sched_min,
    )
    # One status context for the page: the queue, the cards and the total
    # are judged at one instant with one chain status per certificate.
    status = prepare_status(db)
    axis_settings = AxisSettings.from_settings(settings)
    axes = prepare_status_model_context(
        db, certificate_status=status, settings=axis_settings
    )
    items, queue_total = attention_queue_page(
        db, scope_tags=scope_tags, window_days=settings.renewal_window_days,
        scan_evidence=scan_evidence, status=status,
    )
    axis_stats = dashboard_axis_stats(
        db, scope_tags=scope_tags, status=status, axes=axes
    )
    stats = {
        "expired": axis_stats["condition"]["expired"],
        "critical": axis_stats["condition"]["le7"],
        "warning": axis_stats["condition"]["8to30"],
        "healthy": axis_stats["condition"]["ok"],
    }
    tracked_total = dashboard_inventory_count(db, scope_tags=scope_tags)

    view = present_home(
        queue=items,
        queue_total=queue_total,
        stats=stats,
        axis_stats=axis_stats,
        tracked_total=tracked_total,
        scan_coverage=summarize_scan_evidence(scan_evidence),
        calendar=list_calendar(db, bucket="week", scope_tags=scope_tags),
        now=datetime.now(UTC),
        error=error,
        warning=warning,
        saved=saved,
    )

    csrf_ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={
            **view.template_context(),
            "version": __version__, "commit": __commit__,
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
    notice: str | None = None,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
    condition: str | None = None,
    monitoring: str | None = None,
    renewal: str | None = None,
    delivery: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    grouped: int = 1,
    view: str = "",
) -> HTMLResponse:
    invalid_filters = invalid_status_filters(
        condition=condition,
        monitoring=monitoring,
        renewal=renewal,
        delivery=delivery,
    )
    if invalid_filters:
        ignored = ", ".join(f"{name}={value}" for name, value in invalid_filters.items())
        notice = notice or f"Ignored unknown filter: {ignored}"
        if "condition" in invalid_filters:
            condition = None
        if "monitoring" in invalid_filters:
            monitoring = None
        if "renewal" in invalid_filters:
            renewal = None
        if "delivery" in invalid_filters:
            delivery = None
    db = _db_path(request)
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = scope_tags_from_auth(auth_ctx)
    settings = _get_settings(request)
    data = load_browse_page(
        db,
        q=q,
        urgency=urgency,
        source=source,
        condition=condition,
        monitoring=monitoring,
        renewal=renewal,
        delivery=delivery,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        grouped=grouped,
        view=view,
        scope_tags=scope_tags,
        sched_hour=settings.sched_hour,
        sched_min=settings.sched_min,
        axis_settings=AxisSettings.from_settings(settings),
    )
    presented = present_browse(data, now=datetime.now(UTC))

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            **presented.template_context(),
            "version": __version__, "commit": __commit__,
            "error": error,
            "warning": warning,
            "notice": notice,
            **get_auth_context(request),
            "active_page": "browse",
            **get_csrf_context(request),
        },
    )


@router.post("/alerts/flush")
async def flush_alert_queue(
    request: Request, _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    """Flush the pending alert queue: trigger immediate send via process_pending()."""
    if not check_rate_limit(f"flush_alerts:{_extract_client_ip(request)}", 3, 300):
        return RedirectResponse(
            url="/alerts?error=rate+limited%3A+too+many+flush+requests",
            status_code=303,
        )
    db = _db_path(request)
    s = _get_settings(request)

    # Tag-scoped access control: filter alerts by user's scope tags
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = writable_scope_tags(auth_ctx)

    alert_config = s.build_alert_config() if s.smtp_host else None
    webhook_config = s.build_webhook_config() if s.webhook_url else None
    from cert_watch.alerting.dispatch import Dispatcher
    from cert_watch.scheduler import try_run_alert_delivery

    result = await run_in_threadpool(
        try_run_alert_delivery,
        getattr(request.app.state, "scheduler", None),
        lambda: Dispatcher(
            db,
            alert_config,
            webhook_config,
            scope_tags=scope_tags,
            ignore_backoff=True,
        ).process_pending(),
    )
    if result is None:
        return RedirectResponse(
            url=f"/alerts?warning={quote('Alert delivery already in progress')}",
            status_code=303,
        )
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
    deferred = result.get("deferred", 0)
    if failed > 0 or deferred > 0:
        # A deferral is not a clean no-op: nothing was sent because the evidence
        # store was unwritable. Reporting "0 alert(s) sent" as success would
        # describe an outage as a successful flush.
        detail = f"Flushed {sent} alert(s), {failed} failed"
        if deferred:
            detail += f", {deferred} deferred"
        return RedirectResponse(
            url=f"/alerts?warning={quote(detail)}",
            status_code=303,
        )
    return RedirectResponse(
        url=f"/alerts?saved={quote(f'{sent} alert(s) sent')}",
        status_code=303,
    )


@router.post("/alerts/{alert_id}/retry")
async def retry_failed_alert(
    request: Request,
    alert_id: IdParam,
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    """Return one terminal failed alert to the eligible queue."""
    db = _db_path(request)
    try:
        with get_write_lock():
            retried = AlertStore(db).operator_retry(alert_id, auth=acting_auth(request))
    except ScopeDeniedError:
        record_audit(
            db,
            actor=resolve_actor(request),
            action="alert.retry_denied",
            target_type="alert",
            target_id=alert_id,
            detail={"reason": "scope_denied"},
            source_ip=resolve_source_ip(request),
        )
        return RedirectResponse(url="/alerts?error=alert+not+found", status_code=303)
    if not retried:
        with _connect(db) as conn:
            row = conn.execute(
                "SELECT status FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        if row is None:
            return RedirectResponse(
                url="/alerts?error=alert+not+found", status_code=303
            )
        return RedirectResponse(
            url="/alerts?warning=only+failed+alerts+can+be+retried", status_code=303
        )
    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert.retry_failed",
        target_type="alert",
        target_id=alert_id,
        detail={"previous_status": "failed"},
        source_ip=resolve_source_ip(request),
    )
    return RedirectResponse(url="/alerts?saved=alert+queued+for+retry", status_code=303)


@router.post("/alerts/mark-all-read")
async def mark_all_alerts_read(
    request: Request, _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    """Mark all unread alerts as read."""
    if not check_rate_limit(f"mark_all_read:{_extract_client_ip(request)}", 10, 300):
        return RedirectResponse(
            url="/alerts?error=rate+limited%3A+too+many+mark-all-read+requests",
            status_code=303,
        )
    db = _db_path(request)

    from cert_watch.routes._deps import acting_auth

    count = mark_all_alerts_read_service(
        db,
        auth=acting_auth(request),
        actor=resolve_actor(request),
        source_ip=resolve_source_ip(request),
    )
    plural = "alert" if count == 1 else "alerts"
    return RedirectResponse(
        url=f"/alerts?saved={quote(f'{count} {plural} marked as read')}",
        status_code=303,
    )
