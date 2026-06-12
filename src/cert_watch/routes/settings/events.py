"""Event streaming configuration routes."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.events import (
    ALL_EVENT_TYPES,
    EventStreamConfig,
    load_event_config,
    save_event_config,
)
from cert_watch.http_client import validate_webhook_url
from cert_watch.middleware import check_csrf, require_admin_form
from cert_watch.routes._deps import _db_path
from cert_watch.routes.settings.core import __commit__, __version__, templates

router = APIRouter()


@router.get("/settings/events", response_class=HTMLResponse, response_model=None)
def settings_events_page(request: Request) -> HTMLResponse | RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err
    db = _db_path(request)
    config = load_event_config(db)
    from cert_watch.middleware import get_auth_context, get_csrf_context

    ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)
    return templates.TemplateResponse(
        request=request,
        name="settings_events.html",
        context={
            "version": __version__, "commit": __commit__,
            "config": config,
            "all_event_types": ALL_EVENT_TYPES,
            "active_page": "settings",
            **auth_ctx,
            **ctx,
        },
    )


@router.post("/settings/events")
async def save_settings_events(request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings/events?error={csrf_err}", status_code=303)

    db = _db_path(request)
    form = await request.form()
    enabled: list[str] = []
    for et in form.getlist("enabled_event_types"):
        if isinstance(et, str) and et:
            enabled.append(et)
    if not enabled:
        enabled = list(ALL_EVENT_TYPES)
    webhook_url = str(form.get("webhook_url") or "").strip() or None
    webhook_kind = str(form.get("webhook_kind") or "generic").strip()
    pagerduty_routing_key = str(form.get("pagerduty_routing_key") or "").strip()
    if webhook_url:
        settings = getattr(request.app.state, "settings", None)
        err = validate_webhook_url(
            webhook_url,
            allow_private=settings.allow_private if settings else True,
            allowed_subnets=settings.allowed_subnets if settings else (),
        )
        if err:
            return RedirectResponse(
                url=f"/settings/events?error={quote('Invalid webhook URL: ' + err)}",
                status_code=303,
            )
    try:
        rl_raw = form.get("rate_limit_per_second") or 100
        rate_limit = int(rl_raw) if isinstance(rl_raw, (str, int)) else 100
    except (ValueError, TypeError):
        rate_limit = 100
    config = EventStreamConfig(
        enabled_event_types=enabled,
        webhook_url=webhook_url,
        webhook_kind=webhook_kind,
        pagerduty_routing_key=pagerduty_routing_key,
        rate_limit_per_second=rate_limit,
    )
    save_event_config(db, config)

    record_audit(
        str(db),
        actor=resolve_actor(request),
        action="settings.events",
        target_type="event_stream_config",
        target_id="event_stream_config",
        detail={
            "enabled_event_types": enabled,
            "webhook_kind": webhook_kind,
            "webhook_url_set": bool(webhook_url),
            "pagerduty_routing_key_set": bool(pagerduty_routing_key),
            "rate_limit_per_second": rate_limit,
        },
        source_ip=resolve_source_ip(request),
    )
    return RedirectResponse(url="/settings/events?saved=1", status_code=303)
