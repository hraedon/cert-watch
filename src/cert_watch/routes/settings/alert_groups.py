"""Alert-group management routes (WI-059).

Server-rendered CRUD for alert groups, mirroring the roles tab. An alert group is
a team's alert-preference entity: ``match_tags`` scopes which certs route to it
(a team's default tag), with per-group recipients, webhook, alert threshold, and
digest cadence. The REST API at ``/api/alert-groups`` covers the same model for
programmatic use; this exposes it in the Settings UI (vanilla forms, no JS).
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import SqliteAlertGroupRepository
from cert_watch.middleware import check_csrf, require_admin_form
from cert_watch.routes._deps import IdParam, _db_path, get_templates
from cert_watch.routes.api._shared import _validate_webhook_url
from cert_watch.routes.settings.render import _settings_context
from cert_watch.tags import parse_tags

templates = get_templates()

router = APIRouter()

_TAB = "alert-groups"


def _redirect_err(msg: str) -> RedirectResponse:
    return RedirectResponse(url=f"/settings?tab={_TAB}&error={quote(msg)}", status_code=303)


def _redirect_ok() -> RedirectResponse:
    return RedirectResponse(url=f"/settings?tab={_TAB}&saved=1", status_code=303)


def _parse_optional_positive_int(raw: str, field: str) -> tuple[int | None, str | None]:
    """('', None) -> (None, None); a positive int -> (int, None); else (None, error)."""
    raw = (raw or "").strip()
    if not raw:
        return None, None
    try:
        val = int(raw)
    except ValueError:
        return None, f"{field} must be a whole number"
    if val < 1:
        return None, f"{field} must be 1 or greater"
    return val, None


def _parse_form(form) -> tuple[dict | None, str | None]:
    """Validate the shared create/edit fields. Returns (values, error)."""
    name = str(form.get("name") or "").strip()
    if not name:
        return None, "name is required"

    recipients = parse_tags(str(form.get("recipients") or ""))
    for r in recipients:
        if "@" not in r:
            return None, f"invalid email: {r}"

    match_tags = parse_tags(str(form.get("match_tags") or ""))
    webhook_url = str(form.get("webhook_url") or "").strip()
    if webhook_url and _validate_webhook_url(webhook_url) is not None:
        return None, "webhook URL is not allowed (must be a public http(s) URL)"

    threshold_days, err = _parse_optional_positive_int(
        str(form.get("threshold_days") or ""), "threshold days"
    )
    if err:
        return None, err

    cadence_raw = str(form.get("digest_cadence_days") or "").strip()
    digest_cadence_days = 7
    if cadence_raw:
        parsed, err = _parse_optional_positive_int(cadence_raw, "digest cadence")
        if err:
            return None, err
        assert parsed is not None  # err is None here, so parsed is a positive int
        digest_cadence_days = parsed

    return {
        "name": name,
        "recipients": recipients,
        "match_tags": match_tags,
        "webhook_url": webhook_url,
        "threshold_days": threshold_days,
        "digest_cadence_days": digest_cadence_days,
    }, None


@router.get("/settings/alert-groups", response_class=HTMLResponse, response_model=None)
def alert_groups_page(request: Request) -> HTMLResponse | RedirectResponse:
    redirect_resp = require_admin_form(request)
    if redirect_resp:
        return redirect_resp
    db = _db_path(request)
    groups = SqliteAlertGroupRepository(db).list_all()
    ctx = _settings_context(request, tab=_TAB)
    ctx["alert_groups"] = groups
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


@router.post("/settings/alert-groups")
async def create_alert_group(request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err
    csrf_err = await check_csrf(request)
    if csrf_err:
        return _redirect_err(csrf_err)

    values, err = _parse_form(await request.form())
    if err:
        return _redirect_err(err)
    assert values is not None  # err is None here, so _parse_form returned values

    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    if repo.get_by_name(values["name"]):
        return _redirect_err(f"alert group '{values['name']}' already exists")

    group_id = repo.create(
        values["name"], values["recipients"], values["match_tags"],
        values["webhook_url"], threshold_days=values["threshold_days"],
        digest_cadence_days=values["digest_cadence_days"],
    )
    record_audit(
        db, actor=resolve_actor(request), action="alert_group.create",
        target_type="alert_group", target_id=group_id,
        detail={"name": values["name"], "match_tags": values["match_tags"]},
        source_ip=resolve_source_ip(request),
    )
    return _redirect_ok()


@router.post("/settings/alert-groups/{group_id}")
async def update_alert_group(group_id: IdParam, request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err
    csrf_err = await check_csrf(request)
    if csrf_err:
        return _redirect_err(csrf_err)

    db = _db_path(request)
    repo = SqliteAlertGroupRepository(db)
    if repo.get(group_id) is None:
        return _redirect_err("alert group not found")

    values, err = _parse_form(await request.form())
    if err:
        return _redirect_err(err)
    assert values is not None  # err is None here, so _parse_form returned values

    existing = repo.get_by_name(values["name"])
    if existing is not None and existing.id != group_id:
        return _redirect_err(f"alert group '{values['name']}' already exists")

    repo.update(
        group_id, name=values["name"], recipients=values["recipients"],
        match_tags=values["match_tags"], webhook_url=values["webhook_url"],
        threshold_days=values["threshold_days"],
        digest_cadence_days=values["digest_cadence_days"],
    )
    record_audit(
        db, actor=resolve_actor(request), action="alert_group.update",
        target_type="alert_group", target_id=group_id,
        detail={"name": values["name"], "match_tags": values["match_tags"]},
        source_ip=resolve_source_ip(request),
    )
    return _redirect_ok()


@router.post("/settings/alert-groups/{group_id}/delete")
async def delete_alert_group(group_id: IdParam, request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err
    csrf_err = await check_csrf(request)
    if csrf_err:
        return _redirect_err(csrf_err)

    db = _db_path(request)
    if SqliteAlertGroupRepository(db).delete(group_id):
        record_audit(
            db, actor=resolve_actor(request), action="alert_group.delete",
            target_type="alert_group", target_id=group_id, detail={},
            source_ip=resolve_source_ip(request),
        )
    return _redirect_ok()
