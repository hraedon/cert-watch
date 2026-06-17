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
    # Inline match count per existing group (WI-060): how many leaf certs would
    # each group route to? Read-only, one COUNT query per group.
    match_counts = {g.id: _match_preview(db, list(g.match_tags), sample_limit=0)[0] for g in groups}
    ctx = _settings_context(request, tab=_TAB)
    ctx["alert_groups"] = groups
    ctx["alert_group_match_counts"] = match_counts
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


@router.get("/settings/alert-groups/preview", response_class=HTMLResponse, response_model=None)
def alert_groups_preview(request: Request) -> HTMLResponse | RedirectResponse:
    """Live 'which certs match these tags' preview (WI-060).

    Read-only GET: the operator enters candidate match tags and sees the count
    (and a small sample) of leaf certs whose effective (cert or host) tags
    intersect them, before committing a group to those tags. Reuses the same
    escaped-LIKE effective-tag matching as the dashboard scope filter.
    """
    redirect_resp = require_admin_form(request)
    if redirect_resp:
        return redirect_resp
    db = _db_path(request)
    raw_tags = str(request.query_params.get("match_tags") or "")
    preview_tags = parse_tags(raw_tags)
    count, sample = _match_preview(db, preview_tags, sample_limit=5)
    groups = SqliteAlertGroupRepository(db).list_all()
    match_counts = {g.id: _match_preview(db, list(g.match_tags), sample_limit=0)[0] for g in groups}
    ctx = _settings_context(request, tab=_TAB)
    ctx["alert_groups"] = groups
    ctx["alert_group_match_counts"] = match_counts
    ctx["preview_match_tags"] = ", ".join(preview_tags)
    ctx["preview_count"] = count
    ctx["preview_sample"] = sample
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)


def _match_preview(
    db_path, match_tags: list[str], *, sample_limit: int = 5
) -> tuple[int, list[dict]]:
    """Count leaf certs whose effective (cert ∪ host) tags intersect *match_tags*.

    Returns ``(count, sample)`` where sample is up to *sample_limit*
    ``{hostname, subject}`` rows (empty when sample_limit <= 0). A cert matches
    when any of its own tags or its host's tags appears in *match_tags*
    (case-insensitive). LIKE wildcards in tags are escaped (BC-051). Read-only.

    Scope (WI-060): this is a **tag-based** preview only, by design. It does NOT
    count certs routed via manual ``alert_group_certs`` assignment nor via
    WI-061 role-linked scope-tag routing -- the inline column and preview copy
    are labelled "tag matches" accordingly. Operators verifying total routing
    for a group with manual/role-linked certs must account for those separately.

    Non-ASCII limitation: SQLite LIKE is ASCII-case-insensitive, so tags that
    differ only by non-ASCII casing (e.g. Turkish dotless-i) may undercount vs
    the alert engine's Python ``casefold()`` match. This parity gap is shared
    with the dashboard scope filter (``_add_effective_tag_filter``); SMB tag
    corpora are typically ASCII.
    """
    from cert_watch.database.connection import _connect
    from cert_watch.database.dashboard import _escape_like

    normalized: list[str] = []
    seen: set[str] = set()
    for tag in match_tags:
        t = (tag or "").strip()
        if not t or t.casefold() in seen:
            continue
        seen.add(t.casefold())
        normalized.append(t)
    if not normalized:
        return 0, []
    conditions: list[str] = []
    params: list = []
    for tag in normalized:
        like = f"%,{_escape_like(tag)},%"
        conditions.append(
            "(',' || COALESCE(c.tags, '') || ',') LIKE ? ESCAPE '\\' "
            "OR (',' || COALESCE(h.tags, '') || ',') LIKE ? ESCAPE '\\'"
        )
        params.extend([like, like])
    where = " OR ".join(conditions)
    join = (
        "FROM certificates c "
        "LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port "
        "WHERE c.is_leaf = 1"
    )
    with _connect(db_path) as conn:
        count = conn.execute(
            f"SELECT COUNT(*) {join} AND ({where})", params
        ).fetchone()[0]
        sample: list[dict] = []
        if sample_limit > 0:
            rows = conn.execute(
                f"SELECT DISTINCT c.hostname, c.subject {join} AND ({where}) "
                f"ORDER BY c.hostname LIMIT ?",
                params + [sample_limit],
            ).fetchall()
            sample = [{"hostname": r["hostname"], "subject": r["subject"]} for r in rows]
    return count, sample


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
