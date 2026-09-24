"""Alert-group management routes (WI-059).

Server-rendered CRUD for alert groups, mirroring the roles tab. An alert group is
a team's alert-preference entity: ``match_tags`` scopes which certs route to it
(a team's default tag), with per-group recipients, webhook, alert threshold, and
digest cadence. The REST API at ``/api/alert-groups`` covers the same model for
programmatic use; this exposes it in the Settings UI (vanilla forms, no JS).
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import admin_page_guard
from cert_watch.database import SqliteAlertGroupRepository
from cert_watch.routes._deps import (
    IdParam,
    _db_path,
    _get_settings,
    acting_auth,
    get_templates,
)
from cert_watch.routes.api._shared import _validate_webhook_url
from cert_watch.routes.settings.core import settings_tab_form
from cert_watch.routes.settings.render import _settings_context
from cert_watch.services.alert_groups import (
    AlertGroupConflictError,
    AlertGroupNotFoundError,
)
from cert_watch.services.alert_groups import (
    create_alert_group as create_alert_group_service,
)
from cert_watch.services.alert_groups import (
    delete_alert_group as delete_alert_group_service,
)
from cert_watch.services.alert_groups import (
    update_alert_group as update_alert_group_service,
)
from cert_watch.tags import parse_tags

templates = get_templates()

router = APIRouter()

_TAB = "alert-groups"
_FORM = settings_tab_form(_TAB)


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


def _parse_form(form: Any) -> tuple[dict[str, Any] | None, str | None]:
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


def _email_delivery_missing(request: Request) -> list[str]:
    """What email delivery still lacks; empty when email alerts can be sent.

    Mirrors ``Settings.build_alert_config``: without an SMTP host, a From
    address *and* at least one global recipient there is no SMTP transport
    at all, so alert-group recipients receive nothing either.
    """
    settings = _get_settings(request)
    missing = []
    if not settings.smtp_host:
        missing.append("an SMTP server")
    if not settings.alert_from:
        missing.append("a From address")
    if not settings.alert_recipients:
        missing.append("at least one global recipient")
    return missing


def _groups_context(request: Request, db: Path) -> dict[str, Any]:
    groups = SqliteAlertGroupRepository(db).list_all()
    ctx = _settings_context(request, tab=_TAB)
    ctx["alert_groups"] = groups
    # Inline match count per existing group (WI-060): how many leaf certs would
    # each group route to? Read-only, one COUNT query per group.
    ctx["alert_group_match_counts"] = {
        g.id: _match_preview(db, list(g.match_tags), sample_limit=0)[0] for g in groups
    }
    # Groups whose email recipients can't be reached because email delivery
    # isn't configured (#113): creating one used to give no hint of that.
    missing = _email_delivery_missing(request)
    ctx["email_missing"] = (
        ", ".join(missing[:-1]) + " and " + missing[-1] if len(missing) > 1 else "".join(missing)
    )
    ctx["groups_without_email"] = [g.name for g in groups if g.recipients] if missing else []
    return ctx


@router.get("/settings/alert-groups", response_class=HTMLResponse, response_model=None)
def alert_groups_page(
    request: Request, _auth: str = Depends(admin_page_guard),
) -> HTMLResponse | RedirectResponse:
    ctx = _groups_context(request, _db_path(request))
    return templates.TemplateResponse(
        request=request, name="settings/alert_groups.html", context=ctx
    )


@router.get("/settings/alert-groups/preview", response_class=HTMLResponse, response_model=None)
def alert_groups_preview(
    request: Request, _auth: str = Depends(admin_page_guard),
) -> HTMLResponse | RedirectResponse:
    """Live 'which certs match these tags' preview (WI-060).

    Read-only GET: the operator enters candidate match tags and sees the count
    (and a small sample) of leaf certs whose effective (cert or host) tags
    intersect them, before committing a group to those tags. Reuses the same
    escaped-LIKE effective-tag matching as the dashboard scope filter.
    """
    db = _db_path(request)
    raw_tags = str(request.query_params.get("match_tags") or "")
    preview_tags = parse_tags(raw_tags)
    count, sample = _match_preview(db, preview_tags, sample_limit=5)
    ctx = _groups_context(request, db)
    ctx["preview_match_tags"] = ", ".join(preview_tags)
    ctx["preview_count"] = count
    ctx["preview_sample"] = sample
    return templates.TemplateResponse(
        request=request, name="settings/alert_groups.html", context=ctx
    )


def _match_preview(
    db_path: str | Path, match_tags: list[str], *, sample_limit: int = 5
) -> tuple[int, list[dict[str, Any]]]:
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

    Matching is Unicode-case-insensitive via the ``cw_casefold`` SQL function
    (WI-066), so it agrees with the alert engine's Python ``casefold()`` match
    for non-ASCII tags (Turkish dotless-i, German ß, etc.) as well as the
    dashboard scope filter.
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
    params: list[str] = []
    for tag in normalized:
        like = f"%,{_escape_like(tag)},%"
        conditions.append(
            "cw_casefold(',' || COALESCE(c.tags, '') || ',') LIKE cw_casefold(?) ESCAPE '\\' "
            "OR cw_casefold(',' || COALESCE(h.tags, '') || ',') LIKE cw_casefold(?) ESCAPE '\\'"
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
        sample: list[dict[str, Any]] = []
        if sample_limit > 0:
            rows = conn.execute(
                f"SELECT DISTINCT c.hostname, c.subject {join} AND ({where}) "
                f"ORDER BY c.hostname LIMIT ?",
                [*params, sample_limit],
            ).fetchall()
            sample = [{"hostname": r["hostname"], "subject": r["subject"]} for r in rows]
    return count, sample


@router.post("/settings/alert-groups")
async def create_alert_group(
    request: Request, _auth: str = Depends(_FORM),
) -> RedirectResponse:
    values, err = _parse_form(await request.form())
    if err:
        return _redirect_err(err)
    assert values is not None  # err is None here, so _parse_form returned values

    db = _db_path(request)
    try:
        create_alert_group_service(
            db,
            name=values["name"],
            recipients=values["recipients"],
            match_tags=values["match_tags"],
            webhook_url=values["webhook_url"],
            threshold_days=values["threshold_days"],
            digest_cadence_days=values["digest_cadence_days"],
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except AlertGroupConflictError as exc:
        return _redirect_err(str(exc))
    return _redirect_ok()


@router.post("/settings/alert-groups/{group_id}")
async def update_alert_group(
    group_id: IdParam, request: Request, _auth: str = Depends(_FORM),
) -> RedirectResponse:
    db = _db_path(request)
    form = await request.form()
    values, err = _parse_form(form)
    if err:
        return _redirect_err(err)
    assert values is not None  # err is None here, so _parse_form returned values

    try:
        update_alert_group_service(
            db,
            group_id, name=values["name"], recipients=values["recipients"],
            match_tags=values["match_tags"],
            # The UI no longer offers this inert control. Preserve a legacy
            # value on omission; explicit submissions retain existing behavior.
            webhook_url=values["webhook_url"] if "webhook_url" in form else None,
            threshold_days=values["threshold_days"],
            digest_cadence_days=values["digest_cadence_days"],
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except (AlertGroupConflictError, AlertGroupNotFoundError) as exc:
        return _redirect_err(str(exc))
    return _redirect_ok()


@router.post("/settings/alert-groups/{group_id}/delete")
async def delete_alert_group(
    group_id: IdParam, request: Request, _auth: str = Depends(_FORM),
) -> RedirectResponse:
    db = _db_path(request)
    with contextlib.suppress(AlertGroupNotFoundError):
        delete_alert_group_service(
            db,
            group_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    return _redirect_ok()
