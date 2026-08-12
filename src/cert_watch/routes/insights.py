"""Insights, compliance, readiness, and crypto posture view routes."""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.compliance import build_compliance_report, report_to_dict
from cert_watch.crypto_posture import analyze_fleet_crypto, crypto_posture_to_dict
from cert_watch.database import (
    _connect,
    list_grade_trends,
    list_tls_version_trends,
)
from cert_watch.middleware import get_auth_context, get_csrf_context
from cert_watch.posture import GRADE_WORST_ORDER
from cert_watch.readiness import build_readiness_report, readiness_report_to_dict
from cert_watch.routes._deps import _db_path, get_templates
from cert_watch.routes._scoped import enforce_scope_tag, scope_tags_from_auth
from cert_watch.routes.api._shared import compliance_signing_key

logger = logging.getLogger("cert_watch.routes.insights")

router = APIRouter()

templates = get_templates()


def _pivot_tls_monthly(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Aggregate daily TLS version rows into monthly stacked-bar data.

    Returns (sorted_rows, max_monthly_total) so the template can scale bars.
    """
    months: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for r in rows:
        if not r.get("date"):
            continue
        month = r["date"][:7]
        if month not in months:
            months[month] = {"month": month, "tls_1_3": 0, "tls_1_2": 0, "tls_1_0": 0}
        v = (r.get("protocol_version") or "").strip()
        count = r.get("count", 0)
        if v == "TLSv1.3":
            months[month]["tls_1_3"] += count
        elif v == "TLSv1.2":
            months[month]["tls_1_2"] += count
        else:
            months[month]["tls_1_0"] += count
    result = sorted(months.values(), key=lambda m: m["month"])
    max_total = max(
        (m["tls_1_3"] + m["tls_1_2"] + m["tls_1_0"] for m in result), default=1
    )
    return result, max(max_total, 1)


def _pivot_grade_monthly(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Aggregate daily grade rows into monthly stacked-bar data.

    Returns (sorted_rows, max_monthly_total) so the template can scale bars.
    """
    months: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for r in rows:
        if not r.get("date"):
            continue
        month = r["date"][:7]
        if month not in months:
            months[month] = {"month": month, "grade_a": 0, "grade_b": 0, "grade_c": 0}
        grade = (r.get("posture_grade") or "").strip().upper()
        count = r.get("count", 0)
        if grade in ("A+", "A"):
            months[month]["grade_a"] += count
        elif grade == "B":
            months[month]["grade_b"] += count
        else:
            # C and worse share a series: they mean the same operator action
            # ("fix this"), and the crit/expired hues fail CVD separation when
            # stacked adjacently (see plan 055 chart notes).
            months[month]["grade_c"] += count
    result = sorted(months.values(), key=lambda m: m["month"])
    max_total = max(
        (m["grade_a"] + m["grade_b"] + m["grade_c"] for m in result), default=1
    )
    return result, max(max_total, 1)


@router.get("/posture", response_class=HTMLResponse)
def posture_view(request: Request) -> HTMLResponse:
    """Fleet posture: grade distribution + trends + crypto inventory.

    Absorbs the old /insights?tab=trends and /crypto pages; the compliance
    and SC-081 readiness reports are generated outputs linked from here.
    """
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))

    posture = crypto_posture_to_dict(analyze_fleet_crypto(db))

    tls_trends: list[dict[str, Any]] = []
    tls_max: int = 1
    grade_trends: list[dict[str, Any]] = []
    grade_max: int = 1
    try:
        tls_trends, tls_max = _pivot_tls_monthly(
            list_tls_version_trends(db, days=180, scope_tags=scope_tags)
        )
    except Exception:
        logger.exception("posture: TLS trends query failed")
    try:
        grade_trends, grade_max = _pivot_grade_monthly(
            list_grade_trends(db, days=180, scope_tags=scope_tags)
        )
    except Exception:
        logger.exception("posture: grade trends query failed")

    # Fleet posture grade (worst-weighted across scanned certs) + distribution
    fleet_grade = None
    with _connect(db) as conn:
        grade_rows = conn.execute(
            "SELECT grade, COUNT(*) as cnt FROM scan_posture GROUP BY grade"
        ).fetchall()
    if grade_rows:
        counts: dict[str, int] = {}
        worst = 0
        for r in grade_rows:
            counts[r["grade"]] = r["cnt"]
            worst = max(worst, GRADE_WORST_ORDER.get(r["grade"], 0))
        _by_ordinal = {v: k for k, v in GRADE_WORST_ORDER.items()}
        fleet_grade = {
            "grade": _by_ordinal.get(worst, "F"),
            "counts": counts,
            "total": sum(counts.values()),
        }

    return templates.TemplateResponse(
        request=request,
        name="posture.html",
        context={
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "posture",
            "posture": posture,
            "fleet_grade": fleet_grade,
            "tls_trends": tls_trends,
            "tls_max": tls_max,
            "grade_trends": grade_trends,
            "grade_max": grade_max,
        },
    )


@router.get("/insights")
def insights_redirect(request: Request, tab: str = "calendar") -> RedirectResponse:
    """The Insights page dissolved: trends live on /posture, the expiry
    calendar is a view of the certificate inventory."""
    if tab == "trends":
        return RedirectResponse(url="/posture", status_code=301)
    return RedirectResponse(url="/?view=calendar", status_code=301)


@router.get("/crypto")
def crypto_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(url="/posture", status_code=301)


@router.get("/reports/compliance", response_class=HTMLResponse)
def compliance_report_view(
    request: Request,
    tag: str = "",
) -> HTMLResponse:
    db = _db_path(request)
    denied = enforce_scope_tag(request, tag)
    if denied:
        return HTMLResponse(content=denied, status_code=403)
    signing_key = compliance_signing_key(request)
    report = build_compliance_report(
        db,
        scope_tag=tag,
        version=__version__,
        commit=__commit__,
        signing_key=signing_key,
    )
    return templates.TemplateResponse(
        request=request,
        name="compliance.html",
        context={
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "posture",
            "report": report_to_dict(report),
            "tag": tag,
        },
    )


@router.get("/readiness", response_class=HTMLResponse)
def readiness_report_view(request: Request) -> HTMLResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    report = build_readiness_report(db, scope_tags=scope_tags)
    return templates.TemplateResponse(
        request=request,
        name="readiness.html",
        context={
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "posture",
            "report": readiness_report_to_dict(report),
        },
    )
