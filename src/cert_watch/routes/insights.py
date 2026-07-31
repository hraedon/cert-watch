"""Insights, compliance, readiness, and crypto posture view routes."""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from cert_watch import __commit__, __version__
from cert_watch.compliance import build_compliance_report, report_to_dict
from cert_watch.crypto_posture import analyze_fleet_crypto, crypto_posture_to_dict
from cert_watch.database import (
    count_leaf_certs,
    list_calendar,
    list_grade_trends,
    list_tls_version_trends,
)
from cert_watch.middleware import get_auth_context, get_csrf_context
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
            months[month] = {"month": month, "grade_a": 0, "grade_b": 0, "grade_c": 0, "grade_f": 0}
        grade = (r.get("posture_grade") or "").strip().upper()
        count = r.get("count", 0)
        if grade in ("A+", "A"):
            months[month]["grade_a"] += count
        elif grade == "B":
            months[month]["grade_b"] += count
        elif grade == "C":
            months[month]["grade_c"] += count
        else:
            months[month]["grade_f"] += count
    result = sorted(months.values(), key=lambda m: m["month"])
    max_total = max(
        (m["grade_a"] + m["grade_b"] + m["grade_c"] + m["grade_f"] for m in result), default=1
    )
    return result, max(max_total, 1)


@router.get("/insights", response_class=HTMLResponse)
def insights_view(
    request: Request,
    tab: str = "calendar",
) -> HTMLResponse:
    db = _db_path(request)

    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))

    calendar_data: list[dict[str, Any]] = []
    tls_trends: list[dict[str, Any]] = []
    tls_max: int = 1
    grade_trends: list[dict[str, Any]] = []
    grade_max: int = 1

    total_certs = 0
    try:
        total_certs = count_leaf_certs(db, scope_tags=scope_tags)
    except Exception:
        logger.exception("insights: total certs query failed")
    try:
        calendar_data = list_calendar(db, bucket="week", scope_tags=scope_tags)
    except Exception:
        logger.exception("insights: calendar query failed")

    _now = datetime.now(UTC)
    _week_start = _now - timedelta(days=_now.weekday())
    current_week_start = _week_start.strftime("%Y-%m-%d")
    next_week_start = (_week_start + timedelta(days=7)).strftime("%Y-%m-%d")
    four_weeks_ahead = (_week_start + timedelta(days=21)).strftime("%Y-%m-%d")
    for b in calendar_data:
        bs = b.get("bucket_start", "")
        if bs <= current_week_start:
            b["tone"] = "tone-crit"
        elif bs <= next_week_start:
            b["tone"] = "tone-warn"
        else:
            b["tone"] = ""
    expiring_soon_count = sum(
        b.get("count", 0) for b in calendar_data
        if b.get("bucket_start", "") >= current_week_start
        and b.get("bucket_start", "") <= four_weeks_ahead
    )
    try:
        tls_trends, tls_max = _pivot_tls_monthly(
            list_tls_version_trends(db, days=180, scope_tags=scope_tags)
        )
    except Exception:
        logger.exception("insights: TLS trends query failed")
    try:
        grade_trends, grade_max = _pivot_grade_monthly(
            list_grade_trends(db, days=180, scope_tags=scope_tags)
        )
    except Exception:
        logger.exception("insights: grade trends query failed")

    return templates.TemplateResponse(
        request=request,
        name="insights.html",
        context={
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "insights",
            "tab": tab,
            "calendar_data": calendar_data,
            "current_week_start": current_week_start,
            "expiring_soon_count": expiring_soon_count,
            "total_certs": total_certs,
            "tls_trends": tls_trends,
            "tls_max": tls_max,
            "grade_trends": grade_trends,
            "grade_max": grade_max,
        },
    )


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
            "active_page": "insights",
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
            "active_page": "insights",
            "report": readiness_report_to_dict(report),
        },
    )


@router.get("/crypto", response_class=HTMLResponse)
def crypto_posture_view(request: Request) -> HTMLResponse:
    """Fleet crypto inventory & agility lens (informational, non-grade-affecting)."""
    db = _db_path(request)
    posture = crypto_posture_to_dict(analyze_fleet_crypto(db))
    return templates.TemplateResponse(
        request=request,
        name="crypto.html",
        context={
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "insights",
            "posture": posture,
        },
    )
