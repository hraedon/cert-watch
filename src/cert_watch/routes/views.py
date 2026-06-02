"""Dashboard, alerts, scan-history, healthz, metrics, CT lookup, CAA check routes."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __commit__, __version__, ct_lookup
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteTrustAnchorRepository,
    _total_alerts,
    _total_scan_history,
    get_posture_grades_for_certs,
    list_alerts_with_subject,
    list_dashboard_grouped_page,
    list_dashboard_page,
    list_fleet_pivot,
    list_scan_history,
)
from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.filters import register_filters
from cert_watch.middleware import (
    check_metrics_token,
    get_auth_context,
    get_csrf_context,
    rate_limit,
)

logger = logging.getLogger("cert_watch.routes.views")

router = APIRouter()

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
register_filters(templates)


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _db_path(request: Request) -> Path:
    return _get_settings(request).db_path


@router.get("/healthz")
def healthz(request: Request) -> dict:
    db = _db_path(request)
    checks: dict[str, str] = {}
    ok = True
    # DB connectivity + last scan (targeted query, no full table load)
    try:
        with _connect(db) as conn:
            conn.execute("SELECT 1")
            scan_row = conn.execute(
                "SELECT scanned_at, status FROM scan_history "
                "ORDER BY scanned_at DESC LIMIT 1"
            ).fetchone()
        checks["database"] = "ok"
        if scan_row:
            checks["last_scan"] = scan_row["scanned_at"]
            checks["last_scan_status"] = scan_row["status"]
        else:
            checks["last_scan"] = "none"
    except Exception:
        checks["database"] = "error"
        ok = False
    # Scheduler
    from cert_watch.scheduler import _scheduler_thread
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        checks["scheduler"] = "running"
    else:
        checks["scheduler"] = "not running"
    # Certificate counts
    try:
        with _connect(db) as conn:
            total_row = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE is_leaf = 1"
            ).fetchone()
            expired_row = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE is_leaf = 1 "
                "AND julianday(not_after) <= julianday('now')"
            ).fetchone()
        checks["certificates"] = str(total_row[0] if total_row else 0)
        checks["expired"] = str(expired_row[0] if expired_row else 0)
    except Exception:
        pass
    return {
        "status": "ok" if ok else "degraded",
        "version": __version__,
        "commit": __commit__,
        "checks": checks,
    }


@router.get("/api/health")
def api_health(request: Request) -> JSONResponse:
    """Structured health data for the dashboard banner."""
    db = _db_path(request)
    checks: dict[str, object] = {}

    # Scheduler
    from cert_watch.scheduler import _scheduler_thread
    checks["scheduler_running"] = (
        _scheduler_thread is not None and _scheduler_thread.is_alive()
    )

    # Last scan
    try:
        with _connect(db) as conn:
            scan_row = conn.execute(
                "SELECT scanned_at, status FROM scan_history "
                "ORDER BY scanned_at DESC LIMIT 1"
            ).fetchone()
        if scan_row:
            checks["last_scan_at"] = scan_row["scanned_at"]
            checks["last_scan_status"] = scan_row["status"]
        else:
            checks["last_scan_at"] = None
            checks["last_scan_status"] = None
    except Exception:
        checks["last_scan_at"] = None
        checks["last_scan_status"] = None

    # Failed alerts in last 24h
    try:
        cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        with _connect(db) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'failed' AND created_at > ?",
                (cutoff,),
            ).fetchone()
        checks["failed_alerts_24h"] = row[0] if row else 0
    except Exception:
        checks["failed_alerts_24h"] = 0

    # Auth status
    auth = getattr(request.app.state, "auth_provider", None)
    checks["auth_provider"] = auth.provider_name if auth else "none"
    checks["break_glass_enabled"] = (
        hasattr(auth, "local_admin_user") and bool(auth.local_admin_user)
    ) if auth else False

    # Overall color
    overall = "ok"
    if not checks["scheduler_running"]:
        overall = "critical"
    elif checks["failed_alerts_24h"] > 0 or checks.get("last_scan_status") == "failure":
        overall = "warning"

    checks["overall"] = overall
    return JSONResponse(content=checks)


@router.get("/", response_class=HTMLResponse)
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

    # Pivot views use SQL-level aggregation (BC-048)
    pivot_groups = None
    pivot_stats = None
    if view in ("issuer", "owner", "renewal_method"):
        pivot_groups = list_fleet_pivot(db, view)

    per_page = 25
    if pivot_groups:
        # Pivot view: compute stats from SQL (no full inventory load)
        total = sum(g["count"] for g in pivot_groups)
        page_entries = []
        total_pages = 1
        # Urgency distribution via targeted SQL
        with _connect(db) as conn:
            rows = conn.execute(
                """SELECT
                    SUM(CASE WHEN c.not_after < datetime('now') THEN 1 ELSE 0 END) AS expired,
                    SUM(CASE WHEN c.not_after >= datetime('now')
                             AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) < 7
                        THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN c.not_after >= datetime('now')
                             AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) >= 7
                             AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) < 30
                        THEN 1 ELSE 0 END) AS warning,
                    SUM(CASE WHEN c.not_after >= datetime('now')
                             AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) >= 30
                        THEN 1 ELSE 0 END) AS healthy
                FROM certificates c
                WHERE c.is_leaf = 1
                """
            ).fetchone()
        r = dict(rows)
        # Add pending hosts count (no cert = gray, not counted in urgency buckets)
        pivot_stats = {
            "expired": r.get("expired") or 0,
            "critical": r.get("critical") or 0,
            "warning": r.get("warning") or 0,
            "healthy": r.get("healthy") or 0,
        }
    elif grouped:
        # Grouped path: grouping by leaf fingerprint with worst urgency +
        # host count, filtered/sorted — SQL-level pagination (BC-073).
        page_entries, total = list_dashboard_grouped_page(
            db, q=q, urgency=urgency, source=source,
            sort_by=sort_by, sort_order=sort_order,
            page=page, per_page=per_page,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))
    else:
        # Fast path: no grouping, no pivot — SQL-level pagination (BC-073).
        page_entries, total = list_dashboard_page(
            db, q=q, urgency=urgency, source=source,
            sort_by=sort_by, sort_order=sort_order,
            page=page, per_page=per_page,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))

    anchors = SqliteTrustAnchorRepository(db).list_entries()
    csrf_ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)

    display_entries = [] if pivot_groups else page_entries
    cert_ids = [e["id"] for e in display_entries if e.get("id")]
    posture_grades = get_posture_grades_for_certs(db, cert_ids) if cert_ids else {}

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "entries": display_entries,
            "all_entries": page_entries,
            "pivot_groups": pivot_groups,
            "pivot_stats": pivot_stats,
            "pivot_view": view if pivot_groups else "",
            "trust_anchors": anchors,
            "version": __version__, "commit": __commit__,
            "error": error,
            "warning": warning,
            **auth_ctx,
            "active_page": "dashboard",
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


@router.get("/alerts", response_class=HTMLResponse)
def alerts_view(request: Request, page: int = 1) -> HTMLResponse:
    db = _db_path(request)
    per_page = 50
    total = _total_alerts(db)
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))
    rows = list_alerts_with_subject(db, page=page, limit=per_page)
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "alerts": rows,
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            "active_page": "alerts",
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )


@router.get("/scan-history", response_class=HTMLResponse)
def scan_history_view(request: Request, page: int = 1) -> HTMLResponse:
    db = _db_path(request)
    per_page = 50
    total = _total_scan_history(db)
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))
    rows = list_scan_history(db, page=page, limit=per_page)
    return templates.TemplateResponse(
        request=request,
        name="scan_history.html",
        context={
            "history": rows,
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "scans",
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )


@router.get("/ct-lookup/{domain}", dependencies=[Depends(rate_limit("ct", 10, 60))])
def ct_lookup_view(request: Request, domain: str) -> dict:
    result = ct_lookup.query_ct_log(domain)
    if isinstance(result, str):
        return {"error": result}
    return {
        "domain": domain,
        "count": len(result),
        "entries": [
            {
                "common_name": e.common_name,
                "issuer_name": e.issuer_name,
                "name_value": e.name_value,
                "not_before": e.not_before.isoformat(),
                "not_after": e.not_after.isoformat(),
                "serial_number": e.serial_number,
            }
            for e in result
        ],
    }


@router.get("/caa-check/{domain}", dependencies=[Depends(rate_limit("caa", 10, 60))])
def caa_check_view(request: Request, domain: str) -> dict:
    """FEAT-010: Return CAA records and issuance policy for a domain."""
    import re as _re

    _DOMAIN_RE = _re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
        r"\.[a-zA-Z]{2,}$",
    )
    if not domain or len(domain) > 253 or not _DOMAIN_RE.match(domain):
        return {"domain": domain, "error": "invalid domain"}
    from cert_watch.caa_check import check_caa

    result = check_caa(domain)
    if result.error:
        return {"domain": domain, "error": result.error}
    return {
        "domain": domain,
        "records": result.records,
        "issue_allowed": result.issue_allowed,
        "issuewild_allowed": result.issuewild_allowed,
    }


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request) -> str:
    if not check_metrics_token(request):
        return PlainTextResponse("unauthorized", status_code=401)
    db = _db_path(request)
    lines: list[str] = []
    with _connect(db) as conn:
        lines.append("# HELP cert_watch_cert_expiry_days Days until certificate expiry")
        lines.append("# TYPE cert_watch_cert_expiry_days gauge")
        cert_rows = conn.execute(
            "SELECT hostname, port, subject, not_after FROM certificates WHERE is_leaf = 1"
        ).fetchall()
        for r in cert_rows:
            host_label = (
                f'{r["hostname"]}:{r["port"]}' if r["hostname"] else "(uploaded)"
            ).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            subject_label = (
                r["subject"]
                .replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            )
            not_after = _parse_iso(r["not_after"])
            days = (not_after - datetime.now(UTC)).days
            lines.append(
                f'cert_watch_cert_expiry_days{{host="{host_label}",'
                f'subject="{subject_label}"}} {days}'
            )
        total_certs = len(cert_rows)
        expired = sum(
            1 for r in cert_rows
            if (_parse_iso(r["not_after"]) - datetime.now(UTC)).days < 0
        )
        hosts_row = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()
        total_hosts = hosts_row[0] if hosts_row else 0
    lines.append("# HELP cert_watch_hosts_tracked Number of tracked hosts")
    lines.append("# TYPE cert_watch_hosts_tracked gauge")
    lines.append(f"cert_watch_hosts_tracked {total_hosts}")
    lines.append("# HELP cert_watch_certificates_tracked Number of certificate groups")
    lines.append("# TYPE cert_watch_certificates_tracked gauge")
    lines.append(f"cert_watch_certificates_tracked {total_certs}")
    lines.append("# HELP cert_watch_certificates_expired Number of expired certificates")
    lines.append("# TYPE cert_watch_certificates_expired gauge")
    lines.append(f"cert_watch_certificates_expired {expired}")
    return "\n".join(lines) + "\n"
