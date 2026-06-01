"""Dashboard, alerts, scan-history, healthz, metrics, CT lookup, CAA check routes."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __commit__, __version__, ct_lookup
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteTrustAnchorRepository,
    _total_alerts,
    _total_scan_history,
    get_posture_grades_for_certs,
    group_entries_by_fingerprint,
    list_alerts_with_subject,
    list_fleet_pivot,
    list_scan_history,
    list_unified_entries,
    list_unified_entries_page,
)
from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.filters import register_filters
from cert_watch.middleware import (
    _extract_client_ip,
    check_metrics_token,
    check_rate_limit,
    get_csrf_context,
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
        # Grouping requires the full filtered set so cross-host search within
        # a fingerprint group works (e.g. searching "beta" finds a group that
        # also contains "alpha").  BC-047 does not yet optimise this path.
        all_entries = list_unified_entries(db)
        entries = group_entries_by_fingerprint(all_entries)
        if q:
            ql = q.lower()

            def _match(e: dict) -> bool:
                fields = [e.get("name"), e.get("subject"), e.get("issuer"), e.get("host")]
                if e.get("kind") == "grouped":
                    for h in e.get("hosts", []):
                        fields.extend([h.get("host"), h.get("name")])
                return any(ql in (f or "").lower() for f in fields)

            entries = [e for e in entries if _match(e)]
        if urgency:
            entries = [e for e in entries if e.get("urgency") == urgency]
        if source:
            if source == "scanned":
                entries = [e for e in entries if e.get("kind") in ("scanned", "pending", "grouped")]
            else:
                entries = [e for e in entries if e.get("source") == source]
        _sort_keys = {
            "name": lambda e: (e.get("name") or "").lower(),
            "issue_date": lambda e: e.get("not_before") or "9999-12-31T23:59:59",
            "last_scan": lambda e: e.get("last_scanned_at") or "0000-01-01T00:00:00",
            "expiry": lambda e: e.get("not_after") or "9999-12-31T23:59:59",
            "days": lambda e: (
                e["days_remaining"] if e.get("days_remaining") is not None else 9999
            ),
        }
        key_fn = _sort_keys.get(sort_by, _sort_keys["days"])
        reverse = sort_order == "desc"
        entries.sort(key=key_fn, reverse=reverse)
        total = len(entries)
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))
        start = (page - 1) * per_page
        page_entries = entries[start : start + per_page]
    else:
        # Fast path: no grouping, no pivot — paginate at the raw level.
        offset = (page - 1) * per_page
        page_entries, total = list_unified_entries_page(
            db,
            offset=offset,
            limit=per_page,
            q=q,
            urgency=urgency,
            source=source,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))

    anchors = SqliteTrustAnchorRepository(db).list_entries()
    ctx = get_csrf_context(request)
    auth_user = request.scope.get("auth_user", "")

    display_entries = [] if pivot_groups else page_entries
    cert_ids = [e["id"] for e in display_entries if e.get("id")]
    posture_grades = get_posture_grades_for_certs(db, cert_ids) if cert_ids else {}

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "entries": display_entries,
            "all_entries": page_entries if pivot_groups else page_entries,
            "pivot_groups": pivot_groups,
            "pivot_stats": pivot_stats,
            "pivot_view": view if pivot_groups else "",
            "trust_anchors": anchors,
            "version": __version__, "commit": __commit__,
            "error": error,
            "warning": warning,
            "auth_user": auth_user,
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
            **ctx,
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
    auth_user = request.scope.get("auth_user", "")
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "alerts": rows,
            "version": __version__, "commit": __commit__,
            "auth_user": auth_user,
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
    auth_user = request.scope.get("auth_user", "")
    return templates.TemplateResponse(
        request=request,
        name="scan_history.html",
        context={
            "history": rows,
            "version": __version__, "commit": __commit__,
            "auth_user": auth_user,
            "active_page": "scans",
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )


@router.get("/ct-lookup/{domain}")
def ct_lookup_view(request: Request, domain: str) -> dict:
    if not check_rate_limit(f"ct:{_extract_client_ip(request)}", 10, 60):
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "rate limited"}, status_code=429)
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


@router.get("/caa-check/{domain}")
def caa_check_view(request: Request, domain: str) -> dict:
    """FEAT-010: Return CAA records and issuance policy for a domain."""
    if not check_rate_limit(f"caa:{_extract_client_ip(request)}", 10, 60):
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "rate limited"}, status_code=429)
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
