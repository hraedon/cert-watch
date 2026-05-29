"""Dashboard, alerts, scan-history, healthz, metrics, CT lookup, CAA check routes."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __version__, ct_lookup
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteHostRepository,
    SqliteTrustAnchorRepository,
    group_entries_by_fingerprint,
    list_alerts_with_subject,
    list_dashboard_rows,
    list_scan_history,
    list_unified_entries,
)
from cert_watch.filters import register_filters
from cert_watch.middleware import check_rate_limit, get_csrf_context

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
    # DB connectivity
    try:
        import sqlite3
        with sqlite3.connect(str(db), timeout=5) as conn:
            conn.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"
        ok = False
    # Last scan
    try:
        rows = list_scan_history(db)
        if rows:
            checks["last_scan"] = rows[0].get("scanned_at", "unknown")
            checks["last_scan_status"] = rows[0].get("status", "unknown")
        else:
            checks["last_scan"] = "none"
    except Exception:
        checks["last_scan"] = "unavailable"
    # Scheduler
    from cert_watch.scheduler import _scheduler_thread
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        checks["scheduler"] = "running"
    else:
        checks["scheduler"] = "not running"
    # Certificate counts
    try:
        dash_rows = list_dashboard_rows(db)
        checks["certificates"] = str(len(dash_rows))
        expired = sum(1 for r in dash_rows if r.get("days_remaining", 0) < 0)
        checks["expired"] = str(expired)
    except Exception:
        pass
    return {"status": "ok" if ok else "degraded", "version": __version__, "checks": checks}


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
) -> HTMLResponse:
    db = _db_path(request)
    entries = list_unified_entries(db)

    if grouped:
        entries = group_entries_by_fingerprint(entries)

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
        entries = [e for e in entries if e["urgency"] == urgency]
    if source:
        if source == "scanned":
            entries = [
                e for e in entries if e["kind"] in ("scanned", "pending", "grouped")
            ]
        else:
            entries = [e for e in entries if e["source"] == source]

    anchors = SqliteTrustAnchorRepository(db).list_entries()
    ctx = get_csrf_context(request)
    auth_user = request.scope.get("auth_user", "")

    _sort_keys = {
        "name": lambda e: (e.get("name") or "").lower(),
        "issue_date": lambda e: e.get("not_before") or "9999-12-31T23:59:59",
        "last_scan": lambda e: e.get("last_scanned_at") or "0000-01-01T00:00:00",
        "expiry": lambda e: e.get("not_after") or "9999-12-31T23:59:59",
        "days": lambda e: (
            e["days_remaining"] if e["days_remaining"] is not None else 9999
        ),
    }
    key_fn = _sort_keys.get(sort_by, _sort_keys["days"])
    reverse = sort_order == "desc"
    entries.sort(key=key_fn, reverse=reverse)

    per_page = 25
    total = len(entries)
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    page_entries = entries[start : start + per_page]

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "entries": page_entries,
            "trust_anchors": anchors,
            "version": __version__,
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
            **ctx,
        },
    )


@router.get("/alerts", response_class=HTMLResponse)
def alerts_view(request: Request) -> HTMLResponse:
    db = _db_path(request)
    rows = list_alerts_with_subject(db)
    auth_user = request.scope.get("auth_user", "")
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "alerts": rows,
            "version": __version__,
            "auth_user": auth_user,
            "active_page": "alerts",
        },
    )


@router.get("/scan-history", response_class=HTMLResponse)
def scan_history_view(request: Request) -> HTMLResponse:
    db = _db_path(request)
    rows = list_scan_history(db)
    auth_user = request.scope.get("auth_user", "")
    return templates.TemplateResponse(
        request=request,
        name="scan_history.html",
        context={
            "history": rows,
            "version": __version__,
            "auth_user": auth_user,
            "active_page": "scans",
        },
    )


@router.get("/ct-lookup/{domain}")
def ct_lookup_view(request: Request, domain: str) -> dict:
    if not check_rate_limit(f"ct:{request.client.host}", 10, 60):
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
    if not check_rate_limit(f"caa:{request.client.host}", 10, 60):
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
    db = _db_path(request)
    rows = list_dashboard_rows(db)
    hosts = SqliteHostRepository(db).list_all()
    lines: list[str] = []
    lines.append("# HELP cert_watch_cert_expiry_days Days until certificate expiry")
    lines.append("# TYPE cert_watch_cert_expiry_days gauge")
    for r in rows:
        host_label = r["host"].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        subject_label = r["subject"].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lines.append(
            f'cert_watch_cert_expiry_days{{host="{host_label}",'
            f'subject="{subject_label}"}} {r["days_remaining"]}'
        )
    lines.append("# HELP cert_watch_hosts_tracked Number of tracked hosts")
    lines.append("# TYPE cert_watch_hosts_tracked gauge")
    lines.append(f"cert_watch_hosts_tracked {len(hosts)}")
    lines.append("# HELP cert_watch_certificates_tracked Number of certificate groups")
    lines.append("# TYPE cert_watch_certificates_tracked gauge")
    lines.append(f"cert_watch_certificates_tracked {len(rows)}")
    expired = sum(1 for r in rows if r["days_remaining"] < 0)
    lines.append("# HELP cert_watch_certificates_expired Number of expired certificates")
    lines.append("# TYPE cert_watch_certificates_expired gauge")
    lines.append(f"cert_watch_certificates_expired {expired}")
    return "\n".join(lines) + "\n"
