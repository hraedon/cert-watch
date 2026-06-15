"""Dashboard, alerts, scan-history, healthz, metrics, CAA check routes."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from prometheus_client import CollectorRegistry, Gauge, generate_latest

from cert_watch import __commit__, __version__
from cert_watch.database import (
    SqliteTrustAnchorRepository,
    _count_alerts_by_filter,
    distinct_tags,
    get_posture_grades_for_certs,
    list_alerts_with_subject,
    list_dashboard_grouped_page,
    list_dashboard_page,
    list_fleet_pivot,
    list_scan_batches,
)
from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.middleware import (
    check_metrics_token,
    get_auth_context,
    get_csrf_context,
    rate_limit,
    require_auth,
    require_write,
    require_write_form,
)
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, get_templates
from cert_watch.routes._scoped import scope_tags_from_auth

logger = logging.getLogger("cert_watch.routes.views")

router = APIRouter()

templates = get_templates()


@router.get("/healthz")
def healthz(request: Request) -> dict:
    """Lightweight liveness probe — process is alive.

    Build metadata (version/commit) is intentionally omitted from the public
    liveness body to avoid unnecessary disclosure (BC-029 H).
    """
    return {"status": "ok"}


@router.get("/readyz")
def readyz(request: Request):
    """Readiness probe — DB reachable, writable, and scheduler healthy."""
    db = _db_path(request)
    checks: dict[str, str] = {}
    ok = True
    # DB connectivity + last scan (targeted query, no full table load)
    db_reachable = False
    try:
        with _connect(db) as conn:
            conn.execute("SELECT 1")
            scan_row = conn.execute(
                "SELECT scanned_at, status FROM scan_history "
                "ORDER BY scanned_at DESC LIMIT 1"
            ).fetchone()
        checks["database"] = "ok"
        db_reachable = True
        if scan_row:
            checks["last_scan"] = scan_row["scanned_at"]
            checks["last_scan_status"] = scan_row["status"]
        else:
            checks["last_scan"] = "none"
    except Exception:
        checks["database"] = "error"
        ok = False
    # DB write capability (only if the DB is reachable)
    if db_reachable:
        try:
            with _connect(db) as conn:
                conn.execute(
                    "UPDATE kv_store SET value = ? WHERE key = '_heartbeat'",
                    (datetime.now(UTC).isoformat(),),
                )
                if conn.execute("SELECT changes()").fetchone()[0] == 0:
                    conn.execute(
                        "INSERT OR IGNORE INTO kv_store (key, value) VALUES ('_heartbeat', ?)",
                        (datetime.now(UTC).isoformat(),),
                    )
                conn.commit()
            checks["db_write"] = "ok"
        except Exception:
            return JSONResponse(
                {"status": "error", "reason": "database not writable"},
                status_code=503,
            )
    # Scheduler
    from cert_watch.scheduler import _scheduler_thread
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        checks["scheduler"] = "running"
    else:
        checks["scheduler"] = "not running"
        ok = False
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
        logger.warning("readyz cert count query failed", exc_info=True)
    return {
        "status": "ok" if ok else "degraded",
        "version": __version__,
        "commit": __commit__,
        "checks": checks,
    }


@router.get("/api/health", dependencies=[Depends(require_auth)])
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
        getattr(auth, "is_break_glass_enabled", False)
    ) if auth else False

    # Overall color
    overall = "ok"
    if not checks["scheduler_running"]:
        overall = "critical"
    elif (
        (checks["failed_alerts_24h"] if isinstance(checks["failed_alerts_24h"], int) else 0) > 0
    ) or checks.get("last_scan_status") == "failure":
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

    # Tag-scoped access control: scoped users see only objects whose effective
    # tags include one of their scope tags. Admins with an empty scope see all.
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = scope_tags_from_auth(auth_ctx)

    # Pivot views use SQL-level aggregation (BC-048)
    pivot_groups = None
    pivot_stats = None
    if view in ("issuer", "owner", "renewal_method"):
        pivot_groups = list_fleet_pivot(db, view, scope_tags=scope_tags)

    per_page = 25
    if pivot_groups:
        # Pivot view: compute stats from SQL (no full inventory load)
        total = sum(g["count"] for g in pivot_groups)
        page_entries: list[dict] = []
        total_pages = 1
        # Urgency distribution via targeted SQL
        with _connect(db) as conn:
            row = conn.execute(
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
        r = dict(row)
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
            scope_tags=scope_tags,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))
    else:
        # Fast path: no grouping, no pivot — SQL-level pagination (BC-073).
        page_entries, total = list_dashboard_page(
            db, q=q, urgency=urgency, source=source,
            sort_by=sort_by, sort_order=sort_order,
            page=page, per_page=per_page,
            scope_tags=scope_tags,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))

    anchors = SqliteTrustAnchorRepository(db).list_entries()
    csrf_ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)

    display_entries = [] if pivot_groups else page_entries
    cert_ids = [e["id"] for e in display_entries if e.get("id")]
    posture_grades = get_posture_grades_for_certs(db, cert_ids) if cert_ids else {}

    # Fleet posture grade (worst-weighted across scanned certs)
    fleet_grade = None
    with _connect(db) as conn:
        grade_rows = conn.execute(
            "SELECT grade, COUNT(*) as cnt FROM scan_posture GROUP BY grade"
        ).fetchall()
    if grade_rows:
        from cert_watch.posture import GRADE_WORST_ORDER

        grade_order = GRADE_WORST_ORDER
        counts = {}
        worst = 0
        for r in grade_rows:
            g = r["grade"]
            counts[g] = r["cnt"]
            worst = max(worst, grade_order.get(g, 0))
        has_f = counts.get("F", 0)
        has_c = counts.get("C", 0)
        has_b = counts.get("B", 0)
        fleet_g = "C" if has_f else ("B" if has_c or has_b else "A")
        fleet_grade = {"grade": fleet_g, "counts": counts, "worst": worst}

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "entries": display_entries,
            "all_entries": page_entries,
            "all_tags": distinct_tags(db),
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
            "fleet_grade": fleet_grade,
            **csrf_ctx,
        },
    )


@router.get("/alerts", response_class=HTMLResponse)
def alerts_view(
    request: Request,
    page: int = 1,
    filter_type: str = "all",
    saved: str = "",
) -> HTMLResponse:
    db = _db_path(request)
    per_page = 50
    counts = _count_alerts_by_filter(db)
    unread_only = filter_type == "unread"
    critical_only = filter_type == "critical"
    warning_only = filter_type == "warning"
    rows = list_alerts_with_subject(
        db,
        page=page,
        limit=per_page,
        unread_only=unread_only,
        critical_only=critical_only,
        warning_only=warning_only,
    )
    total = counts.get(filter_type, counts["all"])
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))

    # Resolve alert-group routing names for each alert's cert
    from cert_watch.database import SqliteAlertGroupRepository, SqliteCertificateRepository
    from cert_watch.tags import tags_match

    group_repo = SqliteAlertGroupRepository(db)
    cert_repo = SqliteCertificateRepository(db)
    all_groups = group_repo.list_all()
    _group_cache: dict[str, str | None] = {}

    for a in rows:
        cert_id = a.get("cert_id") or ""
        if not cert_id:
            a["group_name"] = None
            continue
        if cert_id not in _group_cache:
            effective = cert_repo.effective_tags(cert_id)
            manual_ids = set(group_repo.groups_for_cert_manual(cert_id))
            matched = None
            for g in all_groups:
                if g.id in manual_ids or tags_match(effective, g.match_tags):
                    matched = g.name
                    break
            _group_cache[cert_id] = matched
        a["group_name"] = _group_cache.get(cert_id)

    # BC-130: reflect the channels that are actually configured rather than
    # hardcoding Email + Webhook chips on every alert.
    settings = getattr(request.app.state, "settings", None)
    alert_channels: list[str] = []
    if settings is not None:
        if settings.smtp_host and settings.alert_from and settings.alert_recipients:
            alert_channels.append("email")
        if settings.webhook_url:
            alert_channels.append("webhook")

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "alerts": rows,
            "alert_channels": alert_channels,
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "alerts",
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "filter_type": filter_type,
            "alert_counts": counts,
            "saved": saved,
        },
    )


@router.get("/scan-history", response_class=HTMLResponse)
def scan_history_view(request: Request, page: int = 1) -> HTMLResponse:
    db = _db_path(request)
    per_page = 20
    rows, total = list_scan_batches(db, page=page, per_page=per_page)
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))
    return templates.TemplateResponse(
        request=request,
        name="scan_history.html",
        context={
            "batches": rows,
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


@router.get(
    "/caa-check/{domain}",
    dependencies=[Depends(require_auth), Depends(rate_limit("caa", 10, 60))],
)
def caa_check_view(request: Request, domain: str) -> dict:
    """FEAT-010: Return CAA records and issuance policy for a domain."""
    from cert_watch.caa_check import _DOMAIN_RE, _MAX_DOMAIN_LEN
    if not domain or len(domain) > _MAX_DOMAIN_LEN or not _DOMAIN_RE.match(domain):
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


@router.post("/api/alerts/{alert_id}/read")
async def mark_alert_read(
    request: Request,
    alert_id: IdParam,
    _auth: str = Depends(require_write),
) -> dict:
    """Mark an alert as read."""
    db = _db_path(request)
    from cert_watch.database import _connect
    with _connect(db) as conn:
        cur = conn.execute(
            "UPDATE alerts SET read = 1 WHERE id = ?",
            (alert_id,),
        )
        conn.commit()
    return {"ok": True, "id": alert_id, "updated": cur.rowcount > 0}


@router.post("/alerts/flush")
async def flush_alert_queue(request: Request) -> RedirectResponse:
    """Flush the pending alert queue: trigger immediate send via process_pending()."""
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    from cert_watch.middleware import _extract_client_ip, check_rate_limit

    if not check_rate_limit(f"flush_alerts:{_extract_client_ip(request)}", 3, 300):
        return RedirectResponse(
            url="/alerts?error=rate+limited%3A+too+many+flush+requests",
            status_code=303,
        )
    db = _db_path(request)
    s = _get_settings(request)
    from cert_watch.alerts import process_pending
    from cert_watch.database import SqliteAlertRepository

    alert_repo = SqliteAlertRepository(db)
    alert_config = s.build_alert_config() if s.smtp_host else None
    webhook_config = s.build_webhook_config() if s.webhook_url else None
    result = process_pending(alert_repo, alert_config, webhook_config)
    from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip

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
    if failed > 0:
        return RedirectResponse(
            url=f"/alerts?warning={quote(f'Flushed {sent} alert(s), {failed} failed')}",
            status_code=303,
        )
    return RedirectResponse(
        url=f"/alerts?saved={quote(f'{sent} alert(s) sent')}",
        status_code=303,
    )


@router.post("/alerts/mark-all-read")
async def mark_all_alerts_read(request: Request) -> RedirectResponse:
    """Mark all unread alerts as read."""
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    from cert_watch.middleware import _extract_client_ip, check_rate_limit

    if not check_rate_limit(f"mark_all_read:{_extract_client_ip(request)}", 10, 300):
        return RedirectResponse(
            url="/alerts?error=rate+limited%3A+too+many+mark-all-read+requests",
            status_code=303,
        )
    db = _db_path(request)
    from cert_watch.database import _connect

    with _connect(db) as conn:
        cur = conn.execute("UPDATE alerts SET read = 1 WHERE read = 0")
        conn.commit()
    count = cur.rowcount
    from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip

    record_audit(
        db,
        actor=resolve_actor(request),
        action="alert.mark_all_read",
        target_type="alert",
        target_id="all",
        detail={"count": count},
        source_ip=resolve_source_ip(request),
    )
    plural = "alert" if count == 1 else "alerts"
    return RedirectResponse(
        url=f"/alerts?saved={quote(f'{count} {plural} marked as read')}",
        status_code=303,
    )


def _pivot_tls_monthly(rows: list[dict]) -> tuple[list[dict], int]:
    """Aggregate daily TLS version rows into monthly stacked-bar data.

    Returns (sorted_rows, max_monthly_total) so the template can scale bars.
    """
    from collections import OrderedDict

    months: OrderedDict[str, dict] = OrderedDict()
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


def _pivot_grade_monthly(rows: list[dict]) -> tuple[list[dict], int]:
    """Aggregate daily grade rows into monthly stacked-bar data.

    Returns (sorted_rows, max_monthly_total) so the template can scale bars.
    """
    from collections import OrderedDict

    months: OrderedDict[str, dict] = OrderedDict()
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
    from cert_watch.database import list_calendar, list_grade_trends, list_tls_version_trends

    calendar_data: list[dict] = []
    tls_trends: list[dict] = []
    tls_max: int = 1
    grade_trends: list[dict] = []
    grade_max: int = 1

    total_certs = 0
    try:
        with _connect(db) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE is_leaf = 1"
            ).fetchone()
            total_certs = row[0] if row else 0
    except Exception:
        logger.exception("insights: total certs query failed")
    try:
        calendar_data = list_calendar(db, bucket="week")
    except Exception:
        logger.exception("insights: calendar query failed")
    try:
        tls_trends, tls_max = _pivot_tls_monthly(list_tls_version_trends(db, days=180))
    except Exception:
        logger.exception("insights: TLS trends query failed")
    try:
        grade_trends, grade_max = _pivot_grade_monthly(list_grade_trends(db, days=180))
    except Exception:
        logger.exception("insights: grade trends query failed")

    return templates.TemplateResponse(
        request=request,
        name="insights.html",
        context={
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            "active_page": "insights",
            "tab": tab,
            "calendar_data": calendar_data,
            "total_certs": total_certs,
            "tls_trends": tls_trends,
            "tls_max": tls_max,
            "grade_trends": grade_trends,
            "grade_max": grade_max,
        },
    )


@router.get("/team", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
def team_dashboard(request: Request, page: int = 1) -> HTMLResponse:
    db = _db_path(request)
    username = request.scope.get("auth_user", "")
    per_page = 25

    from cert_watch.database.users_roles import SqliteRoleRepository, SqliteUserRepository

    has_role = False
    role_name = ""
    role_email = ""

    try:
        user_repo = SqliteUserRepository(db)
        role_repo = SqliteRoleRepository(db)
        user = user_repo.get_by_username(username) if username else None
        role = role_repo.get(user.role_id) if user and user.role_id else None
        has_role = role is not None and bool(role.email)
        role_name = role.name if role else ""
        role_email = role.email if role else ""
    except Exception:
        logger.debug("Team dashboard: user/role lookup failed", exc_info=True)
        has_role = False

    entries: list[dict] = []
    stats = {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}
    total_entries = 0
    total_pages = 1

    if has_role:
        from cert_watch.filters import compute_urgency_with_chain

        with _connect(db) as conn:
            # Total count for pagination
            total_row = conn.execute(
                """SELECT COUNT(*) FROM certificates c
                   LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port
                   WHERE c.is_leaf = 1 AND LOWER(h.owner_email) = LOWER(?)""",
                (role_email,),
            ).fetchone()
            total_entries = total_row[0] if total_row else 0
            total_pages = max((total_entries + per_page - 1) // per_page, 1)
            page = max(1, min(page, total_pages))
            offset = (page - 1) * per_page

            # Fetch paginated certs with chain info for urgency computation
            rows = conn.execute(
                """SELECT c.id, c.subject, c.issuer, c.not_after,
                          c.hostname, c.port, c.source,
                          h.owner_email,
                          (SELECT MIN(julianday(ch.not_after) - julianday('now'))
                           FROM certificates ch WHERE ch.parent_cert_id = c.id
                          ) AS min_chain_days,
                          (SELECT sp.chain_status FROM scan_posture sp
                           WHERE sp.cert_id = c.id
                           ORDER BY sp.scanned_at DESC, sp.id DESC LIMIT 1
                          ) AS chain_status
                   FROM certificates c
                   LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port
                   WHERE c.is_leaf = 1 AND LOWER(h.owner_email) = LOWER(?)
                   ORDER BY c.not_after ASC
                   LIMIT ? OFFSET ?""",
                (role_email, per_page, offset),
            ).fetchall()

            # Stats across ALL team certs (not just current page)
            stat_rows = conn.execute(
                """SELECT c.not_after,
                          (SELECT MIN(julianday(ch.not_after) - julianday('now'))
                           FROM certificates ch WHERE ch.parent_cert_id = c.id
                          ) AS min_chain_days,
                          (SELECT sp.chain_status FROM scan_posture sp
                           WHERE sp.cert_id = c.id
                           ORDER BY sp.scanned_at DESC, sp.id DESC LIMIT 1
                          ) AS chain_status
                   FROM certificates c
                   LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port
                   WHERE c.is_leaf = 1 AND LOWER(h.owner_email) = LOWER(?)""",
                (role_email,),
            ).fetchall()

        # Compute stats from all team certs
        for r in stat_rows:
            na = _parse_iso(r["not_after"])
            leaf_days = (na - datetime.now(UTC)).days
            u = compute_urgency_with_chain(leaf_days, r["min_chain_days"], r["chain_status"])
            stats[u] += 1

        # Build page entries
        from cert_watch.filters import subject_cn

        for r in rows:
            na = _parse_iso(r["not_after"])
            leaf_days = (na - datetime.now(UTC)).days
            u = compute_urgency_with_chain(leaf_days, r["min_chain_days"], r["chain_status"])
            host = f"{r['hostname']}:{r['port']}" if r["hostname"] else ""
            entries.append({
                "id": r["id"],
                "name": subject_cn(r["subject"]),
                "subject": r["subject"],
                "issuer": r["issuer"],
                "not_after": r["not_after"],
                "days_remaining": leaf_days,
                "urgency": u,
                "host": host,
                "source": r["source"],
            })

    auth_ctx = get_auth_context(request)
    csrf_ctx = get_csrf_context(request)

    return templates.TemplateResponse(
        request=request,
        name="team_dashboard.html",
        context={
            "version": __version__, "commit": __commit__,
            **auth_ctx,
            **csrf_ctx,
            "active_page": "team",
            "has_role": has_role,
            "role_name": role_name,
            "role_email": role_email,
            "entries": entries,
            "stats": stats,
            "total_entries": total_entries,
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )


def _scan_error_reason(error_message: str | None) -> str:
    """Map a scan error_message to a canonical counter reason label."""
    if not error_message:
        return "unknown"
    msg = error_message.lower()
    if "refused" in msg:
        return "connection_refused"
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "resolve" in msg or "dns" in msg:
        return "dns_failure"
    if "blocked" in msg:
        return "blocked"
    return "unknown"


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    dependencies=[Depends(rate_limit("metrics", 120, 60))],
)
def metrics(request: Request) -> PlainTextResponse:
    if not check_metrics_token(request):
        return PlainTextResponse("unauthorized", status_code=401)
    db = _db_path(request)
    registry = CollectorRegistry()

    cert_expiry_gauge = Gauge(
        "cert_watch_cert_expiry_days",
        "Days until certificate expiry",
        ["host", "subject", "fingerprint"],
        registry=registry,
    )
    hosts_gauge = Gauge(
        "cert_watch_hosts_tracked",
        "Number of tracked hosts",
        registry=registry,
    )
    certs_gauge = Gauge(
        "cert_watch_certificates_tracked",
        "Number of leaf certificate groups",
        registry=registry,
    )
    expired_gauge = Gauge(
        "cert_watch_certificates_expired",
        "Number of expired certificates",
        registry=registry,
    )
    urgency_gauge = Gauge(
        "cert_watch_certificates_by_urgency",
        "Leaf certificates grouped by expiry urgency",
        ["urgency"],
        registry=registry,
    )
    posture_gauge = Gauge(
        "cert_watch_certificates_by_posture",
        "Leaf certificates grouped by TLS posture grade",
        ["grade"],
        registry=registry,
    )
    scan_errors_gauge = Gauge(
        "cert_watch_scan_errors",
        "Recorded scan failures by host and reason (gauge, not counter — "
        "old records are purged by retention)",
        ["host", "reason"],
        registry=registry,
    )

    now = datetime.now(UTC)
    with _connect(db) as conn:
        cert_rows = conn.execute(
            "SELECT c.id, c.hostname, c.port, c.subject, c.not_after, "
            "c.fingerprint_sha256 "
            "FROM certificates c WHERE c.is_leaf = 1"
        ).fetchall()

        cert_ids = [r["id"] for r in cert_rows]
        posture_map: dict[str, str] = get_posture_grades_for_certs(db, cert_ids) if cert_ids else {}

        urgency_counts = {"healthy": 0, "warning": 0, "critical": 0, "expired": 0}
        grade_counts: dict[str, int] = {
            "a_plus": 0, "a": 0, "b": 0, "c": 0, "f": 0, "unknown": 0,
        }
        expired = 0
        for r in cert_rows:
            host_label = f'{r["hostname"]}:{r["port"]}' if r["hostname"] else "(uploaded)"
            not_after = _parse_iso(r["not_after"])
            days = (not_after - now).days
            fp_short = (r["fingerprint_sha256"] or "")[:16]
            cert_expiry_gauge.labels(
                host=host_label, subject=r["subject"], fingerprint=fp_short,
            ).set(days)
            if days < 0:
                urgency_counts["expired"] += 1
                expired += 1
            elif days < 7:
                urgency_counts["critical"] += 1
            elif days < 30:
                urgency_counts["warning"] += 1
            else:
                urgency_counts["healthy"] += 1
            grade = posture_map.get(r["id"], "unknown")
            if grade not in grade_counts:
                grade_counts[grade] = 0
            grade_counts[grade] += 1

        total_certs = len(cert_rows)
        hosts_row = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()
        total_hosts = hosts_row[0] if hosts_row else 0

        error_rows = conn.execute(
            "SELECT hostname, port, error_message, COUNT(*) as cnt "
            "FROM scan_history WHERE status = 'failure' "
            "GROUP BY hostname, port, error_message"
        ).fetchall()
        error_counts: dict[tuple[str, str], int] = {}
        for r in error_rows:
            host_label = f'{r["hostname"]}:{r["port"]}'
            reason = _scan_error_reason(r["error_message"])
            error_counts[(host_label, reason)] = (
                error_counts.get((host_label, reason), 0) + r["cnt"]
            )

    for urgency, count in urgency_counts.items():
        urgency_gauge.labels(urgency=urgency).set(count)
    for grade, count in grade_counts.items():
        posture_gauge.labels(grade=grade).set(count)
    for (host_label, reason), count in error_counts.items():
        scan_errors_gauge.labels(host=host_label, reason=reason).set(count)

    hosts_gauge.set(total_hosts)
    certs_gauge.set(total_certs)
    expired_gauge.set(expired)

    return PlainTextResponse(
        generate_latest(registry).decode("utf-8"),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/reports/compliance", response_class=HTMLResponse)
def compliance_report_view(
    request: Request,
    tag: str = "",
) -> HTMLResponse:
    from cert_watch.compliance import build_compliance_report, report_to_dict
    from cert_watch.routes.api._shared import compliance_signing_key

    db = _db_path(request)
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
            "active_page": "insights",
            "report": report_to_dict(report),
            "tag": tag,
        },
    )


@router.get("/readiness", response_class=HTMLResponse)
def readiness_report_view(request: Request) -> HTMLResponse:
    from cert_watch.readiness import build_readiness_report, readiness_report_to_dict

    db = _db_path(request)
    report = build_readiness_report(db)
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
