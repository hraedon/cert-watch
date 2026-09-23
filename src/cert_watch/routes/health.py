"""Health, readiness, and favicon routes."""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.alerting.model import UNDELIVERED_AFTER_HOURS, delivery_is_configured
from cert_watch.auth import SESSION_COOKIE, validate_session
from cert_watch.auth.request_context import _is_auth_enabled, authenticate_api_key
from cert_watch.database.connection import _connect
from cert_watch.routes._deps import _db_path, _get_settings
from cert_watch.security import _request_security

logger = logging.getLogger("cert_watch.routes.health")

router = APIRouter()


def _is_sqlite_busy(exc: sqlite3.OperationalError) -> bool:
    """Return whether a write failed only because another transaction owns the DB."""
    code = getattr(exc, "sqlite_errorcode", None)
    if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return True
    message = str(exc).lower()
    return "database is locked" in message or "database table is locked" in message


def _alert_delivery_counts(db: str | Path, *, now: datetime) -> tuple[int, int]:
    """Return overdue pending rows and abandoned sending leases separately."""
    cutoff = (now - timedelta(hours=UNDELIVERED_AFTER_HOURS)).isoformat()
    with _connect(db) as conn:
        row = conn.execute(
            """SELECT
                   SUM(CASE WHEN status = 'pending' AND created_at <= ?
                            THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status = 'sending' AND
                                      (lease_expires_at IS NULL OR lease_expires_at <= ?)
                            THEN 1 ELSE 0 END)
               FROM alerts""",
            (cutoff, now.isoformat()),
        ).fetchone()
    return (int(row[0] or 0), int(row[1] or 0)) if row else (0, 0)


def _undelivered_count(db: str | Path, *, now: datetime) -> int:
    """Count overdue pending rows and abandoned sending leases."""
    overdue, stale_leases = _alert_delivery_counts(db, now=now)
    return overdue + stale_leases


@router.get("/healthz")
def healthz(request: Request) -> dict[str, str]:
    """Lightweight liveness probe — process is alive.

    Build metadata (version/commit) is intentionally omitted from the public
    liveness body to avoid unnecessary disclosure (BC-029 H).
    """
    return {"status": "ok"}


@router.get("/readyz")
def readyz(request: Request) -> JSONResponse:
    """Readiness probe — DB reachable, writable, and scheduler healthy.

    Probe contract: HTTP 200 when ready, **503 when degraded** — the status
    code is what kubelet/blackbox probes judge (a 200-with-`degraded` body
    reads as Ready to a kubelet). When an auth provider is configured,
    unauthenticated callers get a shallow body (status only); the detailed
    checks stay behind session/API-key auth (disclosure hygiene, same class
    as WI-124 #5).
    """
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
    except Exception:  # noqa: BLE001 — readiness must report arbitrary DB initialization failures
        checks["database"] = "error"
        ok = False
    # DB write capability (only if the DB is reachable) — best-effort: a
    # SQLITE_BUSY during a scan should not fail the readiness check when the
    # DB is reachable for reads (L8).
    if db_reachable:
        try:
            with _connect(db) as conn:
                conn.execute("PRAGMA busy_timeout = 1000")
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
        except sqlite3.OperationalError as exc:
            if _is_sqlite_busy(exc):
                logger.debug("readyz heartbeat write failed (DB busy), continuing")
                checks["db_write"] = "ok"
            else:
                logger.warning("readyz heartbeat write failed", exc_info=True)
                checks["db_write"] = "error"
                ok = False
    # Scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is not None and scheduler.is_running:
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
        checks["certificates"] = "error"
        checks["expired"] = "error"
        ok = False
    if db_reachable:
        try:
            overdue, stale_leases = _alert_delivery_counts(
                db, now=datetime.now(UTC)
            )
            checks["undelivered_alerts"] = str(overdue)
            checks["stale_sending_leases"] = str(stale_leases)
        except Exception:
            logger.warning("readyz alert lifecycle query failed", exc_info=True)
            checks["undelivered_alerts"] = "error"
            checks["stale_sending_leases"] = "error"
    # Shallow body for unauthenticated callers under an auth provider; open
    # mode (no provider) and authenticated callers get the full detail.
    # /readyz is a public path, so auth_middleware never runs on it and
    # scope["auth_user"] is never set here — validate presented credentials
    # (API key, then session cookie) directly.
    full = True
    if _is_auth_enabled(request):
        authed = authenticate_api_key(request, db) is not None
        if not authed:
            _settings = getattr(request.app.state, "settings", None)
            _ttl = getattr(_settings, "session_ttl", None) if _settings else None
            authed = bool(
                validate_session(
                    request.cookies.get(SESSION_COOKIE, ""),
                    _request_security(request),
                    db_path=str(db),
                    session_ttl=_ttl,
                )
            )
        full = authed
    body: dict[str, Any] = {"status": "ok" if ok else "degraded"}
    if full:
        body["checks"] = checks
    return JSONResponse(body, status_code=200 if ok else 503)


@router.get("/favicon.ico")
def favicon() -> RedirectResponse:
    """Redirect legacy browser /favicon.ico requests to the SVG favicon."""
    return RedirectResponse(url="/static/favicon.svg", status_code=301)


def _count(checks: dict[str, object], key: str) -> int:
    """Read a counter that a failed query may have left as a non-int."""
    value = checks.get(key)
    return value if isinstance(value, int) else 0


def build_api_health_response(request: Request) -> JSONResponse:
    """Structured health data for the dashboard banner."""
    db = _db_path(request)
    checks: dict[str, object] = {}
    scan_query_ok = True
    alert_query_ok = True

    # Scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    checks["scheduler_running"] = bool(scheduler and scheduler.is_running)

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
        logger.warning("health scan history query failed", exc_info=True)
        checks["last_scan_at"] = None
        checks["last_scan_status"] = None
        scan_query_ok = False

    # Alerts that did not go out. Two disjoint populations, both operator-visible:
    #
    #   failed      — the bounded delivery attempt policy gave up.
    #   undelivered — still `pending` well past the cycle that should have sent
    #                 it, or abandoned in `sending` under an expired lease.
    #
    # The second is queried by outcome, not by cause, deliberately. A deferral
    # is correct behavior — it keeps the alert deliverable instead of burning
    # its retries on a database outage — but correct-and-silent is how an
    # expiry notice goes unsent for a week with every health surface green.
    # The counter is what makes the deferral loud. A deferral that outlives
    # EVIDENCE_DEFERRAL_GIVE_UP_HOURS on its persisted clock is marked failed
    # (#38), but only if the database will take that write; when it will not,
    # this age-based count is still the only hand raised.
    #
    # It only means anything when something was supposed to send. With no SMTP
    # and no webhook, `process_pending` returns immediately and every alert
    # stays pending for ever by design; counting those would light this banner
    # permanently on a dashboard-only install, for an outage that is not
    # happening. `alert_delivery_configured` reports which regime is in force,
    # so a zero here is legible rather than mysterious.
    delivery_configured = delivery_is_configured(_get_settings(request))
    checks["alert_delivery_configured"] = delivery_configured
    try:
        now = datetime.now(UTC)
        cutoff = (now - timedelta(hours=UNDELIVERED_AFTER_HOURS)).isoformat()
        with _connect(db) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE status = 'failed' AND last_attempt_at > ?",
                (cutoff,),
            ).fetchone()
            checks["failed_alerts_24h"] = row[0] if row else 0
            checks["undelivered_alerts"] = (
                _undelivered_count(db, now=now) if delivery_configured else 0
            )
    except Exception:
        logger.warning("health alert query failed", exc_info=True)
        checks["failed_alerts_24h"] = 0
        checks["undelivered_alerts"] = 0
        alert_query_ok = False

    # Auth status
    auth = getattr(request.app.state, "auth_provider", None)
    checks["auth_provider"] = auth.provider_name if auth else "none"
    checks["break_glass_enabled"] = (
        getattr(auth, "is_break_glass_enabled", False)
    ) if auth else False

    # Overall color
    overall = "ok"
    db_ok = True
    try:
        with _connect(db) as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception:  # noqa: BLE001 — diagnostic endpoint reports DB failure in its payload
        db_ok = False
    if not db_ok or not scan_query_ok or not alert_query_ok or not checks["scheduler_running"]:
        overall = "critical"
    elif (
        _count(checks, "failed_alerts_24h") > 0
        or _count(checks, "undelivered_alerts") > 0
        or checks.get("last_scan_status") in ("failure", "partial")
    ):
        overall = "warning"

    checks["overall"] = overall
    return JSONResponse(content=checks)


# Import compatibility for callers that inspected the former route function.
# The registered /api/health endpoint is owned by routes.api.system.
api_health = build_api_health_response
