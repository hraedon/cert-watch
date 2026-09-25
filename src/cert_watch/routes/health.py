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
from cert_watch.auth.request_context import (
    _is_auth_enabled,
    check_metrics_token,
    metrics_token_configured,
    resolve_session_user,
)
from cert_watch.database.connection import _connect, _sql_now
from cert_watch.routes._deps import _db_path, _get_settings

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


# Alerts whose delivery failed in the window and that have not been delivered
# since: gave up (``failed``) in the window -- by when they became failed, since
# an alert can give up without any attempt (the bounded evidence deferral), so
# ``last_attempt_at`` stays empty and hid it (#113 review) -- or still
# retrying (``pending``/``sending``) with their latest recorded attempt refused
# or failed in the window. Counting only ``failed`` rows hid a webhook that
# returned HTTP 500 on every attempt for the whole backoff schedule -- up to
# 12 attempts over days -- behind "failed_alerts_24h: 0" (#113). A deferral
# (the attempt could not even be recorded) writes no ledger row and is counted
# by ``undelivered_alerts`` instead.
_FAILED_ALERTS_SQL = """
    SELECT COUNT(*) FROM alerts a
    WHERE (a.status = 'failed' AND a.failed_at > ?)
       OR (a.status IN ('pending', 'sending') AND EXISTS (
            SELECT 1 FROM alert_delivery_events c
            WHERE c.alert_id = a.id AND c.event_kind = 'completed'
              AND c.occurred_at > ?
              AND json_extract(c.details, '$.outcome') = 'failed'
              AND c.id = (
                  SELECT MAX(c2.id) FROM alert_delivery_events c2
                  WHERE c2.alert_id = a.id AND c2.event_kind = 'completed'
              )
       ))
"""


def _undelivered_count(db: str | Path, *, now: datetime) -> int:
    """Count overdue pending rows and abandoned sending leases."""
    overdue, stale_leases = _alert_delivery_counts(db, now=now)
    return overdue + stale_leases


def _detail_allowed(request: Request, auth_ctx: Any, *, metrics_token_unlocks: bool) -> bool:
    """Whether this caller may see the detailed health body.

    The detail (last scan, certificate and alert counts, scheduler errors) is
    computed over the whole estate, so it is for administrators only, plus,
    on ``/readyz`` alone (*metrics_token_unlocks*), the monitoring scraper's
    ``CERT_WATCH_METRICS_TOKEN``. A tag-scoped principal, an API key below
    ``admin`` scope and an anonymous caller get the shallow body: the overall
    status and nothing else (#116 review). The token never widens a session:
    ``/api/health`` is a session API and ignores it. Open mode (no auth
    provider) has no principals to tell apart and keeps the full body, as
    the deployment smoke checks rely on.
    """
    if not _is_auth_enabled(request):
        return True
    if metrics_token_unlocks and metrics_token_configured(request) and check_metrics_token(request):
        return True
    return auth_ctx is not None and bool(getattr(auth_ctx, "is_admin", False))


def _probe_principal(request: Request) -> Any:
    """Resolve the caller of a public probe path to an AuthContext, or None.

    ``/readyz`` is public, so ``auth_middleware`` never runs on it and
    nothing has authenticated the request yet. The middleware's own resolver
    is used (session cookie first, then API key), so a caller presenting
    both credentials gets the same answer here as on ``/api/health``.
    """
    if resolve_session_user(request).error is not None:
        return None
    return getattr(request.state, "auth_context", None)


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
    reads as Ready to a kubelet). When an auth provider is configured, the
    detailed checks are for administrators and the metrics token only; every
    other caller, anonymous or tag-scoped, gets the shallow body (status
    only). See :func:`_detail_allowed`.
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
    scheduler_failures = int(getattr(scheduler, "loop_failure_count", 0) or 0)
    scheduler_error = getattr(scheduler, "last_loop_error", None)
    if scheduler is not None and scheduler.is_running:
        checks["scheduler"] = "running"
    elif scheduler_error:
        checks["scheduler"] = "failed"
        checks["scheduler_failures"] = str(scheduler_failures)
        checks["scheduler_last_error"] = str(scheduler_error)
        ok = False
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
                "AND julianday(not_after) <= julianday(?)",
                (_sql_now(),),
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
    full = _detail_allowed(
        request, _probe_principal(request) if _is_auth_enabled(request) else None,
        metrics_token_unlocks=True,
    )
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
    """Structured health data for the dashboard banner.

    Administrators get every check; everyone else gets ``{"overall": ...}``
    only, because the checks are estate-wide (see :func:`_detail_allowed`).
    """
    db = _db_path(request)
    checks: dict[str, object] = {}
    scan_query_ok = True
    alert_query_ok = True

    # Scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    checks["scheduler_running"] = bool(scheduler and scheduler.is_running)
    checks["scheduler_failure_count"] = int(
        getattr(scheduler, "loop_failure_count", 0) or 0
    )
    checks["scheduler_last_error"] = getattr(scheduler, "last_loop_error", None)

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
            row = conn.execute(_FAILED_ALERTS_SQL, (cutoff, cutoff)).fetchone()
            checks["failed_alerts_24h"] = row[0] if row else 0
            checks["undelivered_alerts"] = (
                _undelivered_count(db, now=now) if delivery_configured else 0
            )
    except Exception:
        logger.warning("health alert query failed", exc_info=True)
        checks["failed_alerts_24h"] = 0
        checks["undelivered_alerts"] = 0
        alert_query_ok = False

    # Registered endpoints that have never produced a certificate. The strip
    # used to read "Monitoring pipeline healthy" while endpoints had never
    # been scanned successfully (#113). Scoped like Home's scan-coverage panel,
    # whose "without a successful scan" chip is the same count.
    try:
        from cert_watch.routes._scoped import scope_tags_from_auth
        from cert_watch.scan_freshness import load_scan_evidence

        scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
        evidence = load_scan_evidence(db, scope_tags=scope_tags)
        checks["endpoints_without_successful_scan"] = sum(
            1 for item in evidence.values() if item.state == "unobserved"
        )
    except Exception:
        logger.warning("health scan coverage query failed", exc_info=True)
        checks["endpoints_without_successful_scan"] = 0
        scan_query_ok = False

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
        or _count(checks, "endpoints_without_successful_scan") > 0
        or checks.get("last_scan_status") in ("failure", "partial")
    ):
        overall = "warning"

    checks["overall"] = overall
    if not _detail_allowed(
        request, getattr(request.state, "auth_context", None), metrics_token_unlocks=False
    ):
        return JSONResponse(content={"overall": overall})
    return JSONResponse(content=checks)


# Import compatibility for callers that inspected the former route function.
# The registered /api/health endpoint is owned by routes.api.system.
api_health = build_api_health_response
