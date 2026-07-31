"""Health, readiness, and favicon routes."""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.auth import SESSION_COOKIE, validate_session
from cert_watch.database.connection import _connect
from cert_watch.middleware import (
    _is_auth_enabled,
    _request_security,
    authenticate_api_key,
    require_auth,
)
from cert_watch.routes._deps import _db_path

logger = logging.getLogger("cert_watch.routes.health")

router = APIRouter()


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
    except Exception:
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
        except sqlite3.OperationalError:
            logger.debug("readyz heartbeat write failed (DB busy), continuing")
            checks["db_write"] = "ok"
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
    db_ok = True
    try:
        with _connect(db) as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception:
        db_ok = False
    if not db_ok or not checks["scheduler_running"]:
        overall = "critical"
    elif (
        (checks["failed_alerts_24h"] if isinstance(checks["failed_alerts_24h"], int) else 0) > 0
    ) or checks.get("last_scan_status") in ("failure", "partial"):
        overall = "warning"

    checks["overall"] = overall
    return JSONResponse(content=checks)
