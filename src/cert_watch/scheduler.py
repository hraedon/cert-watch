"""Daily scheduler. See spec wi_fr05_scheduler.md."""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger("cert_watch.scheduler")


@dataclass
class ScanHistory:
    hostname: str
    port: int
    status: str  # "success" | "partial" | "failure"
    id: str = ""
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error_message: str | None = None


def record_scan_history(db_path: str | Path, entry: ScanHistory) -> str:
    entry_id = entry.id or str(uuid.uuid4())
    from cert_watch.database import _connect
    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO scan_history
               (id, hostname, port, status, scanned_at, error_message)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                entry_id,
                entry.hostname,
                entry.port,
                entry.status,
                entry.scanned_at.isoformat(),
                entry.error_message,
            ),
        )
        conn.commit()
    return entry_id


def _seconds_until(hour: int, minute: int) -> float:
    now = datetime.now(UTC)
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


FAST_RETRY_INTERVAL = 3600  # 1 hour


def _has_pending_hosts(db_path: str | Path) -> bool:
    """Check if any host has never been successfully scanned."""
    from cert_watch.database import _connect
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM hosts h
            WHERE NOT EXISTS (
                SELECT 1 FROM scan_history sh
                WHERE sh.hostname = h.hostname
                AND sh.port = h.port
                AND sh.status = 'success'
            )
            LIMIT 1
            """
        ).fetchone()
    return row is not None


def get_hosts_due_for_scan(db_path: str | Path) -> list[tuple[str, int]]:
    """Return hosts that are due for scanning based on per-host intervals.

    A host is due if:
    - It has a scan_interval_hours set AND enough time has passed since last scan
    - OR it has no scan_interval_hours (uses default daily cycle, always due)
    - OR it has never been scanned (always due)
    """
    from cert_watch.database import _connect
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT h.hostname, h.port, h.scan_interval_hours,
                   MAX(sh.scanned_at) as last_scan
            FROM hosts h
            LEFT JOIN scan_history sh
                ON sh.hostname = h.hostname AND sh.port = h.port AND sh.status = 'success'
            GROUP BY h.hostname, h.port
            """
        ).fetchall()

    now = datetime.now(UTC)
    due: list[tuple[str, int]] = []
    for r in rows:
        if r["scan_interval_hours"] is None:
            # Default: always include in daily cycle
            due.append((r["hostname"], r["port"]))
            continue
        if r["last_scan"] is None:
            # Never scanned — always due
            due.append((r["hostname"], r["port"]))
            continue
        last = datetime.fromisoformat(r["last_scan"])
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        hours_since = (now - last).total_seconds() / 3600
        if hours_since >= r["scan_interval_hours"]:
            due.append((r["hostname"], r["port"]))
    return due


_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()
_scheduler_lock = threading.Lock()


def _run_cycle(
    scan_fn: Callable[[], dict],
    alert_fn: Callable[[], dict],
    *,
    ct_fn: Callable[[], dict] | None = None,
    maintenance_fn: Callable[[], None] | None = None,
) -> None:
    """Run one scan → CT → alert → maintenance cycle.

    Each stage is isolated: a failure in any one is logged and swallowed so the
    remaining stages still run and the scheduler thread survives to the next day.
    Module-level (not a closure) so the failure-isolation behaviour is directly
    testable without waiting for the daily timer to fire.
    """
    try:
        scan_fn()
        logger.info("scheduled scan completed")
    except Exception:  # noqa: BLE001
        logger.exception("scheduler scan_fn failed")
    if ct_fn is not None:
        try:
            ct_fn()
            logger.info("scheduled CT check completed")
        except Exception:  # noqa: BLE001
            logger.exception("scheduler ct_fn failed")
    try:
        alert_fn()
        logger.info("scheduled alerts completed")
    except Exception:  # noqa: BLE001
        logger.exception("scheduler alert_fn failed")
    if maintenance_fn is not None:
        try:
            maintenance_fn()
        except Exception:  # noqa: BLE001
            logger.exception("scheduler maintenance_fn failed")


def start_scheduler(
    scan_fn: Callable[[], dict],
    alert_fn: Callable[[], dict],
    *,
    ct_fn: Callable[[], dict] | None = None,
    maintenance_fn: Callable[[], None] | None = None,
    hour: int = 6,
    minute: int = 0,
    db_path: str | Path | None = None,
) -> None:
    """Start a daemon thread that runs scan_fn + ct_fn + alert_fn once per day.

    ``maintenance_fn`` (optional) runs at the end of each daily cycle for
    housekeeping such as audit-log retention; failures are logged, never raised.

    When db_path is provided and there are hosts with no successful scan yet,
    the scheduler retries every FAST_RETRY_INTERVAL (1 hour) instead of waiting
    for the next daily cycle.  See AC-01.
    """
    global _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return

        def _loop() -> None:
            while not _scheduler_stop.is_set():
                wait = _seconds_until(hour, minute)
                if db_path is not None and _has_pending_hosts(db_path):
                    fast_wait = min(wait, FAST_RETRY_INTERVAL)
                    logger.debug("pending hosts found, retrying in %ds", fast_wait)
                    if _scheduler_stop.wait(timeout=fast_wait):
                        return
                else:
                    if _scheduler_stop.wait(timeout=wait):
                        return
                _run_cycle(
                    scan_fn, alert_fn, ct_fn=ct_fn, maintenance_fn=maintenance_fn
                )

        _scheduler_stop.clear()
        _scheduler_thread = threading.Thread(target=_loop, daemon=True, name="cert-watch-sched")
        _scheduler_thread.start()


def stop_scheduler() -> None:
    _scheduler_stop.set()
    if _scheduler_thread is not None:
        _scheduler_thread.join(timeout=2)


def run_scan_now(
    scan_fn: Callable[[str, int], object],
    alert_fn: Callable[[], dict[str, int]],
    *,
    db_path: str | Path | None = None,
    repo=None,
    host_provider: Callable[[], list[tuple[str, int]]] | None = None,
    store_fn: Callable[[object], str] | None = None,
) -> dict[str, int]:
    """
    Execute one scan + alert cycle. See AC-02/AC-03/AC-05/AC-06.

    Defaults: pulls hosts from the DB via host_provider, calls scan_fn(host, port)
    for each, stores results via store_fn, then calls alert_fn() once at the end.
    """
    if host_provider is None and db_path is not None:
        host_provider = lambda: _hosts_from_db(db_path)  # noqa: E731

    hosts = host_provider() if host_provider else []
    scanned = 0
    failures = 0

    for hostname, port in hosts:
        try:
            result = scan_fn(hostname, port)
        except Exception as exc:  # noqa: BLE001 — AC-05
            logger.exception("scan_fn raised for %s:%s", hostname, port)
            failures += 1
            if db_path is not None:
                record_scan_history(
                    db_path,
                    ScanHistory(
                        hostname=hostname, port=port, status="failure",
                        error_message=str(exc),
                    ),
                )
            continue

        # Treat a result with `error_message` attribute as a ScanError.
        if hasattr(result, "error_message"):
            failures += 1
            if db_path is not None:
                record_scan_history(
                    db_path,
                    ScanHistory(
                        hostname=hostname, port=port, status="failure",
                        error_message=getattr(result, "error_message", "unknown"),
                    ),
                )
                try:
                    from cert_watch.events import Event, emit_event

                    emit_event(
                        Event(
                            event_type="scan_failed",
                            timestamp=datetime.now(UTC),
                            payload={
                                "hostname": hostname,
                                "port": port,
                                "error_message": getattr(result, "error_message", "unknown"),
                            },
                            source="scheduler",
                        ),
                        db_path,
                    )
                except Exception:  # noqa: BLE001
                    pass
            continue

        if store_fn is not None:
            try:
                store_fn(result)
            except Exception:  # noqa: BLE001
                logger.exception("store_fn failed for %s:%s", hostname, port)

        scanned += 1
        if db_path is not None:
            record_scan_history(
                db_path,
                ScanHistory(hostname=hostname, port=port, status="success"),
            )

    alert_counts = alert_fn() or {"sent": 0, "failed": 0}
    return {
        "scanned": scanned,
        "alerts_sent": int(alert_counts.get("sent", 0)),
        "failures": failures + int(alert_counts.get("failed", 0)),
    }


def _hosts_from_db(db_path: str | Path) -> list[tuple[str, int]]:
    """Return hosts due for scanning, respecting per-host intervals."""
    return get_hosts_due_for_scan(db_path)
