"""Daily scheduler. See spec wi_fr05_scheduler.md."""

from __future__ import annotations

import logging
import sqlite3
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
    with sqlite3.connect(str(db_path)) as conn:
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


_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()


def start_scheduler(
    scan_fn: Callable[[], dict],
    alert_fn: Callable[[], dict],
    hour: int = 6,
    minute: int = 0,
) -> None:
    """Start a daemon thread that runs scan_fn + alert_fn once per day. See AC-01."""
    global _scheduler_thread

    def _loop() -> None:
        while not _scheduler_stop.is_set():
            wait = _seconds_until(hour, minute)
            if _scheduler_stop.wait(timeout=wait):
                return
            try:
                scan_fn()
            except Exception:  # noqa: BLE001
                logger.exception("scheduler scan_fn failed")
            try:
                alert_fn()
            except Exception:  # noqa: BLE001
                logger.exception("scheduler alert_fn failed")

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
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT hostname, port FROM hosts").fetchall()
    return [(r["hostname"], r["port"]) for r in rows]
