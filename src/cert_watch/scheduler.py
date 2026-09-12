"""Daily scheduler. See spec wi_fr05_scheduler.md."""

from __future__ import annotations

import concurrent.futures
import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cert_watch.renewal_analytics import RenewalOverdueSignal

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


def _next_daily_time(hour: int, minute: int, now: datetime) -> datetime:
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def _seconds_until(hour: int, minute: int) -> float:
    now = datetime.now(UTC)
    return (_next_daily_time(hour, minute, now) - now).total_seconds()


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


def _host_scan_deadlines(
    db_path: str | Path, hour: int, minute: int, now: datetime,
) -> list[tuple[str, int, datetime, bool]]:
    """One cadence policy for host selection and scheduler wakeups.

    Custom intervals start at the last success. Default hosts use the next
    configured daily UTC boundary after their last success. Failed attempts
    delay retries by an hour, without moving a successful host's cadence.
    """
    from cert_watch.database import _connect
    from cert_watch.scan_freshness import cadence_due_at
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT h.hostname, h.port, h.scan_interval_hours,
                   MAX(CASE WHEN sh.status = 'success' THEN sh.scanned_at END) as last_scan,
                   MAX(sh.scanned_at) as last_attempt
            FROM hosts h
            LEFT JOIN scan_history sh
                ON sh.hostname = h.hostname AND sh.port = h.port
            GROUP BY h.hostname, h.port
            """
        ).fetchall()

    def timestamp(value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)

    deadlines: list[tuple[str, int, datetime, bool]] = []
    for r in rows:
        last = timestamp(r["last_scan"]) if r["last_scan"] else None
        attempt = timestamp(r["last_attempt"]) if r["last_attempt"] else None
        if last is None:
            deadline = now
        else:
            deadline = cadence_due_at(last, r["scan_interval_hours"], hour, minute)
        if attempt is not None and (last is None or attempt > last):
            deadline = max(deadline, attempt + timedelta(seconds=FAST_RETRY_INTERVAL))
        deadlines.append((r["hostname"], r["port"], deadline, attempt is None))
    return deadlines


def get_hosts_due_for_scan(
    db_path: str | Path, *, hour: int = 6, minute: int = 0,
) -> list[tuple[str, int]]:
    """Return only hosts due under the shared daily/interval/retry policy."""
    now = datetime.now(UTC)
    return [
        (host, port) for host, port, deadline, _ in _host_scan_deadlines(db_path, hour, minute, now)
        if deadline <= now
    ]


def _seconds_until_next_scan(db_path: str | Path, hour: int, minute: int) -> float:
    now = datetime.now(UTC)
    deadlines = _host_scan_deadlines(db_path, hour, minute, now)
    # Never-attempted hosts remain eligible in any cycle, but retain the initial
    # hourly retry wakeup rather than triggering unsolicited scans at startup.
    return min((FAST_RETRY_INTERVAL if unattempted else max(0.0, (deadline - now).total_seconds())
                for _, _, deadline, unattempted in deadlines), default=float("inf"))


_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()
_scheduler_wake = threading.Event()
_scheduler_lock = threading.Lock()
_cycle_lock = threading.Lock()


def wake_scheduler() -> None:
    """Interrupt the timer so it rereads effective settings and host cadence."""
    _scheduler_wake.set()

_renewal_webhook_pool: concurrent.futures.ThreadPoolExecutor | None = (
    concurrent.futures.ThreadPoolExecutor(
        max_workers=2, thread_name_prefix="renewal-webhook",
    )
)
_renewal_webhook_pool_lock = threading.Lock()


def _flush_renewal_webhook_pool() -> None:
    """Drain pending tasks and explicitly reset the pool (test helper)."""
    global _renewal_webhook_pool
    with _renewal_webhook_pool_lock:
        pool = _renewal_webhook_pool
        _renewal_webhook_pool = None
    if pool is not None:
        pool.shutdown(wait=True)
    _start_renewal_webhook_pool()


def _start_renewal_webhook_pool() -> None:
    global _renewal_webhook_pool
    with _renewal_webhook_pool_lock:
        if _renewal_webhook_pool is None:
            _renewal_webhook_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="renewal-webhook",
            )


def _shutdown_renewal_webhook_pool() -> None:
    pool = _detach_renewal_webhook_pool()
    if pool is not None:
        pool.shutdown(wait=True)


def _detach_renewal_webhook_pool() -> concurrent.futures.ThreadPoolExecutor | None:
    """Close the submission gate immediately and return the pool to drain."""
    global _renewal_webhook_pool
    with _renewal_webhook_pool_lock:
        pool = _renewal_webhook_pool
        _renewal_webhook_pool = None
    return pool


def _submit_renewal_webhook(fn: Callable[[], None]) -> bool:
    with _renewal_webhook_pool_lock:
        if _renewal_webhook_pool is None:
            return False
        _renewal_webhook_pool.submit(fn)
    return True


def _run_cycle(
    scan_fn: Callable[[], dict[str, Any]],
    alert_fn: Callable[[], dict[str, Any]],
    *,
    ct_fn: Callable[[], dict[str, Any]] | None = None,
    maintenance_fn: Callable[[], None] | None = None,
    digest_fn: Callable[[], dict[str, Any]] | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    """Run one scan → CT → alert → digest → maintenance cycle.

    Each stage is isolated: a failure in any one is logged and swallowed so the
    remaining stages still run and the scheduler thread survives to the next day.
    Module-level (not a closure) so the failure-isolation behaviour is directly
    testable without waiting for the daily timer to fire.
    """
    try:
        scan_fn()
        logger.info("scheduled scan completed")
    except Exception:  # noqa: BLE001 — failure isolation: one stage failing must not stop the others
        logger.exception("scheduler scan_fn failed")
    if stop_event is not None and stop_event.is_set():
        return
    if ct_fn is not None:
        try:
            ct_fn()
            logger.info("scheduled CT check completed")
        except Exception:  # noqa: BLE001 — failure isolation
            logger.exception("scheduler ct_fn failed")
    if stop_event is not None and stop_event.is_set():
        return
    try:
        alert_fn()
        logger.info("scheduled alerts completed")
    except Exception:  # noqa: BLE001 — failure isolation
        logger.exception("scheduler alert_fn failed")
    if stop_event is not None and stop_event.is_set():
        return
    if digest_fn is not None:
        try:
            digest_fn()
            logger.info("scheduled digest completed")
        except Exception:  # noqa: BLE001 — failure isolation
            logger.exception("scheduler digest_fn failed")
    if stop_event is not None and stop_event.is_set():
        return
    if maintenance_fn is not None:
        try:
            maintenance_fn()
        except Exception:  # noqa: BLE001 — failure isolation
            logger.exception("scheduler maintenance_fn failed")


def start_scheduler(
    scan_fn: Callable[[], dict[str, Any]],
    alert_fn: Callable[[], dict[str, Any]],
    *,
    ct_fn: Callable[[], dict[str, Any]] | None = None,
    maintenance_fn: Callable[[], None] | None = None,
    digest_fn: Callable[[], dict[str, Any]] | None = None,
    hour: int = 6,
    minute: int = 0,
    db_path: str | Path | None = None,
    schedule_provider: Callable[[], tuple[int, int]] | None = None,
) -> None:
    """Run the daily cycle and additional cycles when individual hosts are due.

    ``maintenance_fn`` (optional) runs at the end of each daily cycle for
    housekeeping such as audit-log retention; failures are logged, never raised.

    Settings saves wake the timer; each job captures its own complete config.
    An hourly recheck discovers inventory changes even without a settings save.
    """
    global _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return

        from cert_watch.digest import start_digest_pool

        _start_renewal_webhook_pool()
        start_digest_pool()

        def _loop() -> None:
            next_cycle_allowed = 0.0
            daily_deadline: datetime | None = None
            daily_schedule: tuple[int, int] | None = None
            while not _scheduler_stop.is_set():
                # Clear before reading settings so an update during calculation
                # remains signalled and cannot leave the old timer asleep.
                _scheduler_wake.clear()
                if _scheduler_stop.is_set():
                    return
                current_hour, current_minute = (
                    schedule_provider() if schedule_provider else (hour, minute)
                )
                now = datetime.now(UTC)
                if daily_deadline is None or daily_schedule != (current_hour, current_minute):
                    daily_deadline = _next_daily_time(current_hour, current_minute, now)
                    daily_schedule = (current_hour, current_minute)
                cycle_wait = max(0.0, (daily_deadline - now).total_seconds())
                if db_path is not None:
                    try:
                        cycle_wait = min(cycle_wait, _seconds_until_next_scan(
                            db_path, current_hour, current_minute,
                        ))
                    except Exception:
                        logger.exception("could not calculate host scan cadence")
                # An unexpected scan/storage failure must not create a hot loop
                # when no attempt could be recorded. Normal retries remain hourly.
                cycle_wait = max(cycle_wait, next_cycle_allowed - time.monotonic())
                wait = min(cycle_wait, FAST_RETRY_INTERVAL)
                if _scheduler_wake.wait(timeout=wait):
                    continue
                if _scheduler_stop.is_set():
                    return
                # A delayed hourly recheck can cross the daily deadline. Keep
                # that absolute target until after the wait; recomputing it
                # first would silently move an elapsed run to tomorrow.
                if cycle_wait > FAST_RETRY_INTERVAL and datetime.now(UTC) < daily_deadline:
                    continue
                if not _cycle_lock.acquire(blocking=False):
                    logger.warning("skipping scheduled cycle; previous cycle still running")
                    next_cycle_allowed = time.monotonic() + 60
                    continue
                try:
                    _run_cycle(
                        scan_fn, alert_fn, ct_fn=ct_fn, maintenance_fn=maintenance_fn,
                        digest_fn=digest_fn, stop_event=_scheduler_stop,
                    )
                finally:
                    _cycle_lock.release()
                    next_cycle_allowed = time.monotonic() + 60
                    now = datetime.now(UTC)
                    if daily_deadline <= now:
                        daily_deadline = _next_daily_time(current_hour, current_minute, now)

        _scheduler_stop.clear()
        _scheduler_thread = threading.Thread(target=_loop, daemon=True, name="cert-watch-sched")
        _scheduler_thread.start()


def stop_scheduler() -> None:
    _scheduler_stop.set()
    _scheduler_wake.set()
    # Close submission gates before waiting for a potentially long scan. The
    # cycle checks the stop event between stages, and neither pool is recreated
    # until the next explicit start_scheduler() call.
    renewal_pool = _detach_renewal_webhook_pool()
    from cert_watch.digest import _detach_digest_pool
    digest_pool = _detach_digest_pool()
    if renewal_pool is not None:
        renewal_pool.shutdown(wait=True)
    if digest_pool is not None:
        digest_pool.shutdown(wait=True)
    if _scheduler_thread is not None:
        _scheduler_thread.join(timeout=30)


def run_scan_now(
    scan_fn: Callable[[str, int], object],
    alert_fn: Callable[[], dict[str, int]],
    *,
    db_path: str | Path | None = None,
    repo: Any = None,
    host_provider: Callable[[], list[tuple[str, int]]] | None = None,
    store_fn: Callable[[object], str] | None = None,
    settings: Any = None,
) -> dict[str, int]:
    """
    Execute one scan + alert cycle. See AC-02/AC-03/AC-05/AC-06.

    Defaults: pulls hosts from the DB via host_provider, calls scan_fn(host, port)
    for each, stores results via store_fn, then calls alert_fn() once at the end.

    When *settings* is provided, renewal webhook config is read from it instead
    of env vars (WI-133). When None, falls back to env vars for backward compat.
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
                except Exception:  # noqa: BLE001 — best-effort event emission; must not crash scan loop
                    logger.debug("scan_failed event suppressed", exc_info=True)
            continue

        scanned += 1
        if store_fn is not None:
            try:
                new_id = store_fn(result)
            except Exception as exc:  # noqa: BLE001 — pluggable store_fn; failure must not crash scan loop
                # Persistence failed: the scan produced a result but nothing was
                # stored, so it must not count as a successful scan (WI-142
                # sibling — success was previously bookkept before the store
                # completed, inflating `scanned` and hiding the failure).
                scanned -= 1
                failures += 1
                logger.exception("store_fn failed for %s:%s", hostname, port)
                if db_path is not None:
                    try:
                        record_scan_history(
                            db_path,
                            ScanHistory(
                                hostname=hostname,
                                port=port,
                                status="failure",
                                error_message=str(exc),
                            ),
                        )
                    except sqlite3.Error:
                        logger.warning(
                            "could not record scan failure for %s:%s",
                            hostname, port, exc_info=True,
                        )
                continue
            # WI-142 defense in depth: store_scanned's contract is "return a
            # non-empty leaf id on success, raise on failure." The empty-
            # return path was closed at scan.py (it now re-raises), but a
            # future regression that silently returns "" must not be recorded
            # as a successful scan — treat an empty leaf id as a failure too.
            if not new_id:
                scanned -= 1
                failures += 1
                logger.warning(
                    "store_fn returned empty leaf id for %s:%s — treating as failure",
                    hostname, port,
                )
                if db_path is not None:
                    try:
                        record_scan_history(
                            db_path,
                            ScanHistory(
                                hostname=hostname,
                                port=port,
                                status="failure",
                                error_message="store returned empty leaf id",
                            ),
                        )
                    except sqlite3.Error:
                        logger.warning(
                            "could not record scan failure for %s:%s",
                            hostname, port, exc_info=True,
                        )
                continue
        if db_path is not None:
            record_scan_history(
                db_path,
                ScanHistory(hostname=hostname, port=port, status="success"),
            )

    _check_renewal_overdue(db_path, hosts, settings=settings)

    alert_counts = alert_fn() or {"sent": 0, "failed": 0}
    return {
        "scanned": scanned,
        "alerts_sent": int(alert_counts.get("sent", 0)),
        "failures": failures + int(alert_counts.get("failed", 0)),
    }


def _check_renewal_overdue(
    db_path: str | Path | None,
    hosts: list[tuple[str, int]],
    *,
    settings: Any = None,
) -> None:
    if db_path is None:
        return
    try:
        import json as _json

        from cert_watch.database.connection import _connect as _conn
        from cert_watch.events import Event, emit_event
        from cert_watch.renewal_analytics import detect_renewal_overdue

        cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        already_emitted: set[tuple[str, int | None, str]] = set()
        legacy_emitted: set[tuple[str, str]] = set()
        with _conn(db_path) as conn:
            rows = conn.execute(
                """SELECT payload FROM event_log
                   WHERE event_type = 'renewal_overdue'
                   AND created_at > ?""",
                (cutoff,),
            ).fetchall()
        for r in rows:
            try:
                p = _json.loads(r["payload"])
                if not isinstance(p, dict):
                    continue
                hostname = p.get("hostname")
                fingerprint = p.get("cert_fingerprint")
                event_port = p.get("port")
                if not isinstance(hostname, str) or not isinstance(fingerprint, str):
                    continue
                if event_port is None:
                    # Old payloads represented a hostname-wide identity. Keep
                    # that 24-hour suppression contract after adding ports.
                    legacy_emitted.add((hostname, fingerprint))
                elif type(event_port) is int and 1 <= event_port <= 65535:
                    already_emitted.add((hostname, event_port, fingerprint))
            except (_json.JSONDecodeError, TypeError):
                pass

        seen: set[tuple[str, int]] = set()
        for hostname, port in hosts:
            if (hostname, port) in seen:
                continue
            seen.add((hostname, port))
            signal = detect_renewal_overdue(db_path, hostname, port=port)
            if signal is not None:
                if (
                    (signal.hostname, port, signal.cert_fingerprint) in already_emitted
                    or (signal.hostname, signal.cert_fingerprint) in legacy_emitted
                ):
                    continue
                emit_event(
                    Event(
                        event_type="renewal_overdue",
                        timestamp=datetime.now(UTC),
                        payload={
                            "hostname": signal.hostname,
                            "port": port,
                            "cert_fingerprint": signal.cert_fingerprint,
                            "days_remaining": signal.days_remaining,
                            "expected_renewal_at_days": signal.expected_renewal_at_days,
                            "days_overdue": signal.days_overdue,
                            "confidence": signal.confidence,
                        },
                        source="scheduler",
                    ),
                    db_path,
                )
                already_emitted.add((signal.hostname, port, signal.cert_fingerprint))
                # Per-endpoint guard: build_renewal_payload raises on an
                # out-of-range or conflicting port, and this loop's only `try`
                # wraps the whole sweep — so one legacy host row would silently
                # cost every later host its renewal webhook.
                try:
                    _send_renewal_webhook_if_configured(
                        signal, hostname, port, db_path, settings=settings,
                    )
                except Exception:
                    logger.exception(
                        "renewal webhook failed for %s:%s — continuing sweep",
                        hostname, port,
                    )
    except Exception:  # noqa: BLE001 — best-effort overdue check; must not crash scan cycle
        logger.exception("renewal overdue check failed")


def _send_renewal_webhook_if_configured(
    signal: RenewalOverdueSignal,
    hostname: str,
    port: int,
    db_path: str | Path,
    *,
    settings: Any = None,
) -> None:
    from cert_watch.renewal_webhook import (
        build_renewal_payload,
        load_renewal_webhook_config,
        send_renewal_webhook,
    )
    from cert_watch.retry import backoff_range

    if settings is not None:
        config = (
            settings.build_renewal_webhook_config()
            if hasattr(settings, "build_renewal_webhook_config")
            else None
        )
        base_url = getattr(settings, "base_url", "")
    else:
        import os

        config = load_renewal_webhook_config(
            env_url=os.environ.get("CERT_WATCH_RENEWAL_WEBHOOK_URL", ""),
            env_headers=os.environ.get("CERT_WATCH_RENEWAL_WEBHOOK_HEADERS", ""),
            allow_private=os.environ.get("CERT_WATCH_ALLOW_PRIVATE_IPS", "1") == "1",
            allowed_subnets=tuple(
                s.strip()
                for s in os.environ.get("CERT_WATCH_ALLOWED_SUBNETS", "").split(",")
                if s.strip()
            ),
        )
        base_url = os.environ.get("CERT_WATCH_BASE_URL", "")
    if config is None:
        return
    payload = build_renewal_payload(signal, db_path, port=port, base_url=base_url)

    def _deliver_with_retry() -> None:
        for _ in backoff_range(2, 1.0, strategy="exponential"):
            if send_renewal_webhook(payload, config):
                return
        logger.warning(
            "renewal webhook for %s failed after retries", signal.hostname
        )

    try:
        submitted = _submit_renewal_webhook(_deliver_with_retry)
    except Exception:
        logger.warning(
            "renewal webhook pool submit failed for %s",
            signal.hostname,
            exc_info=True,
        )
        return
    if not submitted:
        logger.info(
            "renewal webhook for %s not submitted because scheduler is stopped",
            signal.hostname,
        )


def _hosts_from_db(db_path: str | Path) -> list[tuple[str, int]]:
    """Return hosts due for scanning, respecting per-host intervals."""
    return get_hosts_due_for_scan(db_path)
