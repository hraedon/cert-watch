"""Daily scheduler. See spec wi_fr05_scheduler.md."""

from __future__ import annotations

import concurrent.futures
import logging
import sqlite3
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from cert_watch.renewal_analytics import RenewalOverdueSignal
    from cert_watch.scheduler_context import SchedulerContext

logger = logging.getLogger("cert_watch.scheduler")


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class ScanHistory:
    hostname: str
    port: int
    status: str  # "success" | "partial" | "failure"
    id: str = ""
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error_message: str | None = None


def record_scan_history(
    db_path: str | Path,
    entry: ScanHistory,
    *,
    conn: sqlite3.Connection | None = None,
) -> str:
    entry_id = entry.id or str(uuid.uuid4())
    from cert_watch.database import _connect

    if conn is not None:
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
        return entry_id
    with _connect(db_path) as owned_conn:
        owned_conn.execute(
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
        owned_conn.commit()
    return entry_id


def _next_daily_time(hour: int, minute: int, now: datetime) -> datetime:
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def _seconds_until(hour: int, minute: int, *, now: datetime | None = None) -> float:
    now = now or datetime.now(UTC)
    return (_next_daily_time(hour, minute, now) - now).total_seconds()


FAST_RETRY_INTERVAL = 3600  # 1 hour
LOOP_RESTART_BACKOFF_INITIAL = 1.0
LOOP_RESTART_BACKOFF_MAX = 300.0


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

    def timestamp(value: str, hostname: str, field_name: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError):
            logger.warning(
                "host %s has a malformed %s scan timestamp (%r); ignoring it",
                hostname,
                field_name,
                value,
            )
            return None
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)

    deadlines: list[tuple[str, int, datetime, bool]] = []
    for r in rows:
        last = timestamp(r["last_scan"], r["hostname"], "successful") if r["last_scan"] else None
        attempt = (
            timestamp(r["last_attempt"], r["hostname"], "attempt")
            if r["last_attempt"] else None
        )
        if last is None:
            deadline = now
        else:
            try:
                deadline = cadence_due_at(last, r["scan_interval_hours"], hour, minute)
            except (OverflowError, TypeError, ValueError):
                # A stored interval this arithmetic cannot use -- historically
                # any integer was accepted here, and `last + timedelta(hours=N)`
                # leaves the representable range well before N does. Falling
                # back to the daily boundary keeps the host scanned on the
                # default cadence.
                #
                # Isolation is the point. This loop selects work for the WHOLE
                # estate, so letting one row raise stopped `get_hosts_due_for_scan`
                # and `_seconds_until_next_scan` outright and nothing was scanned
                # at all -- while `load_scan_evidence`, which already caught this,
                # kept every dashboard rendering green. A certificate monitor
                # that has silently stopped monitoring is the worst shape this
                # failure could take. See #29.
                logger.warning(
                    "host %s:%s has an unusable scan_interval_hours (%r); "
                    "falling back to the daily cadence",
                    r["hostname"], r["port"], r["scan_interval_hours"],
                )
                deadline = cadence_due_at(last, None, hour, minute)
        if attempt is not None and (last is None or attempt > last):
            deadline = max(deadline, attempt + timedelta(seconds=FAST_RETRY_INTERVAL))
        deadlines.append((r["hostname"], r["port"], deadline, attempt is None))
    return deadlines


def get_hosts_due_for_scan(
    db_path: str | Path, *, hour: int = 6, minute: int = 0,
    now: datetime | None = None,
) -> list[tuple[str, int]]:
    """Return only hosts due under the shared daily/interval/retry policy."""
    now = now or datetime.now(UTC)
    return [
        (host, port) for host, port, deadline, _ in _host_scan_deadlines(db_path, hour, minute, now)
        if deadline <= now
    ]


def _seconds_until_next_scan(
    db_path: str | Path,
    hour: int,
    minute: int,
    *,
    now: datetime | None = None,
) -> float:
    now = now or datetime.now(UTC)
    deadlines = _host_scan_deadlines(db_path, hour, minute, now)
    # Never-attempted hosts remain eligible in any cycle, but retain the initial
    # hourly retry wakeup rather than triggering unsolicited scans at startup.
    return min((FAST_RETRY_INTERVAL if unattempted else max(0.0, (deadline - now).total_seconds())
                for _, _, deadline, unattempted in deadlines), default=float("inf"))


class Clock(Protocol):
    """Time source used by the scheduler loop and digest budget."""

    def now(self) -> datetime: ...

    def monotonic(self) -> float: ...

    def wait(self, event: threading.Event, timeout: float) -> bool: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()

    def wait(self, event: threading.Event, timeout: float) -> bool:
        return event.wait(timeout)


class Scheduler:
    """Own the scheduling loop, synchronization, jobs, and webhook executor."""

    def __init__(
        self,
        context: SchedulerContext,
        *,
        clock: Clock | None = None,
        shutdown_timeout: float = 30.0,
    ) -> None:
        self.context = context
        self.clock = clock or SystemClock()
        self.shutdown_timeout = shutdown_timeout
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._cycle_lock = threading.Lock()
        self._desired_running = False
        self._loop_failure_count = 0
        self._last_loop_error: str | None = None
        self._webhook_pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._webhook_lock = threading.Lock()
        self._webhook_futures: set[concurrent.futures.Future[None]] = set()
        self._last_scan_lock = threading.Lock()
        self._last_scan_timestamp: float | None = None
        self._bind_context()
        self._load_last_scan_timestamp()

    def _bind_context(self) -> None:
        self.context.bind_runtime(
            stop_event=self._stop_event,
            wake=self.wake,
            scan_runner=self.run_scan_now,
            clock=self.clock,
        )

    @property
    def is_running(self) -> bool:
        with self._lifecycle_lock:
            return (
                self._thread is not None
                and self._thread.is_alive()
                and self._last_loop_error is None
            )

    @property
    def loop_failure_count(self) -> int:
        with self._lifecycle_lock:
            return self._loop_failure_count if self._last_loop_error is not None else 0

    @property
    def last_loop_error(self) -> str | None:
        with self._lifecycle_lock:
            return self._last_loop_error

    @property
    def last_scan_timestamp(self) -> float | None:
        with self._last_scan_lock:
            return self._last_scan_timestamp

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event

    def start(self) -> None:
        """Start exactly one loop; repeated calls are idempotent.

        If a bounded stop returned while a phase was still unwinding, this marks
        a restart request. The exiting generation starts its successor instead
        of clearing its stop event or allowing two loops to overlap.
        """
        with self._lifecycle_lock:
            self._desired_running = True
            if self._thread is not None and self._thread.is_alive():
                return
            self._start_locked()

    def _start_locked(self) -> None:
        self._stop_event = threading.Event()
        self._wake_event.clear()
        self._ensure_webhook_pool()
        self._bind_context()
        thread = threading.Thread(
            target=self._run_loop,
            args=(self._stop_event,),
            daemon=True,
            name="cert-watch-sched",
        )
        self._thread = thread
        thread.start()

    def stop(self, timeout: float | None = None) -> bool:
        """Signal shutdown and wait no longer than one shared deadline.

        Queued webhook work is cancelled. A running network call is allowed to
        finish independently after the deadline; it cannot hold app shutdown.
        Returns whether the scheduler loop stopped within the deadline.
        """
        budget = self.shutdown_timeout if timeout is None else max(0.0, timeout)
        deadline = self.clock.monotonic() + budget
        with self._lifecycle_lock:
            self._desired_running = False
            thread = self._thread
            self._stop_event.set()
            self._wake_event.set()
        pool, futures = self._detach_webhook_pool()
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        if futures:
            concurrent.futures.wait(
                futures,
                timeout=max(0.0, deadline - self.clock.monotonic()),
            )
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - self.clock.monotonic()))
        return thread is None or not thread.is_alive()

    def wake(self) -> None:
        """Interrupt the timer so it rereads settings and host cadence."""
        self._wake_event.set()

    def _run_loop(self, stop_event: threading.Event) -> None:
        next_cycle_allowed = 0.0
        daily_deadline: datetime | None = None
        daily_schedule: tuple[int, int] | None = None
        try:
            while not stop_event.is_set():
                try:
                    self._wake_event.clear()
                    if stop_event.is_set():
                        return
                    current_hour, current_minute = self.context.schedule_time()
                    now = self.clock.now()
                    if (
                        daily_deadline is None
                        or daily_schedule != (current_hour, current_minute)
                    ):
                        daily_deadline = _next_daily_time(current_hour, current_minute, now)
                        daily_schedule = (current_hour, current_minute)
                    cycle_wait = max(0.0, (daily_deadline - now).total_seconds())
                    try:
                        cycle_wait = min(
                            cycle_wait,
                            _seconds_until_next_scan(
                                self.context.settings.db_path,
                                current_hour,
                                current_minute,
                                now=now,
                            ),
                        )
                    except Exception:
                        logger.exception("could not calculate host scan cadence")
                    cycle_wait = max(
                        cycle_wait, next_cycle_allowed - self.clock.monotonic(),
                    )
                    wait = min(cycle_wait, FAST_RETRY_INTERVAL)
                    self._mark_loop_responsive()
                    if self.clock.wait(self._wake_event, wait):
                        self._mark_loop_healthy()
                        continue
                    if stop_event.is_set():
                        return
                    if cycle_wait > FAST_RETRY_INTERVAL and self.clock.now() < daily_deadline:
                        self._mark_loop_healthy()
                        continue
                    if not self._cycle_lock.acquire(blocking=False):
                        logger.warning("skipping scheduled cycle; previous cycle still running")
                        next_cycle_allowed = self.clock.monotonic() + 60
                        self._mark_loop_healthy()
                        continue
                    try:
                        self.run_cycle(stop_event=stop_event)
                    finally:
                        self._cycle_lock.release()
                        next_cycle_allowed = self.clock.monotonic() + 60
                        now = self.clock.now()
                        if daily_deadline <= now:
                            daily_deadline = _next_daily_time(
                                current_hour, current_minute, now,
                            )
                    self._mark_loop_healthy()
                except Exception as exc:
                    failure_count = self._mark_loop_failed(exc)
                    backoff = min(
                        LOOP_RESTART_BACKOFF_MAX,
                        LOOP_RESTART_BACKOFF_INITIAL
                        * 2.0 ** min(failure_count - 1, 30),
                    )
                    logger.exception(
                        "scheduler loop failed; retrying in %.1fs (failure %d)",
                        backoff,
                        failure_count,
                    )
                    daily_deadline = None
                    daily_schedule = None
                    next_cycle_allowed = 0.0
                    if stop_event.wait(backoff):
                        return
        finally:
            with self._lifecycle_lock:
                if self._thread is threading.current_thread():
                    self._thread = None
                if stop_event.is_set() and self._desired_running:
                    self._start_locked()

    def _mark_loop_failed(self, exc: Exception) -> int:
        with self._lifecycle_lock:
            self._loop_failure_count += 1
            self._last_loop_error = type(exc).__name__
            return self._loop_failure_count

    def _mark_loop_healthy(self) -> None:
        with self._lifecycle_lock:
            self._loop_failure_count = 0
            self._last_loop_error = None

    def _mark_loop_responsive(self) -> None:
        with self._lifecycle_lock:
            self._last_loop_error = None

    def run_cycle(
        self,
        *,
        scan_fn: Callable[[], dict[str, Any]] | None = None,
        alert_fn: Callable[[], dict[str, Any]] | None = None,
        ct_fn: Callable[[], dict[str, Any]] | None = None,
        maintenance_fn: Callable[[], None] | None = None,
        digest_fn: Callable[[], dict[str, Any]] | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        """Run one isolated scan → CT → alert → digest → maintenance cycle."""
        scan_fn = scan_fn or self.context.scan_all
        alert_fn = alert_fn or self.context.run_alerts
        maintenance_fn = maintenance_fn or self.context.maintenance
        digest_fn = digest_fn or self.context.maybe_run_weekly_digest
        stopped = stop_event or self._stop_event
        self._run_phase(
            "scan_fn", scan_fn, stopped, completed_message="scheduled scan completed",
        )
        if stopped.is_set():
            return
        if ct_fn is not None:
            self._run_phase(
                "ct_fn", ct_fn, stopped, completed_message="scheduled CT check completed",
            )
        if stopped.is_set():
            return
        self._run_phase(
            "alert_fn", alert_fn, stopped,
            completed_message="scheduled alerts completed",
        )
        if stopped.is_set():
            return
        if digest_fn is not None:
            self._run_phase(
                "digest_fn", digest_fn, stopped,
                completed_message="scheduled digest completed",
            )
        if stopped.is_set():
            return
        if maintenance_fn is not None:
            self._run_phase("maintenance_fn", maintenance_fn, stopped)

    @staticmethod
    def _run_phase(
        name: str,
        fn: Callable[[], Any],
        stopped: threading.Event,
        *,
        completed_message: str | None = None,
    ) -> None:
        """Isolate phase failures unless the process is genuinely stopping."""
        try:
            fn()
        except BaseException:
            if stopped.is_set() or sys.is_finalizing():
                raise
            logger.exception("scheduler %s failed", name)
        else:
            if completed_message is not None:
                logger.info(completed_message)

    def try_run_alert_delivery(
        self, delivery_fn: Callable[[], dict[str, int]],
    ) -> dict[str, int] | None:
        if not self._cycle_lock.acquire(blocking=False):
            return None
        try:
            return delivery_fn()
        finally:
            self._cycle_lock.release()

    def run_scan_now(self, *args: Any, **kwargs: Any) -> dict[str, int]:
        kwargs["now"] = self.clock.now
        kwargs["renewal_check"] = self._check_renewal_overdue
        kwargs["scan_recorded"] = self._record_last_scan_timestamp
        return _run_scan_now(*args, **kwargs)

    def _check_renewal_overdue(
        self,
        db_path: str | Path | None,
        hosts: list[tuple[str, int]],
        *,
        settings: Any = None,
    ) -> None:
        _check_renewal_overdue(
            db_path,
            hosts,
            settings=settings,
            now=self.clock.now,
            send_webhook=self._send_renewal_webhook_if_configured,
        )

    def _send_renewal_webhook_if_configured(
        self,
        signal: RenewalOverdueSignal,
        hostname: str,
        port: int,
        db_path: str | Path,
        *,
        settings: Any = None,
    ) -> None:
        _send_renewal_webhook_if_configured(
            signal,
            hostname,
            port,
            db_path,
            settings=settings,
            submit=self._submit_renewal_webhook,
        )

    def _ensure_webhook_pool(self) -> None:
        with self._webhook_lock:
            if self._webhook_pool is None:
                self._webhook_pool = concurrent.futures.ThreadPoolExecutor(
                    max_workers=2,
                    thread_name_prefix="renewal-webhook",
                )

    def _detach_webhook_pool(
        self,
    ) -> tuple[
        concurrent.futures.ThreadPoolExecutor | None,
        set[concurrent.futures.Future[None]],
    ]:
        with self._webhook_lock:
            pool = self._webhook_pool
            futures = set(self._webhook_futures)
            self._webhook_pool = None
            self._webhook_futures.clear()
        return pool, futures

    def _submit_renewal_webhook(self, fn: Callable[[], None]) -> bool:
        with self._webhook_lock:
            if self._webhook_pool is None:
                return False
            future = self._webhook_pool.submit(fn)
            self._webhook_futures.add(future)
        future.add_done_callback(self._webhook_done)
        return True

    def _webhook_done(self, future: concurrent.futures.Future[None]) -> None:
        with self._webhook_lock:
            self._webhook_futures.discard(future)

    def wait_for_webhooks(self, timeout: float = 5.0) -> bool:
        """Wait for submitted webhook work without tearing down the executor."""
        with self._webhook_lock:
            futures = set(self._webhook_futures)
        if not futures:
            return True
        _, pending = concurrent.futures.wait(futures, timeout=timeout)
        return not pending

    def _record_last_scan_timestamp(self, scanned_at: datetime) -> None:
        timestamp = scanned_at.timestamp()
        with self._last_scan_lock:
            if (
                self._last_scan_timestamp is None
                or timestamp > self._last_scan_timestamp
            ):
                self._last_scan_timestamp = timestamp

    def _load_last_scan_timestamp(self) -> None:
        """Initialize the cache from persisted history once at startup."""
        try:
            from cert_watch.database import _connect
            from cert_watch.database.connection import _parse_iso

            with _connect(self.context.settings.db_path) as conn:
                row = conn.execute("SELECT MAX(scanned_at) FROM scan_history").fetchone()
            value = row[0] if row else None
            timestamp = _parse_iso(value).timestamp() if value else None
        except (OSError, sqlite3.Error):
            logger.debug("could not refresh scheduler last-scan timestamp", exc_info=True)
            return
        except (TypeError, ValueError):
            logger.warning("latest scan timestamp is malformed", exc_info=True)
            timestamp = None
        with self._last_scan_lock:
            self._last_scan_timestamp = timestamp


def wake_scheduler(scheduler: Scheduler | None) -> None:
    """Compatibility seam for callers that receive an app-owned scheduler."""
    if scheduler is not None:
        scheduler.wake()


def try_run_alert_delivery(
    scheduler: Scheduler | None,
    delivery_fn: Callable[[], dict[str, int]],
) -> dict[str, int] | None:
    """Run manual delivery through the app-owned scheduler's cycle lock."""
    if scheduler is None:
        return delivery_fn()
    return scheduler.try_run_alert_delivery(delivery_fn)


def run_scan_now(scheduler: Scheduler, *args: Any, **kwargs: Any) -> dict[str, int]:
    """Run an immediate scan through the app-owned scheduler instance."""
    return scheduler.run_scan_now(*args, **kwargs)


def _run_scan_now(
    scan_fn: Callable[[str, int], object],
    alert_fn: Callable[[], dict[str, int]],
    *,
    db_path: str | Path | None = None,
    repo: Any = None,
    host_provider: Callable[[], list[tuple[str, int]]] | None = None,
    store_fn: Callable[[object], str] | None = None,
    settings: Any = None,
    now: Callable[[], datetime] = _utc_now,
    renewal_check: Callable[..., None],
    scan_recorded: Callable[[datetime], None] | None = None,
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

    def _record(entry: ScanHistory) -> str:
        if db_path is None:
            raise ValueError("db_path is required to record scan history")
        entry_id = record_scan_history(db_path, entry)
        if scan_recorded is not None:
            scan_recorded(entry.scanned_at)
        return entry_id

    for hostname, port in hosts:
        try:
            result = scan_fn(hostname, port)
        except Exception as exc:  # AC-05: isolate this host from the remaining batch.
            logger.exception("scan_fn raised for %s:%s", hostname, port)
            failures += 1
            if db_path is not None:
                try:
                    _record(
                        ScanHistory(
                            hostname=hostname, port=port, status="failure",
                            scanned_at=now(),
                            error_message=str(exc),
                        ),
                    )
                except sqlite3.Error:
                    logger.warning(
                        "could not record scan failure for %s:%s",
                        hostname, port, exc_info=True,
                    )
            continue

        # Treat a result with `error_message` attribute as a ScanError.
        if hasattr(result, "error_message"):
            failures += 1
            if db_path is not None:
                try:
                    _record(
                        ScanHistory(
                            hostname=hostname, port=port, status="failure",
                            scanned_at=now(),
                            error_message=getattr(result, "error_message", "unknown"),
                        ),
                    )
                except sqlite3.Error:
                    logger.warning(
                        "could not record scan failure for %s:%s",
                        hostname, port, exc_info=True,
                    )
                try:
                    from cert_watch.events import Event, emit_event

                    emit_event(
                        Event(
                            event_type="scan_failed",
                            timestamp=now(),
                            payload={
                                "hostname": hostname,
                                "port": port,
                                "error_message": getattr(result, "error_message", "unknown"),
                            },
                            source="scheduler",
                        ),
                        db_path,
                    )
                except Exception:  # Best-effort event emission must not stop the scan loop.
                    logger.debug("scan_failed event suppressed", exc_info=True)
            continue

        scanned += 1
        if store_fn is not None:
            try:
                new_id = store_fn(result)
            except Exception as exc:  # A pluggable store failure must not stop the scan loop.
                # Persistence failed: the scan produced a result but nothing was
                # stored, so it must not count as a successful scan (WI-142
                # sibling — success was previously bookkept before the store
                # completed, inflating `scanned` and hiding the failure).
                scanned -= 1
                failures += 1
                logger.exception("store_fn failed for %s:%s", hostname, port)
                if db_path is not None:
                    try:
                        _record(
                            ScanHistory(
                                hostname=hostname,
                                port=port,
                                status="failure",
                                scanned_at=now(),
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
                        _record(
                            ScanHistory(
                                hostname=hostname,
                                port=port,
                                status="failure",
                                scanned_at=now(),
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
            _record(
                ScanHistory(
                    hostname=hostname,
                    port=port,
                    status="success",
                    scanned_at=now(),
                ),
            )

    renewal_check(db_path, hosts, settings=settings)

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
    now: Callable[[], datetime] = _utc_now,
    send_webhook: Callable[..., None] | None = None,
) -> None:
    if db_path is None:
        return
    try:
        from cert_watch.database import AlertStore
        from cert_watch.events import Event, emit_event
        from cert_watch.renewal_analytics import detect_renewal_overdue

        store = AlertStore(db_path)
        seen: set[tuple[str, int]] = set()
        for hostname, port in hosts:
            if (hostname, port) in seen:
                continue
            seen.add((hostname, port))
            try:
                signal = detect_renewal_overdue(db_path, hostname, port=port)
                if signal is not None:
                    key = f"overdue:{signal.hostname}:{port}:{signal.cert_fingerprint}"
                    legacy_key = f"overdue:{signal.hostname}:*:{signal.cert_fingerprint}"
                    current = now()
                    if not store.rule_firing_due(
                        key,
                        now=current,
                        interval_seconds=24 * 60 * 60,
                        suppression_keys=(legacy_key,),
                    ):
                        continue
                    event_id = emit_event(
                        Event(
                            event_type="renewal_overdue",
                            timestamp=current,
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
                    if event_id is None:
                        continue
                    store.claim_rule_firing(
                        key,
                        now=current,
                        interval_seconds=24 * 60 * 60,
                        suppression_keys=(legacy_key,),
                    )
                    try:
                        if send_webhook is not None:
                            send_webhook(
                                signal, hostname, port, db_path, settings=settings,
                            )
                    except Exception:
                        logger.exception(
                            "renewal webhook failed for %s:%s — continuing sweep",
                            hostname, port,
                        )
            except Exception:
                logger.exception(
                    "renewal overdue check failed for %s:%s — continuing sweep",
                    hostname, port,
                )
    except Exception:  # Best-effort overdue detection must not stop the scan cycle.
        logger.exception("renewal overdue check failed")


def _send_renewal_webhook_if_configured(
    signal: RenewalOverdueSignal,
    hostname: str,
    port: int,
    db_path: str | Path,
    *,
    settings: Any = None,
    submit: Callable[[Callable[[], None]], bool],
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
        import json

        from cert_watch.config import Settings

        fallback_settings = Settings.from_env()
        config = load_renewal_webhook_config(
            env_url=fallback_settings.renewal_webhook_url,
            env_headers=json.dumps(fallback_settings.renewal_webhook_headers or {}),
            allow_private=fallback_settings.allow_private,
            allowed_subnets=fallback_settings.allowed_subnets,
        )
        base_url = fallback_settings.base_url
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
        submitted = submit(_deliver_with_retry)
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
    """Return every registered host for an explicit immediate scan."""
    from cert_watch.database import SqliteHostRepository

    return [
        (host.hostname, host.port)
        for host in SqliteHostRepository(db_path).list_all()
    ]
