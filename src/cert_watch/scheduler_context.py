"""Scheduler context — encapsulates the scan/alert/digest cycle logic.

Extracted from app.py lifespan closures so dependencies are explicit and
mutable state is encapsulated rather than threaded via nonlocal.
"""

from __future__ import annotations

import datetime as _dt
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cert_watch.config import Settings
from cert_watch.database import SqliteAlertRepository, SqliteHostRepository, get_write_lock
from cert_watch.scan import DeferredPostCommit, _evaluate_posture, scan_host, store_scanned
from cert_watch.scheduler import get_hosts_due_for_scan, run_scan_now, wake_scheduler

logger = logging.getLogger("cert_watch.scheduler_context")

_EXPIRY_DIGEST_WEEK_KEY = "_scheduler.expiry_digest_iso_week"
_RENEWAL_DIGEST_WEEK_KEY = "_scheduler.renewal_digest_iso_week"


def _decode_iso_week(value: str | None) -> tuple[int, int]:
    if not value:
        return (0, 0)
    try:
        year, week = (int(part) for part in value.split("-W", 1))
    except (TypeError, ValueError):
        return (0, 0)
    if year < 1 or not 1 <= week <= 53:
        return (0, 0)
    return (year, week)


@dataclass(frozen=True)
class _JobConfig:
    settings: Settings
    alert_cfg: Any
    webhook_cfg: Any


@dataclass
class SchedulerContext:
    settings: Settings
    alert_cfg: Any
    webhook_cfg: Any
    _expiry_digest_week: tuple[int, int] = field(default_factory=lambda: (0, 0))
    _renewal_digest_week: tuple[int, int] = field(default_factory=lambda: (0, 0))
    _renewal_digest_inflight_week: tuple[int, int] | None = field(
        default=None, init=False, repr=False
    )
    _digest_state_lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )
    _config_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _job_config: _JobConfig = field(init=False, repr=False)

    def __post_init__(self) -> None:
        from cert_watch.database.kv_store import kv_get

        self._job_config = _JobConfig(self.settings, self.alert_cfg, self.webhook_cfg)
        self._expiry_digest_week = _decode_iso_week(
            kv_get(self.settings.db_path, _EXPIRY_DIGEST_WEEK_KEY)
        )
        self._renewal_digest_week = _decode_iso_week(
            kv_get(self.settings.db_path, _RENEWAL_DIGEST_WEEK_KEY)
        )

    def _snapshot(self) -> _JobConfig:
        with self._config_lock:
            return self._job_config

    def update_settings(self, settings: Settings) -> None:
        """Publish a complete configuration; running jobs keep their snapshot."""
        config = _JobConfig(
            settings, settings.build_alert_config(), settings.build_webhook_config(),
        )
        with self._config_lock:
            if settings.db_path != self._job_config.settings.db_path:
                raise ValueError("The scheduler database cannot change while running")
            self._job_config = config
            self.settings = settings
            self.alert_cfg = config.alert_cfg
            self.webhook_cfg = config.webhook_cfg
        wake_scheduler()

    def schedule_time(self) -> tuple[int, int]:
        settings = self._snapshot().settings
        return settings.sched_hour, settings.sched_min

    def _record_digest_week(
        self, key: str, week: tuple[int, int]
    ) -> tuple[bool, tuple[int, int]]:
        from cert_watch.database.kv_store import kv_set_max_iso_week

        return kv_set_max_iso_week(self._snapshot().settings.db_path, key, week)

    def scan_all(self) -> dict[str, Any]:
        config = self._snapshot()
        s = config.settings
        host_repo = SqliteHostRepository(s.db_path)
        all_hosts = host_repo.list_all()
        hosts = get_hosts_due_for_scan(s.db_path, hour=s.sched_hour, minute=s.sched_min)
        starttls_by_host = {
            (h.hostname, h.port): h.starttls_mode for h in all_hosts
        }
        deferred_operations: list[DeferredPostCommit] = []

        result = run_scan_now(
            scan_fn=lambda host, port: scan_host(
                host, port, verify=s.tls_verify, timeout=s.scan_timeout,
                retries=s.scan_retries, allow_private=s.allow_private,
                allowed_subnets=s.allowed_subnets,
                dns_servers=s.dns_servers,
                max_output_bytes=s.scan_max_output_bytes,
                hsts_timeout=s.hsts_timeout,
                starttls_mode=starttls_by_host.get((host, port), ""),
            ),
            alert_fn=lambda: {"sent": 0, "failed": 0},
            db_path=s.db_path,
            host_provider=lambda: hosts,
            store_fn=lambda result: self._store_with_lock(result, config, deferred_operations),
            settings=s,
        )
        from cert_watch.scan import _execute_deferred_post_commit
        for deferred in deferred_operations:
            _execute_deferred_post_commit(deferred)
        return result

    def _store_with_lock(
        self, result: Any, config: _JobConfig, deferred_operations: list[DeferredPostCommit],
    ) -> str:
        s = config.settings
        deferred = DeferredPostCommit()
        posture_eval = None
        try:
            posture_eval = _evaluate_posture(
                s.db_path, result,
                check_revocation=s.check_revocation,
                allow_private=s.allow_private,
                allowed_subnets=s.allowed_subnets,
            )
        except Exception:
            logger.warning("pre-lock posture eval failed", exc_info=True)
        with get_write_lock():
            leaf_id = store_scanned(
                result, s.db_path,
                drift_alerts=s.drift_alerts,
                check_revocation=s.check_revocation,
                allow_private=s.allow_private,
                allowed_subnets=s.allowed_subnets,
                webhook_config=config.webhook_cfg,
                _deferred=deferred,
                _posture_eval=posture_eval,
            )
        if leaf_id:
            deferred_operations.append(deferred)
        return leaf_id

    def run_alerts(self) -> dict[str, Any]:
        import datetime as _dt

        from cert_watch.alerts import (
            evaluate_all_certs,
            evaluate_renewal_window,
            process_pending,
            send_expiry_digest,
        )

        config = self._snapshot()
        s = config.settings
        repo = SqliteAlertRepository(s.db_path)
        if s.alert_digest_only:
            evaluate_all_certs(s.db_path, repo, urgent_only=True)
            evaluate_renewal_window(s.db_path, repo, s.renewal_window_days)
            result = process_pending(repo, config.alert_cfg, webhook_config=config.webhook_cfg)
            iso = _dt.datetime.now(_dt.UTC).isocalendar()
            this_week = (iso[0], iso[1])
            if this_week != self._expiry_digest_week:
                delivered = send_expiry_digest(
                    s.db_path, config.alert_cfg, webhook_config=config.webhook_cfg,
                    cadence_days=self._max_group_cadence(s.db_path),
                )
                if delivered:
                    _, stored_week = self._record_digest_week(
                        _EXPIRY_DIGEST_WEEK_KEY, this_week
                    )
                    self._expiry_digest_week = max(self._expiry_digest_week, stored_week)
                result["sent"] = result.get("sent", 0) + (1 if delivered else 0)
                result["failed"] = result.get("failed", 0) + (0 if delivered else 1)
            return result
        evaluate_all_certs(s.db_path, repo)
        evaluate_renewal_window(s.db_path, repo, s.renewal_window_days)
        return process_pending(repo, config.alert_cfg, webhook_config=config.webhook_cfg)

    def _weekly_digest(
        self, delivery_completion_callback: Callable[[bool], None] | None = None
    ) -> bool | None:
        from cert_watch.digest import send_renewal_digest

        config = self._snapshot()
        s = config.settings
        return send_renewal_digest(
            s.db_path, config.alert_cfg, config.webhook_cfg,
            cadence_days=self._max_group_cadence(s.db_path, default=7),
            delivery_completion_callback=delivery_completion_callback,
        )

    def maybe_run_weekly_digest(self) -> dict[str, Any]:
        iso = _dt.datetime.now(_dt.UTC).isocalendar()
        this_week = (iso[0], iso[1])
        with self._digest_state_lock:
            if (
                this_week == self._renewal_digest_week
                or this_week == self._renewal_digest_inflight_week
            ):
                return {"sent": 0, "failed": 0}
            self._renewal_digest_inflight_week = this_week

        callback_lock = threading.Lock()
        callback_completed = False
        callback_succeeded = False

        def _complete_delivery(succeeded: bool) -> bool:
            nonlocal callback_completed, callback_succeeded
            with callback_lock:
                if callback_completed:
                    return callback_succeeded
                now = _dt.datetime.now(_dt.UTC).isocalendar()
                callback_week = (now[0], now[1])
                with self._digest_state_lock:
                    is_current = (
                        callback_week == this_week
                        and self._renewal_digest_inflight_week == this_week
                    )
                if not is_current:
                    callback_completed = True
                    with self._digest_state_lock:
                        if self._renewal_digest_inflight_week == this_week:
                            self._renewal_digest_inflight_week = None
                    return False
                if not succeeded:
                    callback_completed = True
                    with self._digest_state_lock:
                        if self._renewal_digest_inflight_week == this_week:
                            self._renewal_digest_inflight_week = None
                    return False
                try:
                    _, stored_week = self._record_digest_week(
                        _RENEWAL_DIGEST_WEEK_KEY, this_week
                    )
                except Exception:
                    logger.exception("could not persist successful renewal digest week")
                    callback_completed = True
                    with self._digest_state_lock:
                        if self._renewal_digest_inflight_week == this_week:
                            self._renewal_digest_inflight_week = None
                    return False
                callback_completed = True
                callback_succeeded = True
            with self._digest_state_lock:
                self._renewal_digest_week = max(self._renewal_digest_week, stored_week)
                if self._renewal_digest_inflight_week == this_week:
                    self._renewal_digest_inflight_week = None
            return True

        def _completion_callback(succeeded: bool) -> None:
            _complete_delivery(succeeded)

        try:
            delivered = self._weekly_digest(_completion_callback)
        except Exception:
            _complete_delivery(False)
            logger.exception("weekly renewal digest failed")
            return {"sent": 0, "failed": 1}
        if delivered is True:
            # SMTP completes synchronously.  The callback may also have run
            # already for inline webhook fallback; its idempotence prevents a
            # second ledger write in that path.
            if _complete_delivery(True):
                return {"sent": 1, "failed": 0}
            return {"sent": 0, "failed": 1}
        if delivered is None:
            return {"sent": 0, "failed": 0}
        _complete_delivery(False)
        return {"sent": 0, "failed": 1}

    def maintenance(self) -> None:
        from cert_watch.audit import purge_old_audit
        from cert_watch.database import purge_old_alerts, purge_old_history
        from cert_watch.database.drift import purge_old_scan_history
        from cert_watch.events import purge_old_events

        s = self._snapshot().settings
        purge_old_audit(s.db_path, s.audit_retention_days)
        purge_old_history(s.db_path, s.history_retention_days)
        purge_old_scan_history(s.db_path, s.history_retention_days)
        purge_old_alerts(s.db_path, s.alert_retention_days)
        purge_old_events(s.db_path, s.event_retention_days)

    def _max_group_cadence(
        self, db_path: str | Path, *, default: int = 30
    ) -> int:
        from cert_watch.database import SqliteAlertGroupRepository

        try:
            groups = SqliteAlertGroupRepository(db_path).list_all()
        except Exception:  # noqa: BLE001 — best-effort; schema may not be ready
            return default
        cadences = [g.digest_cadence_days for g in groups if g.digest_cadence_days > 0]
        return max(cadences) if cadences else default
