"""Scheduler context — encapsulates the scan/alert/digest cycle logic.

Extracted from app.py lifespan closures so dependencies are explicit and
mutable state is encapsulated rather than threaded via nonlocal.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Any

from cert_watch.config import Settings, publish_settings
from cert_watch.database import SqliteAlertRepository, SqliteHostRepository, get_write_lock
from cert_watch.scan import DeferredPostCommit, _evaluate_posture, scan_host, store_scanned
from cert_watch.scheduler import get_hosts_due_for_scan, run_scan_now, wake_scheduler

logger = logging.getLogger("cert_watch.scheduler_context")

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
    stop_event: threading.Event | None = None
    _config_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _job_config: _JobConfig = field(init=False, repr=False)
    _digest_deadline: float | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._job_config = _JobConfig(self.settings, self.alert_cfg, self.webhook_cfg)
        publish_settings(self.settings)

    def _snapshot(self) -> _JobConfig:
        with self._config_lock:
            return self._job_config

    def update_settings(self, settings: Settings, *, publish: bool = True) -> None:
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
        if publish:
            publish_settings(settings)
        wake_scheduler()

    def schedule_time(self) -> tuple[int, int]:
        settings = self._snapshot().settings
        return settings.sched_hour, settings.sched_min

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

        from cert_watch.scan import _execute_deferred_post_commit
        try:
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
                store_fn=lambda result: self._store_with_lock(
                    result, config, deferred_operations
                ),
                settings=s,
            )
        finally:
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
        from cert_watch.alerting.digest.expiry import ExpiryDigestKind
        from cert_watch.alerting.dispatch import process_pending
        from cert_watch.alerting.model import ALERT_CYCLE_BUDGET_SECONDS
        from cert_watch.alerting.rules.expiry import evaluate_all_certs
        from cert_watch.alerting.rules.renewal import evaluate_renewal_window

        config = self._snapshot()
        s = config.settings
        repo = SqliteAlertRepository(s.db_path)
        closed_sent: list[Any] = []
        if s.alert_digest_only:
            evaluate_all_certs(s.db_path, repo, urgent_only=True)
            evaluate_renewal_window(
                s.db_path, repo, s.renewal_window_days, closed_sent=closed_sent,
            )
            self._resolve_closed_alerts(config, closed_sent)
            deadline = monotonic() + ALERT_CYCLE_BUDGET_SECONDS
            self._digest_deadline = deadline
            result = process_pending(
                repo,
                config.alert_cfg,
                webhook_config=config.webhook_cfg,
                budget_seconds=ALERT_CYCLE_BUDGET_SECONDS,
            )
            digest = self._run_digest(
                config,
                ExpiryDigestKind(config.alert_cfg),
                self._max_group_cadence(s.db_path),
                deadline=deadline,
                stop_event=self.stop_event,
            )
            result["sent"] = result.get("sent", 0) + digest.sent
            result["failed"] = result.get("failed", 0) + digest.failed
            result["deferred"] = result.get("deferred", 0) + digest.busy
            return result
        evaluate_all_certs(s.db_path, repo)
        evaluate_renewal_window(
            s.db_path, repo, s.renewal_window_days, closed_sent=closed_sent,
        )
        self._resolve_closed_alerts(config, closed_sent)
        self._digest_deadline = monotonic() + ALERT_CYCLE_BUDGET_SECONDS
        return process_pending(
            repo,
            config.alert_cfg,
            webhook_config=config.webhook_cfg,
            budget_seconds=ALERT_CYCLE_BUDGET_SECONDS,
        )

    @staticmethod
    def _run_digest(
        config: _JobConfig,
        kind: Any,
        cadence_days: int,
        *,
        deadline: float,
        stop_event: threading.Event | None,
    ) -> Any:
        from datetime import UTC, datetime

        from cert_watch.alerting.digest.engine import DigestEngine
        from cert_watch.alerting.transports.base import Transport
        from cert_watch.alerting.transports.smtp import SmtpTransport
        from cert_watch.alerting.transports.webhook import WebhookTransport
        from cert_watch.database.digest_deliveries import digest_period_key

        transports: list[Transport] = []
        if config.alert_cfg is not None:
            transports.append(SmtpTransport(config.alert_cfg))
        if config.webhook_cfg is not None:
            transports.append(WebhookTransport(config.webhook_cfg))
        now = datetime.now(UTC)
        engine = DigestEngine(
            config.settings.db_path,
            transports,
            budget_seconds=max(0.0, deadline - monotonic()),
            clock=lambda: now,
            stop_event=stop_event,
        )
        return engine.run(
            kind,
            digest_period_key(kind.name, cadence_days, now=now),
        )

    @staticmethod
    def _resolve_closed_alerts(config: _JobConfig, alerts: list[Any]) -> None:
        if not alerts or config.webhook_cfg is None:
            return
        try:
            from cert_watch.alerting.resolve import resolve_webhook_for_renewed_cert

            resolve_webhook_for_renewed_cert(
                config.settings.db_path,
                "",
                config.webhook_cfg,
                pending_alerts=alerts,
            )
        except Exception:
            logger.warning("closed alert incidents could not be resolved", exc_info=True)

    def maybe_run_weekly_digest(self) -> dict[str, Any]:
        from cert_watch.alerting.digest.orphan import OrphanDigestKind
        from cert_watch.alerting.digest.renewal import RenewalDigestKind

        config = self._snapshot()
        cadence_days = self._max_group_cadence(
            config.settings.db_path, default=7
        )
        from cert_watch.alerting.model import ALERT_CYCLE_BUDGET_SECONDS

        deadline = self._digest_deadline
        if deadline is None:
            deadline = monotonic() + ALERT_CYCLE_BUDGET_SECONDS
        try:
            renewal = self._run_digest(
                config,
                RenewalDigestKind(config.alert_cfg),
                cadence_days,
                deadline=deadline,
                stop_event=self.stop_event,
            )
            orphan = self._run_digest(
                config,
                OrphanDigestKind(config.alert_cfg),
                7,
                deadline=deadline,
                stop_event=self.stop_event,
            )
        except Exception:
            logger.exception("weekly digest failed")
            return {"sent": 0, "failed": 1, "deferred": 0}
        finally:
            self._digest_deadline = None
        return {
            "sent": renewal.sent + orphan.sent,
            "failed": renewal.failed + orphan.failed,
            "deferred": renewal.busy + orphan.busy,
        }

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
