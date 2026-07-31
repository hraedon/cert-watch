"""Scheduler context — encapsulates the scan/alert/digest cycle logic.

Extracted from app.py lifespan closures so dependencies are explicit and
mutable state is encapsulated rather than threaded via nonlocal.
"""

from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cert_watch.config import Settings
from cert_watch.database import SqliteAlertRepository, SqliteHostRepository, get_write_lock
from cert_watch.scan import DeferredPostCommit, _evaluate_posture, scan_host, store_scanned
from cert_watch.scheduler import run_scan_now

logger = logging.getLogger("cert_watch.scheduler_context")


@dataclass
class SchedulerContext:
    settings: Settings
    alert_cfg: Any
    webhook_cfg: Any
    _expiry_digest_week: tuple[int, int] = field(default_factory=lambda: (0, 0))
    _weekly_digest_day: int = 0
    _deferred_post_commit: list[DeferredPostCommit] = field(default_factory=list)

    def __post_init__(self) -> None:
        now = _dt.datetime.now(_dt.UTC)
        self._weekly_digest_day = now.weekday()
        iso = now.isocalendar()
        self._expiry_digest_week = (iso[0], iso[1])

    def scan_all(self) -> dict[str, Any]:
        s = self.settings
        host_repo = SqliteHostRepository(s.db_path)
        all_hosts = host_repo.list_all()
        hosts = [(h.hostname, h.port) for h in all_hosts]
        starttls_by_host = {
            (h.hostname, h.port): h.starttls_mode for h in all_hosts
        }
        self._deferred_post_commit = []

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
            store_fn=self._store_with_lock,
            settings=s,
        )
        from cert_watch.scan import _execute_deferred_post_commit
        for deferred in self._deferred_post_commit:
            _execute_deferred_post_commit(deferred)
        return result

    def _store_with_lock(self, result: Any) -> str:
        s = self.settings
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
                webhook_config=self.webhook_cfg,
                _deferred=deferred,
                _posture_eval=posture_eval,
            )
        if leaf_id:
            self._deferred_post_commit.append(deferred)
        return leaf_id

    def run_alerts(self) -> dict[str, Any]:
        import datetime as _dt

        from cert_watch.alerts import (
            evaluate_all_certs,
            evaluate_renewal_window,
            process_pending,
            send_expiry_digest,
        )

        s = self.settings
        repo = SqliteAlertRepository(s.db_path)
        if s.alert_digest_only:
            evaluate_all_certs(s.db_path, repo, urgent_only=True)
            evaluate_renewal_window(s.db_path, repo, s.renewal_window_days)
            result = process_pending(repo, self.alert_cfg, webhook_config=self.webhook_cfg)
            iso = _dt.datetime.now(_dt.UTC).isocalendar()
            this_week = (iso[0], iso[1])
            if this_week != self._expiry_digest_week:
                self._expiry_digest_week = this_week
                delivered = send_expiry_digest(
                    s.db_path, self.alert_cfg, webhook_config=self.webhook_cfg,
                    cadence_days=self._max_group_cadence(s.db_path),
                )
                result["sent"] = result.get("sent", 0) + (1 if delivered else 0)
                result["failed"] = result.get("failed", 0) + (0 if delivered else 1)
            return result
        evaluate_all_certs(s.db_path, repo)
        evaluate_renewal_window(s.db_path, repo, s.renewal_window_days)
        return process_pending(repo, self.alert_cfg, webhook_config=self.webhook_cfg)

    def _weekly_digest(self) -> None:
        from cert_watch.digest import send_renewal_digest

        s = self.settings
        send_renewal_digest(
            s.db_path, self.alert_cfg, self.webhook_cfg,
            cadence_days=self._max_group_cadence(s.db_path, default=7),
        )

    def maybe_run_weekly_digest(self) -> dict[str, Any]:
        import datetime as _dt

        today = _dt.datetime.now(_dt.UTC).weekday()
        if today != self._weekly_digest_day:
            self._weekly_digest_day = today
            try:
                self._weekly_digest()
            except Exception:
                logger.exception("weekly renewal digest failed")
        return {"sent": 0, "failed": 0}

    def maintenance(self) -> None:
        from cert_watch.audit import purge_old_audit
        from cert_watch.database import purge_old_alerts, purge_old_history
        from cert_watch.database.drift import purge_old_scan_history
        from cert_watch.events import purge_old_events

        s = self.settings
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
