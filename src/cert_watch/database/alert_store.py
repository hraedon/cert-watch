"""Persistence for every alert lifecycle transition.

Keeping these writes together makes the lease guards reviewable.  Other
database modules may update orthogonal alert data (for example ``read`` or a
certificate foreign key), but status, attempts, backoff, and leases change
only here.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cert_watch.database.connection import _connect, _iso
from cert_watch.database.schema import init_schema

if TYPE_CHECKING:
    from cert_watch.database.repo import Alert

logger = logging.getLogger("cert_watch.database.alert_store")


class AlertStore:
    def __init__(self, db_path: str | Path, *, initialize: bool = True) -> None:
        self.db_path = Path(db_path)
        if initialize:
            init_schema(self.db_path)

    def enqueue(
        self,
        alert: Alert,
        *,
        conn: sqlite3.Connection | None = None,
        lifetime: bool = False,
    ) -> str | None:
        """Atomically queue an alert unless its dedupe condition already exists.

        ``lifetime`` is used for expiry thresholds, which never fire twice for
        the same fingerprint/type/threshold even after the certificate closes.
        Other rules may fire again after their earlier row has ``closed_at``.
        """
        alert_id = alert.id or str(uuid.uuid4())
        routing = alert.routing or {
            "version": 1,
            "recipients": list(alert.extra_recipients),
            "groups": [],
        }
        alert.routing = routing
        alert.extra_recipients = list(routing.get("recipients", alert.extra_recipients))
        duplicate_predicate = "1 = 0"
        duplicate_params: tuple[Any, ...] = ()
        if alert.dedupe_key:
            duplicate_predicate = (
                "dedupe_key = ?" if lifetime else "dedupe_key = ? AND closed_at IS NULL"
            )
            duplicate_params = (alert.dedupe_key,)
        params = (
            alert_id, alert.cert_id, alert.alert_type, alert.status, alert.message,
            alert.threshold_days, json.dumps(alert.extra_recipients), _iso(alert.created_at),
            _iso(alert.sent_at) if alert.sent_at else None, alert.error_message,
            alert.hostname, alert.subject, alert.trigger_cert_id or alert.cert_id,
            alert.dedupe_key, _iso(alert.closed_at) if alert.closed_at else None,
            json.dumps(routing, separators=(",", ":"), sort_keys=True),
            *duplicate_params,
        )
        sql = f"""INSERT INTO alerts
            (id, cert_id, alert_type, status, message, threshold_days,
             extra_recipients, created_at, sent_at, error_message, hostname,
             subject, trigger_cert_id, dedupe_key, closed_at, routing)
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE {duplicate_predicate})"""

        def execute(active_conn: sqlite3.Connection) -> bool:
            try:
                cursor = active_conn.execute(sql, params)
            except sqlite3.IntegrityError:
                # The partial unique index is the final arbiter when two rule
                # evaluators race between their NOT EXISTS checks.
                return False
            return cursor.rowcount == 1

        if conn is not None:
            inserted = execute(conn)
        else:
            with _connect(self.db_path) as active_conn:
                inserted = execute(active_conn)
                active_conn.commit()
        if not inserted:
            return None
        alert.id = alert_id
        return alert_id

    def close_keys(
        self,
        dedupe_keys: set[str],
        *,
        now: datetime | None = None,
        reason: str = "condition closed",
        conn: sqlite3.Connection | None = None,
    ) -> list[Alert]:
        """Close conditions and return sent rows needing incident resolves.

        Pending rows become cancelled. A live claimed row is deliberately not
        touched; a later evaluation closes it after its lease holder settles.
        """
        if not dedupe_keys:
            return []
        current = now or datetime.now(UTC)
        placeholders = ",".join("?" for _ in dedupe_keys)
        keys = tuple(sorted(dedupe_keys))

        def execute(active_conn: sqlite3.Connection) -> list[Alert]:
            rows = active_conn.execute(
                f"""SELECT * FROM alerts
                    WHERE dedupe_key IN ({placeholders}) AND closed_at IS NULL
                      AND (status != 'sending' OR lease_expires_at IS NULL
                           OR lease_expires_at < ?)""",
                (*keys, _iso(current)),
            ).fetchall()
            active_conn.execute(
                f"""UPDATE alerts SET
                         closed_at = ?,
                         status = CASE WHEN status IN ('pending', 'sending')
                                       THEN 'cancelled' ELSE status END,
                         error_message = CASE WHEN status IN ('pending', 'sending')
                                              THEN ? ELSE error_message END,
                         next_attempt_at = CASE WHEN status IN ('pending', 'sending')
                                                THEN NULL ELSE next_attempt_at END,
                         lease_owner = CASE WHEN status IN ('pending', 'sending')
                                            THEN NULL ELSE lease_owner END,
                         lease_expires_at = CASE WHEN status IN ('pending', 'sending')
                                                 THEN NULL ELSE lease_expires_at END,
                         deferred_since = CASE WHEN status IN ('pending', 'sending')
                                               THEN NULL ELSE deferred_since END
                    WHERE dedupe_key IN ({placeholders}) AND closed_at IS NULL
                      AND (status != 'sending' OR lease_expires_at IS NULL
                           OR lease_expires_at < ?)""",
                (_iso(current), reason, *keys, _iso(current)),
            )
            from cert_watch.database.repo import SqliteAlertRepository
            return [
                SqliteAlertRepository._row_to_alert(row)
                for row in rows if row["status"] == "sent"
            ]

        if conn is not None:
            return execute(conn)
        with _connect(self.db_path) as active_conn:
            result = execute(active_conn)
            active_conn.commit()
        return result

    def close_for_cert_ids(
        self,
        cert_ids: list[str],
        *,
        conn: sqlite3.Connection,
        now: datetime | None = None,
        reason: str = "certificate condition closed",
    ) -> list[Alert]:
        if not cert_ids:
            return []
        placeholders = ",".join("?" for _ in cert_ids)
        current = now or datetime.now(UTC)
        rows = conn.execute(
            f"""SELECT * FROM alerts
                WHERE cert_id IN ({placeholders}) AND closed_at IS NULL
                  AND (status != 'sending' OR lease_expires_at IS NULL
                       OR lease_expires_at < ?)""",
            (*cert_ids, _iso(current)),
        ).fetchall()
        conn.execute(
            f"""UPDATE alerts SET
                     closed_at = ?,
                     status = CASE WHEN status IN ('pending', 'sending')
                                   THEN 'cancelled' ELSE status END,
                     error_message = CASE WHEN status IN ('pending', 'sending')
                                          THEN ? ELSE error_message END,
                     next_attempt_at = CASE WHEN status IN ('pending', 'sending')
                                            THEN NULL ELSE next_attempt_at END,
                     lease_owner = CASE WHEN status IN ('pending', 'sending')
                                        THEN NULL ELSE lease_owner END,
                     lease_expires_at = CASE WHEN status IN ('pending', 'sending')
                                             THEN NULL ELSE lease_expires_at END,
                     deferred_since = CASE WHEN status IN ('pending', 'sending')
                                           THEN NULL ELSE deferred_since END
                WHERE cert_id IN ({placeholders}) AND closed_at IS NULL
                  AND (status != 'sending' OR lease_expires_at IS NULL
                       OR lease_expires_at < ?)""",
            (_iso(current), reason, *cert_ids, _iso(current)),
        )
        from cert_watch.database.repo import SqliteAlertRepository
        return [
            SqliteAlertRepository._row_to_alert(row)
            for row in rows if row["status"] == "sent"
        ]

    def claim_rule_firing(
        self,
        dedupe_key: str,
        *,
        now: datetime,
        interval_seconds: int,
        suppression_keys: tuple[str, ...] = (),
    ) -> bool:
        """Atomically claim an event-only rule firing after its cooldown."""
        from datetime import timedelta

        cutoff = _iso(now - timedelta(seconds=interval_seconds))
        with _connect(self.db_path) as conn:
            if suppression_keys:
                placeholders = ",".join("?" for _ in suppression_keys)
                suppressed = conn.execute(
                    f"""SELECT 1 FROM rule_firings
                        WHERE dedupe_key IN ({placeholders}) AND last_fired_at > ?
                        LIMIT 1""",
                    (*suppression_keys, cutoff),
                ).fetchone()
                if suppressed is not None:
                    return False
            cursor = conn.execute(
                """INSERT INTO rule_firings
                       (dedupe_key, first_fired_at, last_fired_at, fire_count)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(dedupe_key) DO UPDATE SET
                       last_fired_at = excluded.last_fired_at,
                       fire_count = rule_firings.fire_count + 1
                   WHERE rule_firings.last_fired_at <= ?""",
                (dedupe_key, _iso(now), _iso(now), cutoff),
            )
            conn.commit()
        return cursor.rowcount == 1

    def claim(
        self,
        *,
        lease_owner: str,
        lease_expires_at: datetime,
        now: datetime,
        limit: int = 1000,
        scope_tags: tuple[str, ...] = (),
        ignore_backoff: bool = False,
    ) -> list[Alert]:
        """Atomically claim eligible pending rows and expired leases."""
        if not lease_owner:
            raise ValueError("lease_owner is required")
        if limit <= 0:
            return []

        pending_due = "a.next_attempt_at IS NULL OR a.next_attempt_at <= ?"
        due_params: list[Any] = []
        if ignore_backoff:
            pending_due = "1 = 1"
        else:
            due_params.append(_iso(now))

        joins = ""
        scope_clause = ""
        if scope_tags:
            from cert_watch.database.dashboard_helpers import _add_effective_tag_filter

            joins = (
                " JOIN certificates c ON c.id = a.cert_id"
                " JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port"
            )
            scope_clause, scope_params = _add_effective_tag_filter(
                "1=1", [], scope_tags, col_cert="c.tags", col_host="h.tags"
            )

        eligibility = (
            f"((a.status = 'pending' AND ({pending_due})) "
            "OR (a.status = 'sending' AND a.lease_expires_at < ?))"
        )
        params = [*due_params, _iso(now)]
        if scope_clause:
            eligibility += f" AND ({scope_clause})"
            params.extend(scope_params)
        params.append(limit)

        sql = f"""
            UPDATE alerts
            SET status = 'sending', lease_owner = ?, lease_expires_at = ?
            WHERE id IN (
                SELECT a.id FROM alerts AS a{joins}
                WHERE {eligibility}
                ORDER BY a.created_at, a.id
                LIMIT ?
            )
            RETURNING *
        """
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                sql,
                (lease_owner, _iso(lease_expires_at), *params),
            ).fetchall()
            conn.commit()

        from cert_watch.database.repo import SqliteAlertRepository

        return [SqliteAlertRepository._row_to_alert(row) for row in rows]

    def renew_lease(
        self,
        alert_ids: list[str],
        *,
        lease_owner: str,
        lease_expires_at: datetime,
    ) -> set[str]:
        if not alert_ids:
            return set()
        placeholders = ",".join("?" for _ in alert_ids)
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                f"""UPDATE alerts SET lease_expires_at = ?
                    WHERE id IN ({placeholders})
                      AND status = 'sending' AND lease_owner = ?
                    RETURNING id""",
                (_iso(lease_expires_at), *alert_ids, lease_owner),
            ).fetchall()
            conn.commit()
        return {row["id"] for row in rows}

    def complete_sent(
        self,
        alert_id: str,
        *,
        lease_owner: str,
        attempts: int,
        now: datetime,
    ) -> bool:
        return self._complete(
            alert_id,
            lease_owner=lease_owner,
            status="sent",
            attempts=attempts,
            now=now,
            sent_at=now,
        )

    def complete_pending(
        self,
        alert_id: str,
        *,
        lease_owner: str,
        attempts: int,
        now: datetime,
        next_attempt_at: datetime | None,
        error_message: str | None = None,
        deferred_since: datetime | None = None,
        preserve_deferral: bool = False,
    ) -> bool:
        return self._complete(
            alert_id,
            lease_owner=lease_owner,
            status="pending",
            attempts=attempts,
            now=now,
            next_attempt_at=next_attempt_at,
            error_message=error_message,
            deferred_since=deferred_since,
            preserve_deferral=preserve_deferral,
        )

    def complete_failed(
        self,
        alert_id: str,
        *,
        lease_owner: str,
        attempts: int,
        now: datetime,
        failure_reason: str,
        error_message: str,
    ) -> bool:
        return self._complete(
            alert_id,
            lease_owner=lease_owner,
            status="failed",
            attempts=attempts,
            now=now,
            failure_reason=failure_reason,
            error_message=error_message,
        )

    def _complete(
        self,
        alert_id: str,
        *,
        lease_owner: str,
        status: str,
        attempts: int,
        now: datetime,
        sent_at: datetime | None = None,
        next_attempt_at: datetime | None = None,
        failure_reason: str | None = None,
        error_message: str | None = None,
        deferred_since: datetime | None = None,
        preserve_deferral: bool = False,
    ) -> bool:
        if status not in {"sent", "pending", "failed"}:
            raise ValueError(f"invalid completion status: {status}")
        if attempts < 0:
            raise ValueError("attempts cannot be negative")
        if preserve_deferral:
            deferral_sql = "deferred_since = COALESCE(deferred_since, ?)"
        else:
            deferral_sql = "deferred_since = ?"
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                f"""UPDATE alerts SET
                        status = ?, sent_at = ?, error_message = ?,
                        attempt_count = attempt_count + ?,
                        last_attempt_at = CASE WHEN ? > 0 THEN ? ELSE last_attempt_at END,
                        next_attempt_at = ?, failure_reason = ?,
                        lease_owner = NULL, lease_expires_at = NULL,
                        {deferral_sql}
                    WHERE id = ? AND status = 'sending' AND lease_owner = ?""",
                (
                    status,
                    _iso(sent_at) if sent_at else None,
                    error_message,
                    attempts,
                    attempts,
                    _iso(now),
                    _iso(next_attempt_at) if next_attempt_at else None,
                    failure_reason,
                    _iso(deferred_since) if deferred_since else None,
                    alert_id,
                    lease_owner,
                ),
            )
            conn.commit()
        if cursor.rowcount == 0:
            logger.warning(
                "Alert %s completion to %s ignored because lease %s was lost",
                alert_id,
                status,
                lease_owner,
            )
            return False
        return True

    def cancel(self, alert_id: str, *, reason: str | None = None) -> bool:
        now = datetime.now(UTC)
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE alerts SET status = 'cancelled', error_message = ?, closed_at = ?,
                       next_attempt_at = NULL, lease_owner = NULL,
                       lease_expires_at = NULL, deferred_since = NULL
                   WHERE id = ? AND status = 'pending'""",
                (reason, _iso(now), alert_id),
            )
            conn.commit()
        return cursor.rowcount == 1

    def operator_retry(self, alert_id: str, *, auth: Any) -> bool:
        from cert_watch.auth.scope import ensure_write_scope

        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT cert_id FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                return False
            ensure_write_scope(auth, self.db_path, cert_id=row["cert_id"])
            cursor = conn.execute(
                """UPDATE alerts SET status = 'pending', attempt_count = 0,
                       next_attempt_at = NULL, lease_owner = NULL, lease_expires_at = NULL,
                       failure_reason = NULL, error_message = NULL,
                       deferred_since = NULL, sent_at = NULL
                   WHERE id = ? AND status = 'failed' AND closed_at IS NULL""",
                (alert_id,),
            )
            conn.commit()
        return cursor.rowcount == 1

    def revive_legacy_expiry(self, alert_id: str) -> bool:
        """Queue one pre-lifecycle expiry failure if its leaf is still current."""
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE alerts SET status = 'pending', attempt_count = 0,
                       next_attempt_at = NULL, lease_owner = NULL,
                       lease_expires_at = NULL, failure_reason = NULL,
                       error_message = NULL, deferred_since = NULL, sent_at = NULL
                   WHERE id = ? AND status = 'failed'
                     AND failure_reason = 'legacy_failed'
                     AND alert_type IN ('expiry_warning', 'expired')
                     AND EXISTS (
                         SELECT 1 FROM certificates AS current
                         LEFT JOIN hosts AS host
                           ON host.hostname = current.hostname
                          AND host.port = current.port
                         WHERE current.id = alerts.cert_id
                           AND current.is_leaf = 1
                           AND COALESCE(host.renewal_status, 'pending') != 'renewed'
                           AND NOT EXISTS (
                               SELECT 1 FROM certificates AS successor
                               WHERE successor.replaces_cert_id = current.id
                           )
                     )""",
                (alert_id,),
            )
            conn.commit()
        return cursor.rowcount == 1

    def wake_configuration_deferrals(self, error_message: str) -> int:
        """Make no-channel deferrals eligible after a channel is configured."""
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE alerts SET next_attempt_at = NULL
                   WHERE status = 'pending' AND attempt_count = 0
                     AND next_attempt_at IS NOT NULL AND error_message = ?""",
                (error_message,),
            )
            conn.commit()
        return cursor.rowcount

    def reset_pending_compat(self, alert_id: str) -> None:
        """Legacy repository reset; production operator retry is failed-only."""
        with _connect(self.db_path) as conn:
            conn.execute(
                """UPDATE alerts SET status = 'pending', error_message = NULL,
                       failure_reason = NULL, next_attempt_at = NULL,
                       lease_owner = NULL, lease_expires_at = NULL,
                       deferred_since = NULL, sent_at = NULL
                   WHERE id = ?""",
                (alert_id,),
            )
            conn.commit()

    # Compatibility helpers for callers that create test/history states without
    # participating in dispatch. Runtime delivery uses guarded completions.
    def set_sent(self, alert_id: str, *, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        with _connect(self.db_path) as conn:
            conn.execute(
                """UPDATE alerts SET status = 'sent', sent_at = ?,
                       next_attempt_at = NULL, lease_owner = NULL,
                       lease_expires_at = NULL, deferred_since = NULL
                   WHERE id = ?""",
                (_iso(current), alert_id),
            )
            conn.commit()

    def set_failed(self, alert_id: str, error_message: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                """UPDATE alerts SET status = 'failed', error_message = ?,
                       failure_reason = COALESCE(failure_reason, 'legacy'),
                       next_attempt_at = NULL, lease_owner = NULL,
                       lease_expires_at = NULL, deferred_since = NULL
                   WHERE id = ?""",
                (error_message, alert_id),
            )
            conn.commit()

    def note_pending_deferral(
        self, alert_id: str, when: datetime, *, restart: bool = False
    ) -> bool:
        assignment = "?" if restart else "COALESCE(deferred_since, ?)"
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                f"UPDATE alerts SET deferred_since = {assignment} "
                "WHERE id = ? AND status = 'pending'",
                (_iso(when), alert_id),
            )
            conn.commit()
        return cursor.rowcount == 1
