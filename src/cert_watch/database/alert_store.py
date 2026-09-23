"""Persistence for every alert lifecycle transition.

Keeping these writes together makes the lease guards reviewable.  Other
database modules may update orthogonal alert data (for example ``read`` or a
certificate foreign key), but status, attempts, backoff, and leases change
only here.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cert_watch.database.connection import _connect, _iso
from cert_watch.database.schema import init_schema

if TYPE_CHECKING:
    from cert_watch.database.repo import Alert

logger = logging.getLogger("cert_watch.database.alert_store")


class AlertStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        init_schema(self.db_path)

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
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE alerts SET status = 'cancelled', error_message = ?,
                       next_attempt_at = NULL, lease_owner = NULL,
                       lease_expires_at = NULL, deferred_since = NULL
                   WHERE id = ? AND status = 'pending'""",
                (reason, alert_id),
            )
            conn.commit()
        return cursor.rowcount == 1

    def operator_retry(self, alert_id: str) -> bool:
        with _connect(self.db_path) as conn:
            cursor = conn.execute(
                """UPDATE alerts SET status = 'pending', attempt_count = 0,
                       next_attempt_at = NULL, lease_owner = NULL, lease_expires_at = NULL,
                       failure_reason = NULL, error_message = NULL,
                       deferred_since = NULL, sent_at = NULL
                   WHERE id = ? AND status = 'failed'""",
                (alert_id,),
            )
            conn.commit()
        return cursor.rowcount == 1

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
    ) -> None:
        assignment = "?" if restart else "COALESCE(deferred_since, ?)"
        with _connect(self.db_path) as conn:
            conn.execute(
                f"UPDATE alerts SET deferred_since = {assignment} "
                "WHERE id = ? AND status = 'pending'",
                (_iso(when), alert_id),
            )
            conn.commit()
