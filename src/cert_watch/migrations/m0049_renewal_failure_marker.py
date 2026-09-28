"""Migration 0049 — durable renewal failure conditions and rule wakes (#118 S5)."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0049"
DESCRIPTION = "record renewal failure conditions for alerts and digests"


def upgrade(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(renewal_attempts)")
    }
    additions = {
        "failure_attempt_id": "TEXT",
        "failure_reported_at": "TEXT",
        "failure_cleared_at": "TEXT",
        "rule_due_at": "TEXT",
    }
    for name, definition in additions.items():
        if name not in columns:
            conn.execute(
                f"ALTER TABLE renewal_attempts ADD COLUMN {name} {definition}"
            )
    _backfill_failure_conditions(conn)
    # 0048 could leave pre-existing not-deployed attempts without the transition
    # timestamp.  Their accepted success time (or, for historical rows, the
    # attempt receive time) is the durable fallback used by the digest.
    conn.execute(
        """UPDATE renewal_attempts
           SET raised_at=COALESCE(success_received_at,received_at)
           WHERE state='not_deployed' AND raised_at IS NULL"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_attempts_failure_condition "
        "ON renewal_attempts(failure_attempt_id,failure_cleared_at) "
        "WHERE failure_attempt_id IS NOT NULL"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_attempts_rule_due "
        "ON renewal_attempts(rule_due_at) WHERE rule_due_at IS NOT NULL"
    )


def _backfill_failure_conditions(conn: sqlite3.Connection) -> None:
    """Reconstruct endpoint-cycle failures from the ordered S4 attempt ledger."""
    rows = conn.execute(
        """SELECT a.attempt_id,a.host_id,a.state,a.opened_seq,
                  a.baseline_fingerprint,a.received_at,a.last_check_at,
                  (SELECT MIN(r.received_at) FROM renewal_reports r
                   WHERE r.attempt_id=a.attempt_id
                     AND r.outcome='failed'
                     AND r.effect IN ('applied','no_change')) AS accepted_failure_at
           FROM renewal_attempts a
           ORDER BY a.host_id,a.opened_seq"""
    ).fetchall()
    by_host: dict[str, list[tuple[object, ...]]] = {}
    for row in rows:
        by_host.setdefault(str(row[1]), []).append(row)

    for attempts in by_host.values():
        active_origin: str | None = None
        active_reported_at: str | None = None
        active_baseline: str | None = None
        carriers: list[str] = []
        for row in attempts:
            row_baseline = (
                str(row[4]).lower()
                if row[4]
                else None
            )
            successor = bool(
                active_origin
                and active_baseline is not None
                and row_baseline is not None
                and row_baseline != active_baseline
            )
            if successor:
                _clear_backfilled_condition(
                    conn, carriers, str(row[5])
                )
                active_origin = active_reported_at = active_baseline = None
                carriers = []

            failure_at = row[7]
            if active_origin is None and failure_at:
                active_origin = str(row[0])
                active_reported_at = str(failure_at)
                active_baseline = row_baseline

            if active_origin is None:
                continue
            attempt_id = str(row[0])
            conn.execute(
                """UPDATE renewal_attempts
                   SET failure_attempt_id=?,failure_reported_at=?,
                       failure_cleared_at=NULL,rule_due_at=NULL
                   WHERE attempt_id=?""",
                (active_origin, active_reported_at, attempt_id),
            )
            carriers.append(attempt_id)

            if row[2] == "verified":
                cleared_at = str(row[6] or row[5])
                _clear_backfilled_condition(conn, carriers, cleared_at)
                active_origin = active_reported_at = active_baseline = None
                carriers = []

        if active_origin is not None and carriers:
            # One first post-upgrade rule pass raises the unresolved condition
            # from its latest carrier, including a superseding current attempt.
            conn.execute(
                "UPDATE renewal_attempts SET rule_due_at=? WHERE attempt_id=?",
                (active_reported_at, carriers[-1]),
            )


def _clear_backfilled_condition(
    conn: sqlite3.Connection, attempt_ids: list[str], cleared_at: str
) -> None:
    if not attempt_ids:
        return
    placeholders = ",".join("?" for _ in attempt_ids)
    conn.execute(
        f"""UPDATE renewal_attempts
            SET failure_cleared_at=?,rule_due_at=NULL
            WHERE attempt_id IN ({placeholders})""",
        (cleared_at, *attempt_ids),
    )
