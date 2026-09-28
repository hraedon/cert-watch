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
        "failure_expected_fingerprint": "TEXT",
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
                     AND r.effect IN ('applied','no_change')) AS accepted_failure_at,
                  a.new_fingerprint,h.hostname,h.port,
                  a.failure_attempt_id,a.failure_cleared_at,
                  a.verified_fingerprint,a.success_received_at
           FROM renewal_attempts a
           JOIN hosts h ON h.id=a.host_id
           ORDER BY a.host_id,a.opened_seq"""
    ).fetchall()
    by_host: dict[str, list[tuple[object, ...]]] = {}
    for row in rows:
        by_host.setdefault(str(row[1]), []).append(row)

    for attempts in by_host.values():
        # A prior direct invocation already reconstructed this endpoint. Keep
        # its runtime state, especially an operator's later manual clear.
        if any(row[11] is not None for row in attempts):
            continue
        active_origin: str | None = None
        active_reported_at: str | None = None
        active_baseline: str | None = None
        active_expected: str | None = None
        carriers: list[str] = []
        for row in attempts:
            row_baseline = (
                str(row[4]).lower()
                if row[4]
                else None
            )
            failure_at = str(row[7]) if row[7] else None
            evidence_cutoff = failure_at or str(row[5])
            successor_at = (
                _first_successor_evidence(
                    conn,
                    hostname=str(row[9]),
                    port=int(str(row[10])),
                    reported_at=active_reported_at,
                    baseline=active_baseline,
                    expected=active_expected,
                    before=evidence_cutoff,
                )
                if active_origin
                else None
            )
            if successor_at is not None:
                _clear_backfilled_condition(
                    conn, carriers, successor_at
                )
                active_origin = active_reported_at = active_baseline = active_expected = None
                carriers = []

            if active_origin is None and failure_at:
                active_origin = str(row[0])
                active_reported_at = failure_at
                active_baseline = row_baseline
                active_expected = str(row[8]).lower() if row[8] else None

            if active_origin is None:
                continue
            attempt_id = str(row[0])
            conn.execute(
                """UPDATE renewal_attempts
                   SET failure_attempt_id=?,failure_reported_at=?,
                       failure_cleared_at=NULL,failure_expected_fingerprint=?,
                       rule_due_at=NULL
                   WHERE attempt_id=?""",
                (active_origin, active_reported_at, active_expected, attempt_id),
            )
            carriers.append(attempt_id)
            verified_at = _verified_successor_evidence(
                state=str(row[2]),
                verified_fingerprint=(str(row[13]) if row[13] else None),
                observed_at=(
                    str(row[14]) if row[14] else str(row[6] or row[5])
                ),
                baseline=active_baseline,
                expected=active_expected,
            )
            if verified_at is not None:
                _clear_backfilled_condition(conn, carriers, verified_at)
                active_origin = active_reported_at = active_baseline = active_expected = None
                carriers = []

        if active_origin is not None and carriers:
            successor_at = _first_successor_evidence(
                conn,
                hostname=str(attempts[-1][9]),
                port=int(str(attempts[-1][10])),
                reported_at=active_reported_at,
                baseline=active_baseline,
                expected=active_expected,
                before=None,
            )
            if successor_at is not None:
                _clear_backfilled_condition(conn, carriers, successor_at)
                continue
            # One first post-upgrade rule pass raises the unresolved condition
            # from its latest carrier, including a superseding current attempt.
            conn.execute(
                "UPDATE renewal_attempts SET rule_due_at=? WHERE attempt_id=?",
                (active_reported_at, carriers[-1]),
            )


def _first_successor_evidence(
    conn: sqlite3.Connection,
    *,
    hostname: str,
    port: int,
    reported_at: str | None,
    baseline: str | None,
    expected: str | None,
    before: str | None,
) -> str | None:
    """Return the first stored scan/lineage observation satisfying S4."""
    if reported_at is None or (baseline is None and expected is None):
        return None
    evidence = conn.execute(
        """SELECT fingerprint,observed_at FROM (
               SELECT lower(fingerprint_sha256) AS fingerprint,
                      scanned_at AS observed_at
               FROM cert_history
               WHERE hostname=? AND port=? AND scanned_at>?
               UNION ALL
               SELECT lower(COALESCE(c.fingerprint_sha256,next.old_fingerprint)),
                      cl.created_at
               FROM certificate_lineage cl
               LEFT JOIN certificates c ON c.id=cl.new_cert_id
               LEFT JOIN certificate_lineage next ON next.old_cert_id=cl.new_cert_id
               WHERE cl.hostname=? AND cl.port=? AND cl.created_at>?
           )
           WHERE fingerprint IS NOT NULL
             AND (? IS NULL OR observed_at<?)
           ORDER BY observed_at""",
        (hostname, port, reported_at, hostname, port, reported_at, before, before),
    ).fetchall()
    for fingerprint, observed_at in evidence:
        leaf = str(fingerprint).lower()
        if expected is not None:
            matches = leaf == expected and (baseline is None or leaf != baseline)
        else:
            matches = baseline is not None and leaf != baseline
        if matches:
            return str(observed_at)
    return None


def _verified_successor_evidence(
    *,
    state: str,
    verified_fingerprint: str | None,
    observed_at: str,
    baseline: str | None,
    expected: str | None,
) -> str | None:
    """Use S4's durable verified result even when its leaf predates failure."""
    if state != "verified" or verified_fingerprint is None:
        return None
    leaf = verified_fingerprint.lower()
    if baseline is not None and leaf == baseline:
        return None
    if expected is not None and leaf != expected:
        return None
    if baseline is None and expected is None:
        return None
    return observed_at


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
