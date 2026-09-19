"""Migration 0033 — record when delivery of an alert was first deferred (#38).

``process_pending`` defers an alert when the delivery-evidence store refuses
the write that must precede a send. Until now that deferral left no mark on
the row, so nothing could bound it honestly: ``created_at`` is the wrong
clock, because ``evaluate_all_certs`` resets a failed alert to pending with
its original ``created_at``, and one transient lock on an old alert would
read as a days-long outage.

``deferred_since`` is the right clock. It is set at the first deferred cycle,
kept across later deferrals, and cleared whenever the alert leaves that state
(an attempt was recorded, or the alert was sent, failed or reset). Existing
rows get ``NULL``; the migration modifies no data.

Manual application is documented in UPGRADING.md and uses ``MANUAL_SQL`` below,
which is the same statement the runner executes plus the ledger row it would
record. Applying only the ``ALTER`` by hand is also fine: this upgrade is
idempotent and startup then records the ledger row itself.
"""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0033"
DESCRIPTION = "add deferred_since to alerts for bounded evidence deferral (#38)"
COLUMN_SQL = "ALTER TABLE alerts ADD COLUMN deferred_since TEXT"
# The two statements an operator runs to apply this migration by hand.
MANUAL_SQL = (
    COLUMN_SQL,
    "INSERT INTO schema_version (id, description, applied_at) "
    f"VALUES ('{MIGRATION_ID}', '{DESCRIPTION}', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
)


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "deferred_since" not in cols:
        conn.execute(COLUMN_SQL)
    conn.commit()
