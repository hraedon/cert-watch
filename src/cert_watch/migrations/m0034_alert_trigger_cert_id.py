"""Migration 0034 — remember which certificate row an alert fired against (#62).

PagerDuty incidents are keyed by a dedup key derived from the certificate row
id. Since #57 an unchanged rescan rewrites the leaf row under a new id and
carries its alerts forward, so by the time a genuine renewal resolves the
incident, the carried alert sits on a row id PagerDuty never saw: the resolve
keyed on the new row id no longer matches the open incident and is silently
discarded.

``trigger_cert_id`` persistently records the row id the alert was created
against — the id the trigger event's dedup key was built from — and survives
every row rewrite. Resolves key on it instead of the alert's current row id,
so a trigger and its later resolve always agree. Existing rows get ``NULL``
and fall back to ``cert_id``, which preserves the pre-migration keying for
already-open incidents.

Manual application is documented in UPGRADING.md and uses ``MANUAL_SQL`` below,
which is the same statement the runner executes plus the ledger row it would
record. Applying only the ``ALTER`` by hand is also fine: this upgrade is
idempotent and startup then records the ledger row itself.
"""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0034"
DESCRIPTION = "add trigger_cert_id to alerts for stable resolve keying (#62)"
COLUMN_SQL = "ALTER TABLE alerts ADD COLUMN trigger_cert_id TEXT"
# The two statements an operator runs to apply this migration by hand.
MANUAL_SQL = (
    COLUMN_SQL,
    "INSERT INTO schema_version (id, description, applied_at) "
    f"VALUES ('{MIGRATION_ID}', '{DESCRIPTION}', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
)


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "trigger_cert_id" not in cols:
        conn.execute(COLUMN_SQL)
    conn.commit()
