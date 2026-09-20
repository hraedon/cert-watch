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
so a trigger and its later resolve always agree. Existing rows are backfilled
with their current ``cert_id``: every released version deletes an alert with
its certificate row (the rewrite-and-carry behaviour of #57 ships in the same
release as this migration), so for every pre-existing alert the row it sits
on IS the row it fired against — exactly the id its open incident was keyed
with.

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
BACKFILL_SQL = (
    "UPDATE alerts SET trigger_cert_id = cert_id WHERE trigger_cert_id IS NULL"
)
# The statements an operator runs to apply this migration by hand (the ALTER,
# the backfill, then the ledger row).
MANUAL_SQL = (
    COLUMN_SQL,
    BACKFILL_SQL,
    "INSERT INTO schema_version (id, description, applied_at) "
    f"VALUES ('{MIGRATION_ID}', '{DESCRIPTION}', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
)


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "trigger_cert_id" not in cols:
        conn.execute(COLUMN_SQL)
    conn.execute(BACKFILL_SQL)
    conn.commit()
