"""Migration 0040 — record when an alert became ``failed``.

``/api/health`` and ``/metrics`` count alerts that gave up in the last 24
hours. They used ``last_attempt_at``, but an alert can give up without an
attempt (the bounded evidence deferral fails it with zero attempts), which
left ``last_attempt_at`` empty and hid the failure (#113). ``failed_at`` is
set on every transition to ``failed``. Existing failed rows are backfilled
with their last attempt. A failed row with no attempt is dated to the
migration itself: such an alert may have given up moments before the upgrade
(1.0.2 recorded no time for a zero-attempt give-up), and counting it as
failing now for the next 24 hours is the loud side of not knowing, where its
creation time -- possibly weeks old -- would hide it (#113 review).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

MIGRATION_ID = "0040"
DESCRIPTION = "record when an alert became failed"


def upgrade(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    if "failed_at" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN failed_at TEXT")
    since = "COALESCE(last_attempt_at, ?)" if "last_attempt_at" in columns else "?"
    conn.execute(
        f"UPDATE alerts SET failed_at = {since} WHERE status = 'failed' AND failed_at IS NULL",
        (datetime.now(UTC).isoformat(),),
    )
