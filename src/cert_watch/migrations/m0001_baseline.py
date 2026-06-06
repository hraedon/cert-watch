"""Baseline migration 0001 — no-op marker.

This migration is a no-op because `ensure_base()` creates all tables
and columns that existed before the migration system was introduced.
Its purpose is to establish a known baseline id in `schema_version`
so that subsequent migrations can order themselves correctly.

For existing databases (upgraded from a pre-migration version), the
runner stamps 0001 automatically via `_stamp_baseline()`.
For fresh databases, `ensure_base()` creates the full schema and
`run_pending_migrations()` records 0001 as already applied.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    # No-op: tables and columns already created by ensure_base().
    pass
