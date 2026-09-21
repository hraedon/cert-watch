"""Transactional note and tag mutations used by application services."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from cert_watch.database.connection import _iso


def update_host_notes(conn: sqlite3.Connection, host_id: str, notes: str) -> bool:
    cursor = conn.execute("UPDATE hosts SET notes = ? WHERE id = ?", (notes, host_id))
    return cursor.rowcount > 0


def update_host_tags(conn: sqlite3.Connection, host_id: str, tags: str) -> bool:
    cursor = conn.execute("UPDATE hosts SET tags = ? WHERE id = ?", (tags, host_id))
    return cursor.rowcount > 0


def update_certificate_tags(conn: sqlite3.Connection, cert_id: str, tags: str) -> bool:
    cursor = conn.execute(
        "UPDATE certificates SET tags = ?, updated_at = ? WHERE id = ?",
        (tags, _iso(datetime.now(UTC)), cert_id),
    )
    return cursor.rowcount > 0
