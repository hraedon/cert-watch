"""Migration 0027 — add starttls_mode to hosts (STARTTLS scanning).

Empty string = implicit/wrapped TLS (the historical behavior). A non-empty
value (e.g. ``smtp``, ``imap``, ``ldap``) tells the scanner to negotiate a
STARTTLS upgrade for that protocol before reading the certificate.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(hosts)")}
    if "starttls_mode" not in cols:
        conn.execute(
            "ALTER TABLE hosts ADD COLUMN starttls_mode TEXT NOT NULL DEFAULT ''"
        )
    conn.commit()
