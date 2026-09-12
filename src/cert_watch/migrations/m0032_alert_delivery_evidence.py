"""Migration 0032: append-only alert delivery observations."""

import sqlite3

from cert_watch.database.delivery_evidence import DELIVERY_EVENTS_DDL


def upgrade(conn: sqlite3.Connection) -> None:
    conn.executescript(DELIVERY_EVENTS_DDL)
    conn.commit()
