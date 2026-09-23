"""Migration 0032: append-only alert delivery observations."""

import sqlite3

from cert_watch.database.delivery_evidence import DELIVERY_EVENTS_STATEMENTS


def upgrade(conn: sqlite3.Connection) -> None:
    for statement in DELIVERY_EVENTS_STATEMENTS:
        conn.execute(statement)
