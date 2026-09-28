"""Migration 0045 — add explicit API-key bindings for renewal reports."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0045"
DESCRIPTION = "add explicit API-key bindings for renewal reports"


def upgrade(conn: sqlite3.Connection) -> None:
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    if "api_keys" not in tables:
        # Reconcile historical feature-branch databases whose migration ledger
        # claimed 0015 although that table was never created (the same class
        # of database repaired by migration 0035).
        from cert_watch.migrations.m0015_api_keys import upgrade as create_api_keys

        create_api_keys(conn)
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(api_keys)")
    }
    if {"binding", "bound_tags"} <= columns:
        return

    # Rebuild rather than ALTER so ``binding`` has no database default. The
    # application must always supply it for a new row; only this migration
    # assigns ``all`` implicitly to keys that already exist.
    conn.execute(
        """CREATE TABLE api_keys_0045 (
            id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            scope TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            binding TEXT NOT NULL CHECK (binding IN ('all','tags')),
            bound_tags TEXT NOT NULL DEFAULT ''
        )"""
    )
    conn.execute(
        """INSERT INTO api_keys_0045
           (id, key_hash, name, scope, created_at, last_used_at, revoked,
            binding, bound_tags)
           SELECT id, key_hash, name, scope, created_at, last_used_at, revoked,
                  'all', ''
           FROM api_keys"""
    )
    conn.execute("DROP TABLE api_keys")
    conn.execute("ALTER TABLE api_keys_0045 RENAME TO api_keys")
