"""Migration 0030 — merge per-certificate notes into host notes (V1 adjudication).

Implements the UI content-model decision recorded in UI-INVENTORY.md (V1,
decided 2026-08-14): notes are ONE host-scoped concept. Every non-empty
``certificates.notes`` value is concatenated into the matching ``hosts.notes``
(matched on hostname+port), then the column is dropped.

Certificates with notes but no matching host row (uploaded files on hosts that
were never added for scanning) cannot be merged. Those notes are preserved in
the pre-migration backup the runner takes (``backup=True``) and listed in a
warning log; they are dropped from the live schema with the column.
"""

from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger("cert_watch.migrations.0030")


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(certificates)").fetchall()}
    if "notes" not in cols:
        return  # fresh database: nothing to merge or drop

    rows = conn.execute(
        "SELECT id, subject, hostname, port, notes FROM certificates "
        "WHERE notes IS NOT NULL AND TRIM(notes) != ''"
    ).fetchall()

    merged = 0
    orphans: list[tuple[str, str, str]] = []
    for cert_id, subject, hostname, port, notes in rows:
        host = (
            conn.execute(
                "SELECT id, notes FROM hosts WHERE hostname = ? AND port = ?",
                (hostname, port),
            ).fetchone()
            if hostname
            else None
        )
        if host is None:
            orphans.append((cert_id, subject, notes))
            continue
        existing = host[1] or ""
        note = notes.strip()
        if note and note not in existing:
            combined = f"{existing.rstrip()}\n\n{note}" if existing.strip() else note
            conn.execute("UPDATE hosts SET notes = ? WHERE id = ?", (combined, host[0]))
        merged += 1

    if orphans:
        logger.warning(
            "migration 0030: %d certificate note(s) have no matching host and "
            "cannot be merged into hosts.notes; they are preserved only in the "
            "pre-migration backup: %s",
            len(orphans),
            [(cid, subj) for cid, subj, _ in orphans],
        )
    if rows:
        logger.info("migration 0030: merged %d certificate note(s) into hosts.notes", merged)

    conn.execute("ALTER TABLE certificates DROP COLUMN notes")
    conn.commit()
