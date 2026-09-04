"""Migration 0031 — merge per-certificate notes into host notes (V1 adjudication).

Implements the UI content-model decision recorded in UI-INVENTORY.md (V1,
decided 2026-08-14): notes are ONE host-scoped concept. Every non-empty
``certificates.notes`` value is concatenated into the matching ``hosts.notes``
(matched on hostname+port). The column is dropped when every note can be
merged.

Certificates with notes but no matching host row (uploaded files on hosts that
were never added for scanning) cannot be merged. To avoid destructive data
loss, their notes remain live in the deprecated column and are listed in a
warning log. The column's existing default supports current inserts that no
longer name it.
"""

from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger("cert_watch.migrations.0031")


def upgrade(conn: sqlite3.Connection) -> None:
    # Feature databases may record 0029/0030 under the UI branch's old
    # numbering, which makes the canonical digest/role migrations look
    # applied. Re-run both idempotent additions at this unambiguous id so all
    # previously runnable feature databases converge on the complete schema.
    from cert_watch.migrations.m0029_digest_delivery_ledger import (
        upgrade as ensure_digest_delivery_ledger,
    )
    from cert_watch.migrations.m0030_role_tag_tiers import (
        upgrade as ensure_role_tag_tiers,
    )

    ensure_digest_delivery_ledger(conn)
    ensure_role_tag_tiers(conn)

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
        # Leave only notes that could not be represented in the host model in
        # the deprecated column.
        conn.execute("UPDATE certificates SET notes = '' WHERE id = ?", (cert_id,))
        merged += 1

    if orphans:
        logger.warning(
            "migration 0031: %d certificate note(s) have no matching host and "
            "cannot be merged into hosts.notes; preserving them in the live "
            "deprecated certificates.notes column: %s",
            len(orphans),
            [(cid, subj) for cid, subj, _ in orphans],
        )
    if rows:
        logger.info("migration 0031: merged %d certificate note(s) into hosts.notes", merged)

    if not orphans:
        conn.execute("ALTER TABLE certificates DROP COLUMN notes")
    conn.commit()
