"""Migration 0042 — an internal record of certificate renewals (#115).

A link to a certificate that has since been renewed opens the certificate
that replaced it. That used to be worked out from the event log, which is the
wrong source: events age out after the retention period (30 days by
default, while a 90-day certificate is usually renewed at about 60), an
event type disabled under Settings → Event stream is not stored at all, and
a payload can name the wrong endpoint. ``certificate_lineage`` records each
renewal instead -- the old id, the new id and the endpoint -- written by the
scan in the same transaction as the new certificate row. It is not part of
the event stream, not configurable and not purged by event retention.

It is kept for good: one small row per renewal. Rows whose new certificate
was later deleted are inert -- a stale link only resolves to a certificate
that still exists.

Backfill, idempotent:

1. every stored leaf whose ``replaces_cert_id`` names another id;
2. retained ``cert_renewed`` events whose new certificate is a stored leaf
   on the event's endpoint, or is itself the old id of a lineage row already
   recorded on that endpoint (so a chain of two or more renewals is kept
   while its events are). Events that don't lead to a stored certificate on
   their own endpoint are skipped.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime

MIGRATION_ID = "0042"
DESCRIPTION = "add certificate_lineage, an internal record of renewals"

logger = logging.getLogger("cert_watch.migrations")


def _canonical(hostname: str) -> str:
    from cert_watch.host_validation import canonical_hostname

    try:
        return canonical_hostname(hostname)
    except ValueError:
        return hostname


def _port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 65536 else None
    if isinstance(value, str) and value.isascii() and value.isdigit():
        port = int(value)
        return port if 0 < port < 65536 else None
    return None


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS certificate_lineage (
               old_cert_id TEXT NOT NULL,
               new_cert_id TEXT NOT NULL,
               hostname TEXT NOT NULL,
               port INTEGER NOT NULL,
               created_at TEXT NOT NULL,
               PRIMARY KEY (old_cert_id, new_cert_id)
           )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_certificate_lineage_new "
        "ON certificate_lineage(new_cert_id)"
    )
    now = datetime.now(UTC).isoformat()

    from_rows = conn.execute(
        """INSERT OR IGNORE INTO certificate_lineage
               (old_cert_id, new_cert_id, hostname, port, created_at)
           SELECT replaces_cert_id, id, hostname, port, created_at FROM certificates
           WHERE is_leaf = 1 AND replaces_cert_id IS NOT NULL AND replaces_cert_id != id
             AND hostname IS NOT NULL AND hostname != '' AND port IS NOT NULL"""
    ).rowcount

    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    from_events = 0
    if "event_log" in tables:
        field = "CASE WHEN json_valid(payload) THEN json_extract(payload, '$.{}') END"
        events = conn.execute(
            f"SELECT {field.format('replaced_cert_id')} AS old_id,"
            f" {field.format('cert_id')} AS new_id,"
            f" {field.format('hostname')} AS hostname, {field.format('port')} AS port,"
            " timestamp FROM event_log WHERE event_type = 'cert_renewed' ORDER BY id DESC"
        ).fetchall()
        leaves = {
            str(r[0]): (_canonical(str(r[1])), r[2])
            for r in conn.execute(
                "SELECT id, hostname, port FROM certificates "
                "WHERE is_leaf = 1 AND hostname IS NOT NULL AND hostname != ''"
            )
        }
        pending = []
        for old_id, new_id, hostname, port, ts in events:
            parsed = _port(port)
            if not old_id or not new_id or old_id == new_id or not isinstance(hostname, str):
                continue
            if not hostname or parsed is None:
                continue
            pending.append((str(old_id), str(new_id), _canonical(hostname), parsed, ts or now))
        # Grow the set of known chain members from the stored leaves outward.
        known = {
            (str(r[0]), _canonical(str(r[1])), r[2])
            for r in conn.execute("SELECT old_cert_id, hostname, port FROM certificate_lineage")
        }
        changed = True
        while changed and pending:
            changed = False
            for item in list(pending):
                old_id, new_id, hostname, port, ts = item
                reaches = leaves.get(new_id) == (hostname, port) or (
                    (new_id, hostname, port) in known
                )
                if not reaches:
                    continue
                pending.remove(item)
                added = conn.execute(
                    "INSERT OR IGNORE INTO certificate_lineage "
                    "(old_cert_id, new_cert_id, hostname, port, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (old_id, new_id, hostname, port, ts),
                ).rowcount
                from_events += added
                known.add((old_id, hostname, port))
                changed = True
    logger.info(
        "migration 0042: recorded %d renewal(s) from stored certificates and %d "
        "from retained renewal events",
        from_rows,
        from_events,
    )
