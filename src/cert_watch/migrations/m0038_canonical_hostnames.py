"""Migration 0038 — store every hostname in its canonical spelling.

``hosts(hostname, port)`` is unique and every per-endpoint join, the scope
check on an existing endpoint and ``event_log`` filtering compare hostnames
textually. Before this migration a name could be stored as it was typed, so
``VICTIM.example.test``, ``victim.example.test.`` and ``victim.example.test``
were three endpoints (#116 review). New rows are canonical from
:func:`cert_watch.host_validation.canonical_hostname`; this migration brings
the existing rows to the same form:

- ``hosts``: rows that canonicalize to one endpoint are merged into the
  oldest row. Tags are the union; owner, renewal, runbook, issuer and
  STARTTLS fields keep the oldest row's value where it has one and take the
  other row's otherwise; notes are concatenated. Every merge is logged and
  written to ``audit_log`` with the full merged rows, so nothing is lost
  silently.
- ``certificates``, ``scan_history``, ``cert_history``, ``scan_posture`` and
  ``alerts.hostname`` are rewritten to the canonical spelling; their rows are
  kept (the next scan reconciles a doubled current leaf).
- ``event_log`` payload hostnames are rewritten in place.
- ``alerts.dedupe_key`` and ``rule_firings.dedupe_key`` embed the hostname;
  they are rewritten so the next evaluation dedupes against the existing
  condition instead of firing it again. Two open alerts that collapse to one
  key keep the older one open and cancel the newer; two ``rule_firings`` rows
  are merged (earliest first, latest last, summed count).
- ``audit_log`` detail is left as written: it records what was submitted.

A stored hostname that is not valid at all is left untouched and logged.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

from cert_watch.host_validation import canonical_hostname
from cert_watch.tags import format_tags, merge_tags

MIGRATION_ID = "0038"
DESCRIPTION = "canonicalize stored hostnames (IDNA A-label, lower-case, compressed IP literal)"

logger = logging.getLogger("cert_watch.migrations")

_HOSTNAME_TABLES = ("certificates", "scan_history", "cert_history", "scan_posture", "alerts")
_TEXT_FIELDS = (
    "owner_name", "owner_email", "owner_slack", "renewal_method", "runbook_url",
    "expected_issuers", "starttls_mode",
)
_NUMERIC_FIELDS = ("threshold_days", "scan_interval_hours")
_OPEN = ("pending", "sending")


def _canonical(hostname: object) -> str | None:
    if not isinstance(hostname, str) or not hostname:
        return None
    try:
        return canonical_hostname(hostname)
    except ValueError:
        return None


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _merged_fields(keeper: dict[str, Any], others: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "tags": format_tags(merge_tags(keeper.get("tags"), *(o.get("tags") for o in others))),
    }
    for name in _TEXT_FIELDS:
        if name not in keeper:
            continue
        value = keeper.get(name) or ""
        if not value:
            value = next((o.get(name) for o in others if o.get(name)), "")
        merged[name] = value
    for name in _NUMERIC_FIELDS:
        if name not in keeper:
            continue
        value = keeper.get(name)
        if value is None:
            value = next((o.get(name) for o in others if o.get(name) is not None), None)
        merged[name] = value
    if "notes" in keeper:
        notes: list[str] = []
        for row in (keeper, *others):
            note = (row.get("notes") or "").strip()
            if note and note not in notes:
                notes.append(note)
        merged["notes"] = "\n".join(notes)
    return merged


def _report_merge(
    conn: sqlite3.Connection, tables: set[str], canon: str, port: int,
    keeper: dict[str, Any], others: list[dict[str, Any]], merged: dict[str, Any],
) -> None:
    spellings = [keeper["hostname"], *(o["hostname"] for o in others)]
    logger.warning(
        "migration 0038: hosts %s are one endpoint %s:%s; merged into %s (kept %s)",
        spellings, canon, port, keeper["id"], [o["id"] for o in others],
    )
    if "audit_log" not in tables:
        return
    detail = {
        "hostname": canon,
        "port": port,
        "kept": {k: v for k, v in keeper.items() if k != "id"},
        "merged": [dict(o) for o in others],
        "result": merged,
    }
    conn.execute(
        "INSERT INTO audit_log (id, ts, actor, action, target_type, target_id, detail, source_ip)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        (
            str(uuid.uuid4()), datetime.now(UTC).isoformat(), "migration:0038",
            "host.merge_alias", "host", keeper["id"], json.dumps(detail, default=str),
        ),
    )


def _canonicalize_hosts(conn: sqlite3.Connection, tables: set[str]) -> None:
    rows = [dict(r) for r in conn.execute("SELECT * FROM hosts ORDER BY added_at, rowid")]
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows:
        canon = _canonical(row["hostname"])
        if canon is None:
            logger.warning(
                "migration 0038: host %s has an invalid hostname %r; left as stored",
                row["id"], row["hostname"],
            )
            continue
        groups.setdefault((canon, row["port"]), []).append(row)
    for (canon, port), members in groups.items():
        keeper, *others = members
        if others:
            merged = _merged_fields(keeper, others)
            conn.execute(
                f"DELETE FROM hosts WHERE id IN ({','.join('?' * len(others))})",
                [o["id"] for o in others],
            )
            assignments = ", ".join(f"{name} = ?" for name in merged)
            conn.execute(
                f"UPDATE hosts SET hostname = ?, {assignments} WHERE id = ?",
                [canon, *merged.values(), keeper["id"]],
            )
            _report_merge(conn, tables, canon, port, keeper, others, merged)
        elif keeper["hostname"] != canon:
            conn.execute(
                "UPDATE hosts SET hostname = ? WHERE id = ?", (canon, keeper["id"])
            )


def _aliases(conn: sqlite3.Connection, tables: set[str]) -> dict[str, str]:
    """Every stored spelling that differs from its canonical form."""
    seen: set[str] = set()
    for table in _HOSTNAME_TABLES:
        if table in tables and "hostname" in _columns(conn, table):
            seen.update(
                r[0] for r in conn.execute(
                    f"SELECT DISTINCT hostname FROM {table} WHERE hostname IS NOT NULL"
                )
            )
    if "event_log" in tables:
        seen.update(
            r[0] for r in conn.execute(
                "SELECT DISTINCT json_extract(payload, '$.hostname') FROM event_log"
                " WHERE json_valid(payload)"
                " AND json_type(payload, '$.hostname') = 'text'"
            )
        )
    aliases: dict[str, str] = {}
    for spelling in seen:
        canon = _canonical(spelling)
        if canon is None:
            if spelling:
                logger.warning(
                    "migration 0038: stored hostname %r is invalid; left as stored", spelling
                )
        elif canon != spelling:
            aliases[spelling] = canon
    return aliases


def _rekey(key: str, aliases: dict[str, str]) -> str:
    # Keys are ``prefix:hostname:port:...``; the hostname is bounded by colons
    # on both sides, which also holds for an IPv6 literal.
    for old, new in sorted(aliases.items(), key=lambda kv: -len(kv[0])):
        key = key.replace(f":{old}:", f":{new}:")
    return key


def _rekey_alerts(conn: sqlite3.Connection, aliases: dict[str, str]) -> None:
    now = datetime.now(UTC).isoformat()
    rows = conn.execute(
        "SELECT id, dedupe_key, status, created_at FROM alerts WHERE dedupe_key IS NOT NULL"
        " ORDER BY created_at, id"
    ).fetchall()
    for row in rows:
        new_key = _rekey(row["dedupe_key"], aliases)
        if new_key == row["dedupe_key"]:
            continue
        if row["status"] in _OPEN:
            clash = conn.execute(
                "SELECT id, created_at FROM alerts WHERE dedupe_key = ? AND id != ?"
                f" AND status IN ({','.join('?' * len(_OPEN))})",
                (new_key, row["id"], *_OPEN),
            ).fetchone()
            if clash is not None:
                # One open row per condition: the older stays open.
                loser = row["id"] if (row["created_at"], row["id"]) > (
                    clash["created_at"], clash["id"]
                ) else clash["id"]
                conn.execute(
                    "UPDATE alerts SET status = 'cancelled', closed_at = ?, lease_owner = NULL,"
                    " lease_expires_at = NULL, next_attempt_at = NULL, deferred_since = NULL"
                    " WHERE id = ?",
                    (now, loser),
                )
                logger.warning(
                    "migration 0038: open alerts %s and %s are one condition %s;"
                    " cancelled %s", row["id"], clash["id"], new_key, loser,
                )
        conn.execute("UPDATE alerts SET dedupe_key = ? WHERE id = ?", (new_key, row["id"]))


def _rekey_rule_firings(conn: sqlite3.Connection, aliases: dict[str, str]) -> None:
    rows = conn.execute(
        "SELECT dedupe_key, first_fired_at, last_fired_at, fire_count FROM rule_firings"
    ).fetchall()
    for row in rows:
        new_key = _rekey(row["dedupe_key"], aliases)
        if new_key == row["dedupe_key"]:
            continue
        existing = conn.execute(
            "SELECT 1 FROM rule_firings WHERE dedupe_key = ?", (new_key,)
        ).fetchone()
        if existing is None:
            conn.execute(
                "UPDATE rule_firings SET dedupe_key = ? WHERE dedupe_key = ?",
                (new_key, row["dedupe_key"]),
            )
            continue
        conn.execute(
            "UPDATE rule_firings SET first_fired_at = MIN(first_fired_at, ?),"
            " last_fired_at = MAX(last_fired_at, ?), fire_count = fire_count + ?"
            " WHERE dedupe_key = ?",
            (row["first_fired_at"], row["last_fired_at"], row["fire_count"], new_key),
        )
        conn.execute("DELETE FROM rule_firings WHERE dedupe_key = ?", (row["dedupe_key"],))


def upgrade(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    tables = _tables(conn)
    if "hosts" not in tables:
        return
    aliases = _aliases(conn, tables)
    hosts_aliases = {
        r[0]: c for r in conn.execute("SELECT DISTINCT hostname FROM hosts")
        if (c := _canonical(r[0])) is not None and c != r[0]
    }
    aliases.update(hosts_aliases)
    _canonicalize_hosts(conn, tables)
    if not aliases:
        return
    new_then_old = [(new, old) for old, new in aliases.items()]
    for table in _HOSTNAME_TABLES:
        if table not in tables or "hostname" not in _columns(conn, table):
            continue
        conn.executemany(
            f"UPDATE {table} SET hostname = ? WHERE hostname = ?", new_then_old
        )
    if "event_log" in tables:
        conn.executemany(
            "UPDATE event_log SET payload = json_set(payload, '$.hostname', ?)"
            " WHERE json_valid(payload) AND json_extract(payload, '$.hostname') = ?",
            new_then_old,
        )
    if "alerts" in tables and "dedupe_key" in _columns(conn, "alerts"):
        _rekey_alerts(conn, aliases)
    if "rule_firings" in tables:
        _rekey_rule_firings(conn, aliases)
    logger.info("migration 0038: canonicalized %d stored hostname spelling(s)", len(aliases))
