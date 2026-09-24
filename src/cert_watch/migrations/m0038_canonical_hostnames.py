"""Migration 0038 — store every hostname in its canonical spelling.

``hosts(hostname, port)`` is unique and every per-endpoint join, the scope
check on an existing endpoint and ``event_log`` filtering compare hostnames
textually. Before this migration a name could be stored as it was typed, so
``VICTIM.example.test``, ``victim.example.test.`` and ``victim.example.test``
were three endpoints (#116 review). New rows are canonical from
:func:`cert_watch.host_validation.canonical_hostname`; this migration brings
the existing rows to the same form:

- ``hosts``: rows that canonicalize to one endpoint are collapsed onto the
  oldest row, the *survivor*. Which row is older proves nothing: an alias
  planted through the old bug can be the older row. So the rule does not
  depend on it:

  * Same scope (every row's case-folded tag set is equal): one team spelled
    its own endpoint twice. The survivor keeps its values and takes a losing
    row's where it had none; notes are concatenated; the certificates'
    tags and manual alert-group assignments are kept.
  * Different scopes: **fail closed**, and nothing follows the rows' age.
    Tags become the intersection of the rows' tag sets (disjoint: no tags,
    so the endpoint is visible to administrators only until one re-tags
    it). Every other field (owner name, e-mail and Slack, notes, threshold,
    scan interval, expected issuers, STARTTLS mode, renewal status and
    method, runbook) is kept only where every row agrees and is otherwise
    reset to the column's declared default, so a planted row can neither
    route alerts to its owner nor set the victim's thresholds, cadence,
    issuers or notes. A cleared owner means the endpoint's alerts reach only
    alert groups matching its (intersected) tags and the global recipients,
    as for any host without an owner. The per-certificate tags of every
    colliding spelling's certificates are cleared, manual alert-group
    assignments are kept only for groups assigned on every colliding row's
    certificates, and the recipient snapshots (``extra_recipients``,
    ``routing``) of still-deliverable alerts on those certificates are
    emptied, so dispatch cannot mail a planted owner from a queued alert
    either; sent and closed alerts keep their history.

  Every value dropped is recorded in full in an ``audit_log`` row
  (``host.merge_alias``, visible on the audit page) and a WARNING log line
  at startup, so an administrator can re-apply it deliberately; the upgrade
  notes say to look for them.
- Legacy numeric IPv4 spellings (``010.010.010.010``, ``8.8.2056``,
  ``0x08080808``) are read as the resolver reads them and canonicalized to
  the dotted quad, so they collide with and collapse onto the canonical row.
- ``certificates``, ``scan_history``, ``cert_history``, ``scan_posture``,
  ``alerts.hostname`` and ``event_log`` payload hostnames are rewritten to
  the canonical spelling in one pass per table, through a temporary alias
  mapping table; rows are kept.
- ``alerts.dedupe_key`` and ``rule_firings.dedupe_key`` embed the hostname
  as one field of ``prefix:hostname:port:fingerprint[:...]``; only that field
  is rewritten, so the next evaluation dedupes against the existing condition
  instead of firing it again. Two open alerts that collapse to one key keep
  the older one open and cancel the newer; two ``rule_firings`` rows merge.
- ``audit_log`` detail is left as written: it records what was submitted.

A stored hostname that is not valid at all is left untouched and logged.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

from cert_watch.host_validation import canonical_hostname, legacy_ipv4_dotted_quad
from cert_watch.tags import format_tags, parse_tags

MIGRATION_ID = "0038"
DESCRIPTION = "canonicalize stored hostnames (IDNA A-label, lower-case, compressed IP literal)"

logger = logging.getLogger("cert_watch.migrations")

_HOSTNAME_TABLES = ("certificates", "scan_history", "cert_history", "scan_posture", "alerts")
_ALIAS_TABLE = "temp._m0038_alias"

# Same-scope collisions: survivor fields filled from a losing row when empty.
_FILLABLE = (
    "owner_name", "owner_email", "owner_slack", "renewal_method", "runbook_url",
    "expected_issuers", "starttls_mode", "threshold_days", "scan_interval_hours",
)
# Cross-scope collisions: every field but these is kept only when every row
# agrees, else reset to the column's declared default.
_IDENTITY_FIELDS = ("id", "hostname", "port", "added_at", "tags")
_OPEN = ("pending", "sending")
_EMPTY_ROUTING = json.dumps(
    {"version": 1, "recipients": [], "groups": []}, separators=(",", ":"), sort_keys=True
)

# ``prefix:hostname:port:fingerprint[:suffix...]`` — the hostname is the only
# field that may contain colons (IPv6), so it is found by anchoring on the port
# (digits or ``*``) and the fingerprint (64 hex, or a 32-36 character row id
# for a certificate without one). Keys for uploaded certificates
# (``prefix:cert:<id>...``) do not match and are left alone.
_ENDPOINT_KEY = re.compile(
    r"^(?P<prefix>[a-z_]+):(?P<host>.+?):(?P<port>\d{1,5}|\*)"
    r":(?P<fp>[0-9a-fA-F]{64}|[0-9a-fA-F-]{32,36})(?P<rest>:.*)?$"
)


def _canonical(hostname: object) -> str | None:
    if not isinstance(hostname, str) or not hostname:
        return None
    try:
        return canonical_hostname(hostname)
    except ValueError:
        # The app refuses these now; stored ones mean what the resolver made
        # of them, so they collapse onto the dotted-quad row.
        return legacy_ipv4_dotted_quad(hostname.rstrip("."))


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _tag_set(row: dict[str, Any]) -> set[str]:
    return {t.casefold() for t in parse_tags(row.get("tags") or "")}


def _same_scope(members: list[dict[str, Any]]) -> bool:
    first = _tag_set(members[0])
    return all(_tag_set(m) == first for m in members[1:])


def _same_scope_fields(survivor: dict[str, Any], losers: list[dict[str, Any]]) -> dict[str, Any]:
    """One team, two spellings: fill what the survivor lacks, join the notes."""
    fields: dict[str, Any] = {}
    for name in _FILLABLE:
        if name not in survivor:
            continue
        current = survivor.get(name)
        if current is None or current == "":
            value = next(
                (o.get(name) for o in losers if o.get(name) not in (None, "")), None
            )
            if value is not None:
                fields[name] = value
    if "notes" in survivor:
        notes: list[str] = []
        for row in (survivor, *losers):
            note = (row.get("notes") or "").strip()
            if note and note not in notes:
                notes.append(note)
        joined = "\n".join(notes)
        if joined != (survivor.get("notes") or ""):
            fields["notes"] = joined
    return fields


def _column_defaults(conn: sqlite3.Connection, table: str) -> dict[str, Any]:
    """Declared DEFAULT of every column (``None`` when there is none)."""
    defaults: dict[str, Any] = {}
    for row in conn.execute(f"PRAGMA table_info({table})"):
        raw = row[4]
        if raw is None or str(raw).upper() == "NULL":
            defaults[row[1]] = None
        elif len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
            defaults[row[1]] = raw[1:-1]
        else:
            try:
                defaults[row[1]] = int(raw)
            except ValueError:
                defaults[row[1]] = raw
    return defaults


def _cross_scope_fields(
    members: list[dict[str, Any]], defaults: dict[str, Any]
) -> dict[str, Any]:
    """Different teams claim one endpoint: keep only what every row agrees on.

    Nothing depends on which row is older. Tags are the intersection; every
    other field is kept when identical across all rows and otherwise reset
    to the column's declared default (``NULL`` for a threshold or interval,
    the empty string for text, ``pending`` for the renewal status).
    """
    survivor = members[0]
    common = set.intersection(*(_tag_set(m) for m in members))
    kept_tags = [t for t in parse_tags(survivor.get("tags") or "") if t.casefold() in common]
    fields: dict[str, Any] = {}
    if format_tags(kept_tags) != (survivor.get("tags") or ""):
        fields["tags"] = format_tags(kept_tags)
    for name in survivor:
        if name in _IDENTITY_FIELDS:
            continue
        values = {m.get(name) for m in members}
        agreed = values.pop() if len(values) == 1 else defaults.get(name)
        if agreed != survivor.get(name):
            fields[name] = agreed
    return fields


def _endpoint_cert_ids(conn: sqlite3.Connection, row: dict[str, Any]) -> list[str]:
    return [
        r[0] for r in conn.execute(
            "SELECT id FROM certificates WHERE hostname = ? AND port = ?",
            (row["hostname"], row["port"]),
        )
    ]


def _quarantine_certificates(
    conn: sqlite3.Connection, tables: set[str], members: list[dict[str, Any]]
) -> dict[str, Any]:
    """Cross-scope collision: clear per-certificate tags on every colliding
    spelling's certificates and keep only alert-group assignments present on
    every member's certificates. Returns what was dropped, for the audit row."""
    dropped: dict[str, Any] = {
        "certificate_tags": {}, "alert_group_assignments": [], "alert_recipient_snapshots": {},
    }
    if "certificates" not in tables:
        return dropped
    has_tags = "tags" in _columns(conn, "certificates")
    per_member: list[tuple[list[str], set[str]]] = []
    for member in members:
        cert_ids = _endpoint_cert_ids(conn, member)
        groups: set[str] = set()
        if "alert_group_certs" in tables and cert_ids:
            placeholders = ",".join("?" * len(cert_ids))
            groups = {
                r[0] for r in conn.execute(
                    f"SELECT group_id FROM alert_group_certs WHERE cert_id IN ({placeholders})",
                    cert_ids,
                )
            }
        per_member.append((cert_ids, groups))
    common_groups = set.intersection(*(g for _, g in per_member)) if per_member else set()
    for cert_ids, _groups in per_member:
        for cert_id in cert_ids:
            if has_tags:
                tags = conn.execute(
                    "SELECT tags FROM certificates WHERE id = ?", (cert_id,)
                ).fetchone()[0]
                if tags:
                    dropped["certificate_tags"][cert_id] = tags
                    conn.execute("UPDATE certificates SET tags = '' WHERE id = ?", (cert_id,))
            if "alert_group_certs" in tables:
                for row in conn.execute(
                    "SELECT group_id FROM alert_group_certs WHERE cert_id = ?", (cert_id,)
                ).fetchall():
                    if row[0] not in common_groups:
                        dropped["alert_group_assignments"].append(
                            {"cert_id": cert_id, "group_id": row[0]}
                        )
                        conn.execute(
                            "DELETE FROM alert_group_certs WHERE cert_id = ? AND group_id = ?",
                            (cert_id, row[0]),
                        )
    # Queued alerts carry an immutable recipient snapshot taken when they
    # fired; a deliverable one would still mail a planted owner after the
    # host row was cleared. Empty the snapshots of every still-deliverable
    # alert on these certificates; sent and closed alerts keep their history.
    all_cert_ids = [cid for cert_ids, _ in per_member for cid in cert_ids]
    if all_cert_ids and "alerts" in tables and "routing" in _columns(conn, "alerts"):
        placeholders = ",".join("?" * len(all_cert_ids))
        rows = conn.execute(
            f"SELECT id, extra_recipients, routing FROM alerts WHERE cert_id IN ({placeholders})"
            f" AND status IN ({','.join('?' * len(_OPEN))})"
            " AND (COALESCE(extra_recipients, '[]') != '[]' OR COALESCE(routing, ?) != ?)",
            [*all_cert_ids, *_OPEN, _EMPTY_ROUTING, _EMPTY_ROUTING],
        ).fetchall()
        for row in rows:
            dropped["alert_recipient_snapshots"][row["id"]] = {
                "extra_recipients": row["extra_recipients"], "routing": row["routing"],
            }
            conn.execute(
                "UPDATE alerts SET extra_recipients = '[]', routing = ? WHERE id = ?",
                (_EMPTY_ROUTING, row["id"]),
            )
    return dropped


def _report_merge(
    conn: sqlite3.Connection, tables: set[str], canon: str, port: int,
    survivor: dict[str, Any], losers: list[dict[str, Any]], *,
    same_scope: bool, applied: dict[str, Any], dropped: dict[str, Any],
) -> None:
    spellings = [survivor["hostname"], *(o["hostname"] for o in losers)]
    kind = "same scope" if same_scope else "DIFFERENT SCOPES, failed closed"
    logger.warning(
        "migration 0038: hosts %s are one endpoint %s:%s (%s); kept row %s, removed %s;"
        " survivor now %s; the removed rows and every dropped tag, owner and"
        " assignment are in audit_log action host.merge_alias for an administrator"
        " to re-apply deliberately",
        spellings, canon, port, kind, survivor["id"], [o["id"] for o in losers], applied,
    )
    if "audit_log" not in tables:
        return
    detail = {
        "hostname": canon,
        "port": port,
        "same_scope": same_scope,
        "survivor_before": {k: v for k, v in survivor.items() if k != "id"},
        "survivor_changes": applied,
        "removed": [dict(o) for o in losers],
        "dropped_from_certificates": dropped,
    }
    conn.execute(
        "INSERT INTO audit_log (id, ts, actor, action, target_type, target_id, detail, source_ip)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        (
            str(uuid.uuid4()), datetime.now(UTC).isoformat(), "migration:0038",
            "host.merge_alias", "host", survivor["id"], json.dumps(detail, default=str),
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
        survivor, *losers = members
        if losers:
            same_scope = _same_scope(members)
            if same_scope:
                applied = _same_scope_fields(survivor, losers)
                dropped: dict[str, Any] = {
                "certificate_tags": {}, "alert_group_assignments": [],
                "alert_recipient_snapshots": {},
            }
            else:
                applied = _cross_scope_fields(members, _column_defaults(conn, "hosts"))
                dropped = _quarantine_certificates(conn, tables, members)
            conn.execute(
                f"DELETE FROM hosts WHERE id IN ({','.join('?' * len(losers))})",
                [o["id"] for o in losers],
            )
            assignments = "".join(f", {name} = ?" for name in applied)
            conn.execute(
                f"UPDATE hosts SET hostname = ?{assignments} WHERE id = ?",
                [canon, *applied.values(), survivor["id"]],
            )
            _report_merge(
                conn, tables, canon, port, survivor, losers,
                same_scope=same_scope, applied=applied, dropped=dropped,
            )
        elif survivor["hostname"] != canon:
            conn.execute(
                "UPDATE hosts SET hostname = ? WHERE id = ?", (canon, survivor["id"])
            )


def _aliases(conn: sqlite3.Connection, tables: set[str]) -> dict[str, str]:
    """Every stored spelling that differs from its canonical form."""
    seen: set[str] = set()
    for table in ("hosts", *_HOSTNAME_TABLES):
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
    """Rewrite the hostname field of an endpoint-bound dedupe key, nothing else."""
    match = _ENDPOINT_KEY.match(key)
    if match is None or match["host"] not in aliases:
        return key
    return (
        f"{match['prefix']}:{aliases[match['host']]}:{match['port']}:{match['fp']}"
        f"{match['rest'] or ''}"
    )


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


def _rewrite_hostname_columns(
    conn: sqlite3.Connection, tables: set[str], aliases: dict[str, str]
) -> None:
    """One UPDATE per table, joined to the alias map: each row is visited once
    however many spellings there are (the per-alias form scanned event_log
    once per alias, which does not fit an IIS startup window at fleet scale)."""
    conn.execute(f"DROP TABLE IF EXISTS {_ALIAS_TABLE}")
    conn.execute(
        f"CREATE TEMP TABLE {_ALIAS_TABLE.split('.', 1)[1]}"
        " (old TEXT PRIMARY KEY, new TEXT NOT NULL)"
    )
    conn.executemany(
        f"INSERT INTO {_ALIAS_TABLE} (old, new) VALUES (?, ?)", list(aliases.items())
    )
    try:
        for table in _HOSTNAME_TABLES:
            if table not in tables or "hostname" not in _columns(conn, table):
                continue
            conn.execute(
                f"UPDATE {table} SET hostname = (SELECT new FROM {_ALIAS_TABLE} a"
                f" WHERE a.old = {table}.hostname)"
                f" WHERE hostname IN (SELECT old FROM {_ALIAS_TABLE})"
            )
        if "event_log" in tables:
            conn.execute(
                "UPDATE event_log SET payload = json_set(payload, '$.hostname',"
                f" (SELECT new FROM {_ALIAS_TABLE} a"
                " WHERE a.old = json_extract(event_log.payload, '$.hostname')))"
                " WHERE json_valid(payload)"
                f" AND json_extract(payload, '$.hostname') IN (SELECT old FROM {_ALIAS_TABLE})"
            )
    finally:
        conn.execute(f"DROP TABLE IF EXISTS {_ALIAS_TABLE}")


def upgrade(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    tables = _tables(conn)
    if "hosts" not in tables:
        return
    aliases = _aliases(conn, tables)
    _canonicalize_hosts(conn, tables)
    if not aliases:
        return
    _rewrite_hostname_columns(conn, tables, aliases)
    if "alerts" in tables and "dedupe_key" in _columns(conn, "alerts"):
        _rekey_alerts(conn, aliases)
    if "rule_firings" in tables:
        _rekey_rule_firings(conn, aliases)
    logger.info("migration 0038: canonicalized %d stored hostname spelling(s)", len(aliases))
