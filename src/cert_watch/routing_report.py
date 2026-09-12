"""Offline routing inspection of a consolidated, current-schema DB snapshot.

The source is opened only through SQLite's read-only immutable URI. This is an
offline-input contract, not a way to obtain a consistent backup of a live DB.
Only routing columns enter a disposable database used by the actual resolvers.
Neither configuration/credential loading nor alert evaluation/delivery runs.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
from os import stat_result
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from cert_watch import alerts
from cert_watch.database.connection import _connect, _thread_cache


class RoutingReportError(ValueError):
    """The supplied file cannot be inspected under the offline snapshot contract."""


# Explicit source-column allowlist: do not copy tables with credentials, API
# keys, sessions or encrypted settings. Repository-only fields are filled below.
_ROUTING_COLUMNS = {
    "certificates": ("id", "subject", "hostname", "port", "tags", "is_leaf"),
    "hosts": ("hostname", "port", "tags", "owner_email", "threshold_days"),
    "alert_groups": ("id", "name", "recipients", "match_tags", "threshold_days"),
    "alert_group_certs": ("cert_id", "group_id"),
    "roles": ("id", "name", "email", "scope_tag", "alert_group_id"),
    "users": ("id", "username", "email", "role_id"),
}
_INTEGER_COLUMNS = {"port", "is_leaf", "threshold_days"}
_NULLABLE_COLUMNS = {
    ("certificates", "hostname"), ("certificates", "port"),
    ("hosts", "threshold_days"), ("alert_groups", "threshold_days"),
    ("roles", "alert_group_id"), ("users", "role_id"),
}
_REPOSITORY_DEFAULTS = {
    "roles": {
        "description": "", "permission_tier": "viewer",
        "created_at": "2000-01-01T00:00:00+00:00", "updated_at": "2000-01-01T00:00:00+00:00",
    },
    "users": {
        "password_hash": "", "created_at": "2000-01-01T00:00:00+00:00",
        "updated_at": "2000-01-01T00:00:00+00:00",
    },
}


def _refuse_companions(path: Path) -> None:
    if any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal")):
        raise RoutingReportError(
            "snapshot has WAL/SHM/journal companions; provide a completed standalone backup"
        )


def _fingerprint(path: Path) -> tuple[str, tuple[int, int, int, int]]:
    def identity(state: stat_result) -> tuple[int, int, int, int]:
        return state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns

    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if identity(before) != identity(after):
        raise RoutingReportError("snapshot changed while being read")
    return digest.hexdigest(), identity(after)


def _copy_routing_rows(source: Path, scratch: Path) -> str:
    # Registering the known migration IDs performs no migration or DB access.
    from cert_watch.migrations import registry as _registry  # noqa: F401
    from cert_watch.migrations.runner import get_migrations

    expected = {migration_id for migration_id, _, _ in get_migrations()}
    if sqlite3.sqlite_version_info < (3, 37, 0):
        raise RoutingReportError("routing inspection requires SQLite 3.37 or newer")
    uri = source.as_uri() + "?mode=ro&immutable=1"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as incoming:
        incoming.execute("PRAGMA query_only=ON")
        incoming.execute("BEGIN")
        # Views, virtual tables and generated columns can make an allowlisted
        # name evaluate an expression over credentials. Require ordinary stored
        # columns before reading any rows, including the migration ledger.
        table_types = {
            row[1]: row[2] for row in incoming.execute("PRAGMA main.table_list")
        }
        for table, columns in {**_ROUTING_COLUMNS, "schema_version": ("id",)}.items():
            if table_types.get(table) != "table":
                raise RoutingReportError("snapshot requires ordinary routing tables")
            column_kinds = {
                row[1]: row[6] for row in incoming.execute(f"PRAGMA main.table_xinfo({table})")
            }
            if any(column_kinds.get(column) != 0 for column in columns):
                raise RoutingReportError("snapshot requires ordinary stored routing columns")
        applied = {row[0] for row in incoming.execute("SELECT id FROM schema_version")}
        if applied != expected:
            raise RoutingReportError(
                f"snapshot schema does not match this build (expected through {max(expected)})"
            )
        with contextlib.closing(sqlite3.connect(scratch)) as outgoing:
            for table, columns in _ROUTING_COLUMNS.items():
                defaults = _REPOSITORY_DEFAULTS.get(table, {})
                fields = (*columns, *defaults)
                # All identifiers come from the fixed allowlist, never DB contents.
                outgoing.execute(f"CREATE TABLE {table} ({', '.join(fields)})")
                records = incoming.execute(f"SELECT {', '.join(columns)} FROM {table}")
                placeholders = ", ".join("?" for _ in fields)
                for row in records:
                    if any(
                        ((table, column) not in _NULLABLE_COLUMNS if value is None else
                         not isinstance(value, int if column in _INTEGER_COLUMNS else str))
                        for column, value in zip(columns, row, strict=True)
                    ):
                        raise RoutingReportError("snapshot has unsupported routing value types")
                    outgoing.execute(
                        f"INSERT INTO {table} VALUES ({placeholders})", (*row, *defaults.values()),
                    )
            outgoing.commit()
    return max(expected)


def _inspect_routing(scratch: Path) -> dict[str, Any]:
    matches: dict[str, list[str]] = {}
    recipients, _ = alerts._resolve_group_config(scratch, matched_groups=matches)
    _, owners = alerts._load_host_owner_maps(scratch)
    members = alerts._load_role_user_emails(scratch)
    with _connect(scratch) as conn:
        leaves = conn.execute(
            "SELECT id, hostname, port, subject FROM certificates WHERE is_leaf = 1 "
            "ORDER BY COALESCE(hostname, ''), COALESCE(port, 0), subject, id"
        ).fetchall()
        group_rows = conn.execute("SELECT id, name FROM alert_groups ORDER BY name, id").fetchall()
    certificates: list[dict[str, Any]] = []
    for leaf in leaves:
        owner = (
            owners.get((leaf["hostname"], leaf["port"]))
            if leaf["hostname"] and leaf["port"] else None
        )
        specific = alerts.resolve_cert_recipients(recipients.get(leaf["id"], []), owner, members)
        group_ids = sorted(matches.get(leaf["id"], []))
        certificates.append({
            "cert_id": leaf["id"], "hostname": leaf["hostname"] or "", "port": leaf["port"],
            "subject": leaf["subject"] or "", "group_ids": group_ids, "recipients": specific,
            "invalid_recipients": [address for address in specific
                                   if not alerts._validate_email(address)],
            "orphan": not specific, "multi_match": len(group_ids) > 1,
        })
    groups: list[dict[str, Any]] = []
    for group in group_rows:
        cert_ids = [cert["cert_id"] for cert in certificates if group["id"] in cert["group_ids"]]
        groups.append({
            "group_id": group["id"], "name": group["name"],
            "cert_ids": cert_ids, "matched_count": len(cert_ids),
        })
    return {
        "format_version": 1,
        "counts": {
            "leaf_certificates": len(certificates),
            "orphans": sum(cert["orphan"] for cert in certificates),
            "multi_match": sum(cert["multi_match"] for cert in certificates),
        },
        "certificates": certificates, "groups": groups,
        "scope": (
            "Specific routing addresses, not a delivery prediction. Orphans have zero specific "
            "recipients; global SMTP recipients may still receive them. Global configuration is "
            "not loaded. Delivery tries SMTP first, then one global webhook on failure/absence; "
            "stored group webhook URLs do not dispatch here. Invalid addresses are rejected at "
            "send time. Thresholds, renewal state and digest eligibility are not evaluated."
        ),
    }


def build_routing_report(snapshot: Path) -> dict[str, Any]:
    """Resolve routes without changing the input or creating source-side files.

    Require an offline, consolidated backup whose schema matches this build.
    Identity/hash checks catch observed changes, but cannot turn a raw copy of
    a running WAL database into a valid snapshot. Acquire backups separately.
    """
    try:
        source = snapshot.resolve(strict=True)
        if not source.is_file():
            raise RoutingReportError("snapshot must be a regular database file")
        _refuse_companions(source)
        before = _fingerprint(source)
        with TemporaryDirectory(prefix="cert-watch-routing-") as temp:
            scratch = Path(temp) / "routing.sqlite3"
            try:
                version = _copy_routing_rows(source, scratch)
                report = _inspect_routing(scratch)
            finally:
                # Release only this scratch connection, including on Windows;
                # callers' other cached DB handles remain valid.
                holder = _thread_cache()
                connection = holder.connections.pop(str(scratch), None)
                holder.meta.pop(str(scratch), None)
                if connection is not None:
                    connection.close()
        _refuse_companions(source)
        if _fingerprint(source) != before:
            raise RoutingReportError("snapshot changed during inspection")
        report["snapshot_sha256"] = before[0]
        report["schema_version"] = version
        return report
    except RoutingReportError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise RoutingReportError(
            "could not inspect snapshot; provide a readable, complete backup "
            "compatible with this build"
        ) from exc


def render_routing_report(report: dict[str, Any]) -> str:
    """Human-readable inventory; quote DB text so controls cannot affect a terminal."""
    def display(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    counts = report["counts"]
    lines = [
        "Cert-watch routing snapshot",
        f"SHA-256: {report['snapshot_sha256']} | schema: {report['schema_version']}",
        f"Leaf certificates: {counts['leaf_certificates']} | Orphans: {counts['orphans']} "
        f"| Multiple groups: {counts['multi_match']}",
        "", report["scope"], "", "Group coverage:",
    ]
    for group in report["groups"]:
        lines.append(
            f"  {display(group['name'])} ({display(group['group_id'])}): "
            f"{group['matched_count']} leaf certificate(s); IDs {display(group['cert_ids'])}"
        )
    if not report["groups"]:
        lines.append("  No alert groups.")
    lines.extend(("", "Certificate routes:"))
    for cert in report["certificates"]:
        flags = [label for label, present in (
            ("ORPHAN", cert["orphan"]), ("MULTI-MATCH", cert["multi_match"]),
            ("INVALID ADDRESS", bool(cert["invalid_recipients"])),
        ) if present]
        lines.extend((
            f"  {display(cert['cert_id'])} {display(cert['hostname'])}:{display(cert['port'])} "
            f"{display(cert['subject'])} {' '.join(flags)}",
            f"    groups={display(cert['group_ids'])}; "
            f"specific recipients={display(cert['recipients'])}",
        ))
    if not report["certificates"]:
        lines.append("  No leaf certificates.")
    return "\n".join(lines) + "\n"
