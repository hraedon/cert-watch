"""Transactional host mutations used by application services."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Literal

from cert_watch.database.repo import HostEntry, SqliteHostRepository


@dataclass(frozen=True)
class HostTargetLookup:
    status: Literal[
        "host", "certificate", "resource_not_found", "no_host_associated", "host_not_found"
    ]
    host: HostEntry | None = None


def resolve_host_target(conn: sqlite3.Connection, resource_id: str) -> HostTargetLookup:
    """Resolve a host id or certificate id to its host without committing."""
    host_row = conn.execute("SELECT * FROM hosts WHERE id = ?", (resource_id,)).fetchone()
    if host_row is not None:
        return HostTargetLookup("host", SqliteHostRepository._row_to_host(host_row))

    cert_row = conn.execute(
        "SELECT hostname, port FROM certificates WHERE id = ?", (resource_id,)
    ).fetchone()
    if cert_row is None:
        return HostTargetLookup("resource_not_found")
    hostname = cert_row["hostname"] or ""
    port = cert_row["port"] or 443
    if not hostname:
        return HostTargetLookup("no_host_associated")

    host_row = conn.execute(
        "SELECT * FROM hosts WHERE hostname = ? AND port = ?", (hostname, port)
    ).fetchone()
    if host_row is None:
        return HostTargetLookup("host_not_found")
    return HostTargetLookup("certificate", SqliteHostRepository._row_to_host(host_row))


def update_host_ownership(
    conn: sqlite3.Connection,
    host_id: str,
    *,
    owner_name: str | None,
    owner_email: str | None,
    owner_slack: str | None,
    renewal_status: str | None,
    renewal_method: str | None,
    runbook_url: str | None,
) -> HostEntry | None:
    """Apply a partial ownership update without committing the transaction."""
    row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if row is None:
        return None

    values = {
        "owner_name": owner_name,
        "owner_email": owner_email,
        "owner_slack": owner_slack,
        "renewal_status": renewal_status,
        "renewal_method": renewal_method,
        "runbook_url": runbook_url,
    }
    present = {name: value for name, value in values.items() if value is not None}
    if present:
        assignments = ", ".join(f"{name} = ?" for name in present)
        conn.execute(
            f"UPDATE hosts SET {assignments} WHERE id = ?",
            (*present.values(), host_id),
        )

    updated = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    return SqliteHostRepository._row_to_host(updated) if updated is not None else None
