"""Transactional host mutations used by application services."""

from __future__ import annotations

import sqlite3

from cert_watch.database.repo import HostEntry, SqliteHostRepository


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
