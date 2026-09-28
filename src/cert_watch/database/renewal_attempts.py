"""Shared SQL facts projected from the current renewal attempt."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import _connect, _sql_now


def open_attempt_exists_sql(host_alias: str = "h") -> str:
    """Whether the endpoint's materialized current attempt is open."""
    return (
        "EXISTS(SELECT 1 FROM renewal_attempts ras "
        f"WHERE ras.host_id={host_alias}.id AND ras.is_current=1 AND ras.state='open')"
    )


def live_attempt_exists_sql(host_alias: str = "h", now_sql: str = "?") -> str:
    """Whether an open attempt's immutable lease remains live."""
    return (
        "EXISTS(SELECT 1 FROM renewal_attempts ral "
        f"WHERE ral.host_id={host_alias}.id AND ral.is_current=1 AND ral.state='open' "
        f"AND ral.lease_expires_at>{now_sql})"
    )


def stall_suppression_exists_sql(host_alias: str = "h", now_sql: str = "?") -> str:
    """Whether the endpoint currently owns its one stall-suppressing lease."""
    return (
        "EXISTS(SELECT 1 FROM renewal_attempts ras "
        f"WHERE ras.host_id={host_alias}.id AND ras.is_current=1 AND ras.state='open' "
        f"AND ras.suppresses_stalled=1 AND ras.lease_expires_at>{now_sql})"
    )


def endpoint_stall_suppression_exists_sql(
    endpoint_alias: str = "c", now_sql: str = "?"
) -> str:
    """The suppression fact for a certificate-shaped hostname/port row."""
    return (
        "EXISTS(SELECT 1 FROM renewal_attempts ras "
        "JOIN hosts rah ON rah.id=ras.host_id "
        f"WHERE rah.hostname={endpoint_alias}.hostname "
        f"AND rah.port={endpoint_alias}.port AND ras.is_current=1 "
        "AND ras.state='open' AND ras.suppresses_stalled=1 "
        f"AND ras.lease_expires_at>{now_sql})"
    )


def host_projection_sql(host_alias: str = "h") -> str:
    """Select every host field while deriving the compatibility status."""
    names = (
        "id",
        "hostname",
        "port",
        "threshold_days",
        "tags",
        "scan_interval_hours",
        "owner_name",
        "owner_email",
        "owner_slack",
        "renewal_method",
        "runbook_url",
        "notes",
        "expected_issuers",
        "starttls_mode",
        "added_at",
    )
    columns = ",".join(f"{host_alias}.{name}" for name in names)
    return (
        f"{columns},CASE WHEN {open_attempt_exists_sql(host_alias)} "
        "THEN 'in_progress' ELSE 'pending' END AS derived_renewal_status"
    )


def endpoint_stall_suppression_active(
    db_path: str | Path,
    hostname: str,
    port: int,
    *,
    now: datetime | None = None,
) -> bool:
    """Read the webhook/rule suppression fact against one bound instant."""
    instant = _sql_now(now or datetime.now(UTC))
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT " + endpoint_stall_suppression_exists_sql("ep", "?")
            + " FROM (SELECT ? AS hostname,? AS port) ep",
            (instant, hostname, port),
        ).fetchone()
    return bool(row and row[0])
