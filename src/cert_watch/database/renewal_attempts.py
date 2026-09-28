"""Shared renewal-attempt predicates and compatibility projections."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import SQLITE_QUERY_CHUNK, _connect, _sql_now


def renewal_attempt_is_live(
    state: str | None,
    lease_expires_at: str | None,
    *,
    now: datetime | None = None,
) -> bool:
    """Python twin of :func:`renewal_attempt_is_live_sql`."""
    if state != "open" or not lease_expires_at:
        return False
    try:
        lease = datetime.fromisoformat(lease_expires_at)
        if lease.tzinfo is None:
            lease = lease.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        return _whole_milliseconds(lease) > _whole_milliseconds(current)
    except (TypeError, ValueError, OverflowError):
        return False


def renewal_attempt_is_live_sql(attempt_alias: str, now_sql: str = "?") -> str:
    """SQL twin of :func:`renewal_attempt_is_live` for one attempt row."""
    return (
        f"({attempt_alias}.state='open' "
        f"AND cw_epoch_ms({attempt_alias}.lease_expires_at)>cw_epoch_ms({now_sql}))"
    )


def _whole_milliseconds(value: datetime) -> int:
    """Return an instant at the precision used by ``cw_epoch_ms`` in SQL."""
    utc = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc - epoch
    return (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )


def live_attempt_exists_sql(host_alias: str = "h", now_sql: str = "?") -> str:
    """Whether the endpoint's materialized current attempt has a live lease."""
    return (
        "EXISTS(SELECT 1 FROM renewal_attempts ral "
        f"WHERE ral.host_id={host_alias}.id AND ral.is_current=1 AND "
        f"{renewal_attempt_is_live_sql('ral', now_sql)})"
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
        "AND ras.suppresses_stalled=1 AND "
        f"{renewal_attempt_is_live_sql('ras', now_sql)})"
    )


def host_projection_sql(host_alias: str, now_sql: str) -> str:
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
    live_attempt = live_attempt_exists_sql(host_alias, now_sql)
    return (
        f"{columns},CASE WHEN {live_attempt} "
        "THEN 'in_progress' ELSE 'pending' END AS derived_renewal_status"
    )


def endpoint_stall_suppressions(
    db_path: str | Path,
    endpoints: Iterable[tuple[str, int]],
    *,
    now: datetime | None = None,
) -> set[tuple[str, int]]:
    """Return all endpoints with active stall suppression in one query."""
    unique = tuple(dict.fromkeys(endpoints))
    if not unique:
        return set()
    instant = _sql_now(now or datetime.now(UTC))
    suppressions: set[tuple[str, int]] = set()
    with _connect(db_path) as conn:
        for offset in range(0, len(unique), SQLITE_QUERY_CHUNK):
            chunk = unique[offset : offset + SQLITE_QUERY_CHUNK]
            endpoint_sql = " UNION ALL ".join(
                "SELECT ? AS hostname,? AS port" for _ in chunk
            )
            params: list[object] = [value for endpoint in chunk for value in endpoint]
            params.append(instant)
            rows = conn.execute(
                f"WITH ep AS ({endpoint_sql}) SELECT ep.hostname,ep.port FROM ep WHERE "
                + endpoint_stall_suppression_exists_sql("ep", "?"),
                params,
            ).fetchall()
            suppressions.update(
                (str(row["hostname"]), int(row["port"])) for row in rows
            )
    return suppressions


def endpoint_stall_suppression_active(
    db_path: str | Path,
    hostname: str,
    port: int,
    *,
    now: datetime | None = None,
) -> bool:
    """Read the webhook/rule suppression fact against one bound instant."""
    return (hostname, port) in endpoint_stall_suppressions(
        db_path, ((hostname, port),), now=now
    )
