"""Triage page queries — the work queue and the 90-day horizon (Plan 053).

Every function here is read-only assembly over existing tables; the triage
page renders existing signals, it does not create new ones. Scoping follows
the dashboard's effective-tag model (cert ∪ host tags) so a scoped user's
queue agrees with the inventory they can see.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import _add_effective_tag_filter
from cert_watch.database.schema import init_schema
from cert_watch.filters import compute_urgency, subject_cn

HORIZON_DAYS = 90

# Renewal stalls are only worth recomputing for certs already inside a
# plausible renewal window; beyond this nothing can be overdue.
_STALL_CHECK_WINDOW_DAYS = 60

# not_after is a T-separated ISO timestamp while datetime('now') is
# space-separated, so comparisons go through julianday() — and the expired
# test must use the raw < now comparison, not days < 0, because CAST
# truncates toward zero (see dashboard_stats.pivot_urgency_stats).
_DAYS_EXPR = "CAST((julianday(c.not_after) - julianday('now')) AS INTEGER)"


def _leaf_certs_where(
    db_path: str | Path,
    condition: str,
    scope_tags: list[str] | tuple[str, ...] | None,
) -> list[dict[str, Any]]:
    """Leaf certs (scanned ∪ uploaded) matching a not_after *condition*.

    Mirrors dashboard_urgency_stats population: scanned leaf certs joined to
    their host (tag-scoped over cert ∪ host tags) plus uploaded leaf certs
    (cert tags only). Sorted soonest-expiry first.
    """
    init_schema(db_path)
    scanned_sql = f"""
        SELECT c.id, c.subject, c.hostname, c.port, c.not_after,
               c.source, h.id AS host_id, {_DAYS_EXPR} AS days_remaining
        FROM certificates c
        JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
        WHERE c.is_leaf = 1 AND c.source = 'scanned' AND ({condition})
    """
    scanned_params: list[Any] = []
    scanned_sql, scanned_params = _add_effective_tag_filter(
        scanned_sql, scanned_params, scope_tags or (),
        col_cert="c.tags", col_host="h.tags",
    )
    uploaded_sql = f"""
        SELECT c.id, c.subject, c.hostname, c.port, c.not_after,
               c.source, NULL AS host_id, {_DAYS_EXPR} AS days_remaining
        FROM certificates c
        WHERE c.is_leaf = 1 AND c.source != 'scanned' AND ({condition})
    """
    uploaded_params: list[Any] = []
    uploaded_sql, uploaded_params = _add_effective_tag_filter(
        uploaded_sql, uploaded_params, scope_tags or (),
        col_cert="c.tags", col_host="''",
    )
    sql = (
        f"SELECT * FROM ({scanned_sql} UNION ALL {uploaded_sql})"
        " ORDER BY not_after ASC"
    )
    with _connect(db_path) as conn:
        rows = conn.execute(sql, scanned_params + uploaded_params).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["name"] = subject_cn(d["subject"])
        out.append(d)
    return out


def list_expired_certs(
    db_path: str | Path,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Expired leaf certificates, most-recently-expired first."""
    rows = _leaf_certs_where(
        db_path, "julianday(c.not_after) < julianday('now')", scope_tags
    )
    rows.reverse()  # freshest expiry is the most actionable
    return rows


def list_critical_certs(
    db_path: str | Path,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Leaf certificates expiring within 7 days (not yet expired)."""
    return _leaf_certs_where(
        db_path,
        f"julianday(c.not_after) >= julianday('now') AND {_DAYS_EXPR} < 7",
        scope_tags,
    )


def list_expiry_horizon(
    db_path: str | Path,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    horizon_days: int = HORIZON_DAYS,
) -> list[dict[str, Any]]:
    """Per-day clusters of leaf certs expiring within *horizon_days*.

    Returns one entry per day that has expiries: ``days`` (offset from
    today), ``date`` (ISO), ``certs`` (id/name), ``count``, and ``urgency``
    (of the day, from its offset). Days with nothing expiring are absent —
    the timeline renders markers, not a grid.
    """
    rows = _leaf_certs_where(
        db_path,
        "julianday(c.not_after) >= julianday('now')"
        f" AND {_DAYS_EXPR} <= {int(horizon_days)}",
        scope_tags,
    )
    by_day: dict[int, dict[str, Any]] = {}
    for r in rows:
        days = int(r["days_remaining"])
        bucket = by_day.setdefault(
            days,
            {
                "days": days,
                "date": (r["not_after"] or "")[:10],
                "certs": [],
                "count": 0,
                "urgency": compute_urgency(days),
            },
        )
        bucket["certs"].append({"id": r["id"], "name": r["name"]})
        bucket["count"] += 1
    return [by_day[d] for d in sorted(by_day)]


def list_failed_scans(
    db_path: str | Path,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Hosts whose most recent scan failed, freshest failure first."""
    init_schema(db_path)
    sql = """
        SELECT h.id AS host_id, h.hostname, h.port,
               s.error_message, s.scanned_at
        FROM hosts h
        JOIN scan_history s ON s.hostname = h.hostname AND s.port = h.port
        WHERE s.status = 'failure'
          AND s.scanned_at = (
              SELECT MAX(s2.scanned_at) FROM scan_history s2
              WHERE s2.hostname = h.hostname AND s2.port = h.port
          )
    """
    params: list[Any] = []
    sql, params = _add_effective_tag_filter(
        sql, params, scope_tags or (), col_cert=None, col_host="h.tags"
    )
    sql += " ORDER BY s.scanned_at DESC"
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def count_failed_alerts_24h(db_path: str | Path) -> int:
    """Alert deliveries that failed in the last 24 hours (fleet-wide)."""
    init_schema(db_path)
    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'failed' AND created_at > ?",
            (cutoff,),
        ).fetchone()
    return int(row[0]) if row else 0


def list_renewal_stalls(
    db_path: str | Path,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Hosts whose renewal cadence says a successor should exist by now.

    Recomputes :func:`renewal_analytics.detect_renewal_overdue` for hosts
    whose current leaf cert is inside the stall-check window. Cheap at SMB
    scale: only in-window hosts are checked, a few small queries each.
    """
    from cert_watch.renewal_analytics import detect_renewal_overdue

    init_schema(db_path)
    sql = f"""
        SELECT DISTINCT h.hostname, h.port, h.id AS host_id,
               c.id AS cert_id, {_DAYS_EXPR} AS days_remaining
        FROM hosts h
        JOIN certificates c ON c.hostname = h.hostname AND c.port = h.port
        WHERE c.is_leaf = 1
          AND julianday(c.not_after) >= julianday('now')
          AND {_DAYS_EXPR} <= {_STALL_CHECK_WINDOW_DAYS}
    """
    params: list[Any] = []
    sql, params = _add_effective_tag_filter(
        sql, params, scope_tags or (), col_cert="c.tags", col_host="h.tags"
    )
    with _connect(db_path) as conn:
        candidates = conn.execute(sql, params).fetchall()

    stalls: list[dict[str, Any]] = []
    for row in candidates:
        signal = detect_renewal_overdue(
            db_path, row["hostname"], port=row["port"]
        )
        if signal is None:
            continue
        stalls.append(
            {
                "hostname": signal.hostname,
                "port": row["port"],
                "host_id": row["host_id"],
                "cert_id": row["cert_id"],
                "days_remaining": signal.days_remaining,
                "days_overdue": signal.days_overdue,
                "expected_renewal_at_days": signal.expected_renewal_at_days,
                "confidence": signal.confidence,
            }
        )
    stalls.sort(key=lambda s: -s["days_overdue"])
    return stalls
