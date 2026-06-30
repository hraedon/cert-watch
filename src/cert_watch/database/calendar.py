"""Calendar view queries."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.schema import init_schema


def list_calendar(
    db_path: str | Path,
    from_date: str | None = None,
    to_date: str | None = None,
    bucket: str = "month",
) -> list[dict[str, Any]]:
    """Return certificate expiry buckets for the calendar view.

    Buckets: ``day``, ``week``, ``month``.  Each result has
    ``bucket_start``, ``count``, and ``cert_ids`` (JSON array).
    Only leaf certificates are included.
    """
    init_schema(db_path)
    if bucket not in ("day", "week", "month"):
        bucket = "month"

    # SQLite date formatting for bucketing
    if bucket == "day":
        group_expr = "DATE(not_after)"
    elif bucket == "week":
        # Start of ISO week (Monday)
        group_expr = "DATE(not_after, 'weekday 0', '-6 days')"
    else:  # month
        group_expr = "DATE(not_after, 'start of month')"

    conditions = ["is_leaf = 1"]
    params: list[str] = []
    if from_date:
        conditions.append("not_after >= ?")
        params.append(from_date)
    if to_date:
        conditions.append("not_after <= ?")
        params.append(to_date)

    where = " AND ".join(conditions)

    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT {group_expr} AS bucket_start,
                       COUNT(*) AS count,
                       GROUP_CONCAT(id) AS cert_ids_csv
                FROM certificates
                WHERE {where}
                GROUP BY {group_expr}
                ORDER BY bucket_start""",
            params,
        ).fetchall()

    result = []
    for r in rows:
        ids = r["cert_ids_csv"].split(",") if r["cert_ids_csv"] else []
        result.append({
            "bucket_start": r["bucket_start"],
            "count": r["count"],
            "cert_ids": ids,
        })
    return result
