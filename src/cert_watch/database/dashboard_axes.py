"""SQL aggregate counts for the four-axis status model."""
from __future__ import annotations

from pathlib import Path

from cert_watch.database.chain_status_cache import StatusContext, prepare_status
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_page import inventory_candidates_sql
from cert_watch.status_model import (
    AxisSettings,
    StatusModelContext,
    load_delivery_statuses,
    prepare_status_model_context,
    register_status_model_functions,
)


def dashboard_axis_stats(
    db_path: str | Path,
    *,
    q: str | None = None,
    source: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    status: StatusContext | None = None,
    axes: StatusModelContext | None = None,
    axis_settings: AxisSettings | None = None,
) -> dict[str, dict[str, int]]:
    """Count each independent state from the same SQL candidates Browse uses."""
    status = status or prepare_status(db_path)
    axes = axes or prepare_status_model_context(
        db_path, certificate_status=status, settings=axis_settings
    )
    candidates = inventory_candidates_sql(
        q=q, source=source, scope_tags=scope_tags, status=status, axes=axes
    )
    result = {
        "condition": dict.fromkeys(("expired", "le7", "8to30", "ok"), 0),
        "monitoring": dict.fromkeys(("current", "failing", "never_scanned"), 0),
        "renewal": dict.fromkeys(
            ("automation_configured", "manual", "stalled", "in_progress", "unknown"), 0
        ),
        "delivery": dict.fromkeys(("ok", "failing", "unrouted"), 0),
    }
    if candidates is None:
        return result
    sql, params = candidates
    with _connect(db_path) as conn:
        register_status_model_functions(conn, axes)
        cert_ids = tuple(
            row[0]
            for row in conn.execute(
                f"SELECT ekey FROM ({sql}) WHERE etype = 'leaf'", params
            ).fetchall()
        )
    load_delivery_statuses(db_path, cert_ids, axes)
    with _connect(db_path) as conn:
        register_status_model_functions(conn, axes)
        for axis in result:
            rows = conn.execute(
                f"SELECT {axis} AS state, COUNT(*) AS n FROM ({sql})"
                f" WHERE {axis} IS NOT NULL GROUP BY {axis}",
                params,
            ).fetchall()
            for row in rows:
                if row["state"] in result[axis]:
                    result[axis][row["state"]] = int(row["n"])
    return result
