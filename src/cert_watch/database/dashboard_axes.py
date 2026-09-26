"""SQL aggregate counts for the four-axis status model."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from cert_watch.database.chain_status_cache import StatusContext, prepare_status
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_page import inventory_candidates_sql
from cert_watch.status_model import (
    AxisSettings,
    StatusModelContext,
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
    axis_columns: frozenset[str] | None = None,
    home: bool = False,
) -> dict[str, Any]:
    """Count requested states from the same SQL candidates Browse uses.

    ``None`` retains the public all-axis behavior.  Page callers pass only
    axes they display so an unrelated delivery or renewal classifier is not
    evaluated estate-wide.
    """
    status = status or prepare_status(db_path)
    axes = axes or prepare_status_model_context(
        db_path, certificate_status=status, settings=axis_settings
    )
    candidates = inventory_candidates_sql(
        q=q, source=source, scope_tags=scope_tags, status=status, axes=axes,
        sql_delivery=True,
        axis_columns=axis_columns,
    )
    result: dict[str, Any] = {
        "condition": dict.fromkeys(("expired", "le7", "8to30", "ok"), 0),
        "monitoring": dict.fromkeys(("current", "failing", "never_scanned"), 0),
        "renewal": dict.fromkeys(
            ("automation_configured", "manual", "stalled", "in_progress", "unknown"), 0
        ),
        "delivery": dict.fromkeys(("ok", "failing", "unrouted"), 0),
        "overall": dict.fromkeys(
            ("expired", "critical", "warning", "healthy", "failing", "gray"), 0
        ),
    }
    if candidates is None:
        return result
    sql, params = candidates
    requested = set(result) if axis_columns is None else set(axis_columns)
    columns = {
        f"{axis}_{state}": (axis, state)
        for axis, states in result.items()
        if axis in requested
        for state in states
    }
    aggregates = ", ".join(
        f"SUM(CASE WHEN {'etype = \'leaf\' AND ' if axis == 'overall' else ''}"
        f"{'overall_state' if axis == 'overall' else axis} = '{state}' "
        f"THEN 1 ELSE 0 END) AS {alias}"
        for alias, (axis, state) in columns.items()
    )
    with _connect(db_path) as conn:
        register_status_model_functions(conn, axes)
        if not home:
            row = conn.execute(
                f"WITH inventory AS MATERIALIZED ({sql}) "
                f"SELECT {aggregates} FROM inventory",
                params,
            ).fetchone()
            if row is not None:
                for alias, (axis, state) in columns.items():
                    result[axis][state] = int(row[alias] or 0)
            return result

        # Home needs several views of the same population.  Keep them behind
        # one MATERIALIZED inventory CTE so condition, monitoring and delivery
        # are classified estate-wide exactly once.  The second query below is
        # keyed only by the bounded rows selected here.
        current = axes.now
        week_start = (current - timedelta(days=current.weekday())).date().isoformat()
        horizon_end = (
            current - timedelta(days=current.weekday()) + timedelta(weeks=12)
        ).date().isoformat()
        stats_json_args = ["'tracked'", "COUNT(*)"]
        for alias, (axis, state) in columns.items():
            predicate = "etype = 'leaf' AND " if axis == "overall" else ""
            state_column = "overall_state" if axis == "overall" else axis
            stats_json_args.extend(
                [
                    f"'{alias}'",
                    f"SUM(CASE WHEN {predicate}{state_column} = '{state}' "
                    "THEN 1 ELSE 0 END)",
                ]
            )
        stats_json_args.extend(
            [
                "'routing_gap_total'",
                "SUM(routing_gap)",
                "'last_scan'",
                "MAX(monitoring_last_attempt)",
                "'webhook_outcome'",
                "(SELECT json_extract(e.details, '$.outcome') "
                " FROM alert_delivery_events e JOIN alerts a ON a.id = e.alert_id "
                " JOIN inventory visible ON visible.etype = 'leaf' "
                "   AND visible.ekey = a.cert_id "
                " WHERE e.event_kind = 'completed' "
                "   AND cw_normalize_channel(e.channel) = "
                f"'webhook:{axes.settings.webhook_kind.replace(chr(39), chr(39) * 2)}' "
                " ORDER BY e.id DESC LIMIT 1)",
                "'webhook_failed_at'",
                "(SELECT e.occurred_at "
                " FROM alert_delivery_events e JOIN alerts a ON a.id = e.alert_id "
                " JOIN inventory visible ON visible.etype = 'leaf' "
                "   AND visible.ekey = a.cert_id "
                " WHERE e.event_kind = 'completed' "
                "   AND cw_normalize_channel(e.channel) = "
                f"'webhook:{axes.settings.webhook_kind.replace(chr(39), chr(39) * 2)}' "
                " ORDER BY e.id DESC LIMIT 1)",
            ]
        )
        stats_payload = f"json_object({', '.join(stats_json_args)})"
        trust_states = "'incomplete','invalid','unknown','self-signed','unverified'"
        home_sql = f"""
            WITH inventory AS MATERIALIZED ({sql}),
            risk_ranked AS (
                SELECT etype, ekey, hostname, port, condition,
                       ROW_NUMBER() OVER (
                           PARTITION BY condition
                           ORDER BY eff_days ASC, sort_name ASC
                       ) AS n
                FROM inventory
                WHERE condition IN ('expired', 'le7', '8to30')
            ),
            monitoring_ranked AS (
                SELECT etype, ekey, hostname, port, monitoring,
                       ROW_NUMBER() OVER (
                           PARTITION BY monitoring
                           ORDER BY COALESCE(monitoring_first_failed,
                                             monitoring_last_attempt,
                                             sort_added) ASC,
                                    sort_name ASC
                       ) AS n
                FROM inventory
                WHERE monitoring IN ('failing', 'never_scanned')
            ),
            chain_ranked AS (
                SELECT grp_issuer AS issuer, chain_status, hostname, port, subject,
                       ROW_NUMBER() OVER (
                           PARTITION BY grp_issuer ORDER BY sort_name, ekey
                       ) AS member_number,
                       COUNT(*) OVER (PARTITION BY grp_issuer) AS cert_count
                FROM inventory
                WHERE etype = 'leaf' AND chain_status IN ({trust_states})
            ),
            chain_grouped AS (
                SELECT issuer, MAX(cert_count) AS cert_count,
                       GROUP_CONCAT(DISTINCT chain_status) AS statuses,
                       MAX(CASE WHEN member_number = 1 THEN hostname END)
                           AS example_1_hostname,
                       MAX(CASE WHEN member_number = 1 THEN port END)
                           AS example_1_port,
                       MAX(CASE WHEN member_number = 1 THEN subject END)
                           AS example_1_subject,
                       MAX(CASE WHEN member_number = 2 THEN hostname END)
                           AS example_2_hostname,
                       MAX(CASE WHEN member_number = 2 THEN port END)
                           AS example_2_port,
                       MAX(CASE WHEN member_number = 2 THEN subject END)
                           AS example_2_subject
                FROM chain_ranked
                GROUP BY issuer
            ),
            chain_counted AS (
                SELECT *, SUM(cert_count) OVER () AS total_certs,
                       COUNT(*) OVER () AS total_issuers
                FROM chain_grouped
            ),
            week_grouped AS (
                SELECT DATE(sort_expiry, 'weekday 0', '-6 days') AS bucket_start,
                       COUNT(*) AS cert_count,
                       CASE
                         WHEN SUM(condition IN ('expired', 'le7')) > 0 THEN 'critical'
                         WHEN SUM(condition = '8to30') > 0 THEN 'warning'
                         ELSE 'neutral'
                       END AS tone
                FROM inventory
                WHERE etype = 'leaf' AND sort_expiry >= ? AND sort_expiry < ?
                GROUP BY bucket_start
            )
            SELECT 'stats' AS kind, {stats_payload} AS payload,
                   '' AS category, '' AS etype, '' AS ekey,
                   NULL AS hostname, NULL AS port
            FROM inventory
            UNION ALL
            SELECT 'entry', NULL, 'risk:' || condition, etype, ekey, hostname, port
            FROM risk_ranked WHERE n <= 6
            UNION ALL
            SELECT 'entry', NULL, 'monitoring:' || monitoring,
                   etype, ekey, hostname, port
            FROM monitoring_ranked WHERE n <= 8
            UNION ALL
            SELECT 'chain', json_object(
                       'issuer', issuer,
                       'count', cert_count,
                       'statuses', statuses,
                       'total_certs', total_certs,
                       'total_issuers', total_issuers,
                       'example_1_hostname', example_1_hostname,
                       'example_1_port', example_1_port,
                       'example_1_subject', example_1_subject,
                       'example_2_hostname', example_2_hostname,
                       'example_2_port', example_2_port,
                       'example_2_subject', example_2_subject
                   ), '', '', '', NULL, NULL
            FROM chain_counted
            ORDER BY cert_count DESC, issuer ASC
            LIMIT 8
        """
        # A compound SELECT's trailing LIMIT applies to the whole union.  Wrap
        # the chain branch so its bound cannot hide stats or selected rows.
        home_sql = home_sql.replace(
            "FROM chain_counted\n            ORDER BY cert_count DESC, issuer ASC\n"
            "            LIMIT 8",
            "FROM (SELECT * FROM chain_counted "
            "ORDER BY cert_count DESC, issuer ASC LIMIT 8)",
        )
        home_sql += """
            UNION ALL
            SELECT 'week', json_object('bucket_start', bucket_start,
                                       'count', cert_count, 'tone', tone),
                   '', '', '', NULL, NULL
            FROM week_grouped
        """
        rows = conn.execute(home_sql, [*params, week_start, horizon_end]).fetchall()

        selected: list[tuple[str, str, str | None, int | None, str]] = []
        chain_groups: list[dict[str, Any]] = []
        calendar: list[dict[str, Any]] = []
        home_stats: dict[str, Any] = {}
        for row in rows:
            if row["kind"] == "stats":
                home_stats = json.loads(row["payload"] or "{}")
            elif row["kind"] == "entry":
                selected.append(
                    (
                        str(row["etype"]),
                        str(row["ekey"]),
                        row["hostname"],
                        int(row["port"]) if row["port"] is not None else None,
                        str(row["category"]),
                    )
                )
            elif row["kind"] == "chain":
                chain_groups.append(json.loads(row["payload"]))
            elif row["kind"] == "week":
                calendar.append(json.loads(row["payload"]))

        for alias, (axis, state) in columns.items():
            result[axis][state] = int(home_stats.get(alias) or 0)

        unique_keys = tuple(dict.fromkeys((kind, key) for kind, key, *_ in selected))
        endpoints = tuple(
            dict.fromkeys(
                (str(hostname), int(port))
                for _kind, _key, hostname, port, _category in selected
                if hostname is not None and port is not None
            )
        )
        built: list[dict[str, Any]] = []
        if unique_keys:
            from cert_watch.database.dashboard_page import build_inventory_entries

            bounded = inventory_candidates_sql(
                scope_tags=scope_tags,
                status=status,
                axes=axes,
                entry_keys=unique_keys,
                history_endpoints=endpoints,
                axis_columns=frozenset(
                    {"condition", "monitoring", "chain", "renewal"}
                ),
            )
            assert bounded is not None
            bounded_sql, bounded_params = bounded
            bounded_rows = conn.execute(bounded_sql, bounded_params).fetchall()
            by_key = {
                (str(candidate["etype"]), str(candidate["ekey"])): candidate
                for candidate in bounded_rows
            }
            ordered = [by_key[key] for key in unique_keys if key in by_key]
            built = build_inventory_entries(
                db_path, conn, ordered, status=status, axes=axes
            )
        built_by_key = {
            (
                "pending" if entry.get("kind") == "pending" else "leaf",
                str(entry.get("id")),
            ): entry
            for entry in built
        }
        categorized: dict[str, list[dict[str, Any]]] = {}
        for kind, key, _hostname, _port, category in selected:
            entry = built_by_key.get((kind, key))
            if entry is not None:
                categorized.setdefault(category, []).append(entry)

        result["_home"] = {
            "tracked_total": int(home_stats.get("tracked") or 0),
            "last_scan": home_stats.get("last_scan"),
            "webhook_outcome": home_stats.get("webhook_outcome"),
            "webhook_failed_at": home_stats.get("webhook_failed_at"),
            "routing_gap_total": int(home_stats.get("routing_gap_total") or 0),
            "rows": categorized,
            "chain_groups": chain_groups,
            "calendar": sorted(calendar, key=lambda item: str(item["bucket_start"])),
        }
    return result
