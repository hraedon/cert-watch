"""Fleet pivot and grouping queries."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cert_watch.database.schema import init_schema

if TYPE_CHECKING:
    from cert_watch.database.chain_status_cache import StatusContext
    from cert_watch.status_model import AxisSettings, StatusModelContext

_URGENCY_ORDER = ("expired", "critical", "warning", "healthy", "gray")

_METHOD_LABELS = {
    "acme": "ACME",
    "cert-manager": "cert-manager",
    "manual": "Manual",
}

# The raw group column of each pivot in inventory_candidates_sql's rows.
_GROUP_COLUMN = {"issuer": "grp_issuer", "owner": "grp_owner", "renewal_method": "grp_method"}


def _friendly_key(raw: str | None, pivot: str) -> str:
    """The group label a raw group value is shown under for *pivot*."""
    from cert_watch.filters import friendly_issuer

    raw = raw or ""
    if pivot == "issuer":
        return friendly_issuer(raw) if raw else "Unknown"
    if pivot == "owner":
        return raw or "Unassigned"
    if pivot == "renewal_method":
        return _METHOD_LABELS.get(raw, raw) if raw else "Unknown"
    return "Unknown"


def list_fleet_pivot(
    db_path: str | Path,
    pivot: str,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    *,
    now: datetime | None = None,
    status: StatusContext | None = None,
    axes: StatusModelContext | None = None,
    axis_settings: AxisSettings | None = None,
) -> list[dict[str, Any]]:
    """Return fleet pivot groups over the Browse inventory rows, counted in SQL.

    The groups partition the inventory rows (endpoints, pending ones included,
    and uploaded files) that Home and Browse count, with the same status rule
    (:mod:`cert_watch.status_rule`), aggregated in SQL so a pivot page does
    not materialise the estate (#113 review). Each group has ``key``,
    ``count``, ``worst_urgency`` (the most urgent row status; ``gray`` when
    the group's only non-healthy rows are endpoints not yet scanned) and
    ``earliest_expiry`` (the smallest effective days of any row -- the soonest
    expiry in any stored chain -- negative once expired, ``None`` when no row
    has a certificate). The ``entries`` field is ``None`` --
    :func:`get_pivot_group_entries` returns a group's rows on demand (BC-048).

    ``scope_tags`` restricts results to rows whose effective tags include at
    least one supplied tag (WI-051).
    """
    from cert_watch.database.chain_status_cache import prepare_status
    from cert_watch.database.connection import _connect
    from cert_watch.database.dashboard_page import inventory_candidates_sql

    init_schema(db_path)
    from cert_watch.status_model import (
        prepare_status_model_context,
        register_status_model_functions,
    )

    status = status or prepare_status(db_path, now)
    axes = axes or prepare_status_model_context(
        db_path, certificate_status=status, settings=axis_settings
    )
    candidates = inventory_candidates_sql(scope_tags=scope_tags, status=status, axes=axes)
    if candidates is None:
        return []
    sql, params = candidates
    column = _GROUP_COLUMN.get(pivot, "''")
    groups: dict[str, dict[str, Any]] = {}
    with _connect(db_path) as conn:
        register_status_model_functions(conn, axes)
        rows = conn.execute(
            f"SELECT {column} AS grp, urgency, monitoring, COUNT(*) AS n,"
            f" MIN(eff_days) AS min_days, MIN(sort_expiry) AS first_expiry"
            f" FROM ({sql}) GROUP BY grp, urgency, monitoring",
            params,
        ).fetchall()
    # One row per (raw group value, status): bounded by the number of groups,
    # not the estate. Raw values sharing a label (issuer DNs) merge here.
    for row in rows:
        key = _friendly_key(row["grp"], pivot)
        group = groups.setdefault(
            key,
            {
                "key": key,
                "count": 0,
                "_urgencies": set(),
                "_monitoring": set(),
                "earliest_expiry": None,
                "entries": None,
                "_first": row["first_expiry"],
            },
        )
        group["_first"] = min(group["_first"], row["first_expiry"])
        group["count"] += row["n"]
        group["_urgencies"].add(row["urgency"] or "gray")
        group["_monitoring"].add(row["monitoring"] or "never_scanned")
        days = row["min_days"]
        if days is not None and (
            group["earliest_expiry"] is None or days < group["earliest_expiry"]
        ):
            group["earliest_expiry"] = int(days)

    result: list[dict[str, Any]] = []
    # Largest group first; among equals, the one whose leaf expires first.
    ordered = sorted(groups.values(), key=lambda g: (-g["count"], g["_first"], g["key"]))
    for group in ordered:
        del group["_first"]
        urgencies = group.pop("_urgencies")
        monitoring_states = group.pop("_monitoring")
        worst = next((u for u in _URGENCY_ORDER if u in urgencies), "gray")
        if worst == "healthy" and "failing" in monitoring_states:
            worst = "failing"
        elif worst == "healthy" and (
            "gray" in urgencies or "never_scanned" in monitoring_states
        ):
            # A healthy group that still has never-scanned endpoints is not
            # known to be healthy.
            worst = "gray"
        group["worst_urgency"] = worst
        result.append(group)
    return result


def get_pivot_group_page(
    db_path: str | Path,
    pivot: str,
    group_key: str,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    *,
    page: int = 1,
    per_page: int = 100,
    now: datetime | None = None,
    status: StatusContext | None = None,
    axes: StatusModelContext | None = None,
    axis_settings: AxisSettings | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """One page of the inventory rows of one pivot group, and the group's size.

    Used to lazily load a pivot group when it is expanded (BC-048).
    ``group_key`` is the *friendly* key as displayed in the pivot table (e.g.
    "Let's Encrypt", "alice", "ACME"). The group is selected in SQL from the
    rows :func:`list_fleet_pivot` counted, so the total always equals the
    group's count, and only the requested page is built: expanding a
    5,000-row group costs one page, not the group and never the estate.
    Rows come soonest-expiring first. ``per_page=0`` returns the whole group.
    Rows are judged with *status* (a request's shared context), else one
    prepared at ``now`` (default: the time of the call), so a caller that
    injected an instant into :func:`list_fleet_pivot` gets the same statuses
    here, and each row shows the chain status the counts used.

    ``scope_tags`` restricts results to entries whose effective tags
    (cert ∪ host) include at least one supplied tag (WI-051/WI-128).
    """
    from cert_watch.database.chain_status_cache import prepare_status
    from cert_watch.database.connection import _connect
    from cert_watch.database.dashboard_page import (
        build_inventory_entries,
        inventory_candidates_sql,
    )

    init_schema(db_path)
    status = status or prepare_status(db_path, now)
    from cert_watch.status_model import (
        attach_status_models,
        prepare_status_model_context,
        register_status_model_functions,
    )

    axes = axes or prepare_status_model_context(
        db_path, certificate_status=status, settings=axis_settings
    )
    candidates = inventory_candidates_sql(scope_tags=scope_tags, status=status, axes=axes)
    if candidates is None:
        return [], 0
    sql, params = candidates
    column = _GROUP_COLUMN.get(pivot, "''")
    with _connect(db_path) as conn:
        register_status_model_functions(conn, axes)
        raws = [
            row["grp"]
            for row in conn.execute(
                f"SELECT DISTINCT {column} AS grp FROM ({sql})", params
            ).fetchall()
            if _friendly_key(row["grp"], pivot) == group_key
        ]
        if not raws:
            return [], 0
        ph = ",".join("?" * len(raws))
        group_sql = (
            "SELECT etype, ekey, sort_expiry, chain_status, eff_days, condition,"
            " monitoring, monitoring_last_success, monitoring_last_attempt,"
            " monitoring_attempt_status, monitoring_error, monitoring_first_failed,"
            f" renewal, delivery FROM ({sql}) WHERE {column} IN ({ph})"
        )
        group_params = [*params, *raws]
        total = conn.execute(
            f"SELECT COUNT(*) FROM ({group_sql})", group_params
        ).fetchone()[0]
        page_sql = f"{group_sql} ORDER BY sort_expiry ASC, ekey ASC"
        if per_page > 0:
            page_sql += " LIMIT ? OFFSET ?"
            group_params += [per_page, max(0, (page - 1) * per_page)]
        ordered = conn.execute(page_sql, group_params).fetchall()
        entries = build_inventory_entries(conn, ordered, status=status, axes=axes)
    attach_status_models(db_path, entries, axes)
    for entry in entries:
        entry["_pivot_key"] = group_key
    return entries, total


def get_pivot_group_entries(
    db_path: str | Path,
    pivot: str,
    group_key: str,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Every inventory row of one pivot group (see :func:`get_pivot_group_page`)."""
    entries, _ = get_pivot_group_page(
        db_path, pivot, group_key, scope_tags, per_page=0, now=now
    )
    return entries


def group_entries_by_fingerprint(
    entries: list[dict[str, Any]], *, force: bool = False
) -> list[dict[str, Any]]:
    """Group scanned entries sharing the same leaf fingerprint into single rows.

    Entries with ``kind != "scanned"`` or no fingerprint pass through unchanged.
    Groups of size 1 also pass through.  Only scanned entries with a matching
    fingerprint and 2+ hosts are collapsed into a ``kind == "grouped"`` entry.
    """
    fp_groups: dict[str, list[dict[str, Any]]] = {}
    first_seen: dict[str, int] = {}

    for idx, e in enumerate(entries):
        fp = e.get("fingerprint_sha256") if e.get("kind") == "scanned" else None
        if fp:
            fp_groups.setdefault(fp, []).append(e)
            first_seen.setdefault(fp, idx)

    result: list[dict[str, Any]] = []
    emitted_fps: set[str] = set()
    group_idx = 0

    for e in entries:
        fp = e.get("fingerprint_sha256") if e.get("kind") == "scanned" else None

        if not fp or (len(fp_groups.get(fp, [])) <= 1 and not force):
            result.append(e)
            continue

        if fp in emitted_fps:
            continue
        emitted_fps.add(fp)

        group = fp_groups[fp]
        group_idx += 1
        first = group[0]

        urgency_counts: dict[str, int] = {}
        for h in group:
            u = h["urgency"]
            urgency_counts[u] = urgency_counts.get(u, 0) + 1

        group_urgency = "healthy"
        for u in _URGENCY_ORDER:
            if urgency_counts.get(u, 0) > 0:
                group_urgency = u
                break

        result.append({
            "id": first["id"],
            "fingerprint_sha256": fp,
            "group_id": group_idx,
            "kind": "grouped",
            "source": "scanned",
            "subject": first["subject"],
            "issuer": first["issuer"],
            "not_before": first["not_before"],
            "not_after": first["not_after"],
            "days_remaining": first["days_remaining"],
            "urgency": group_urgency,
            "leaf_urgency": first["leaf_urgency"],
            "chain": first["chain"],
            "chain_valid": first["chain_valid"],
            "chain_status": first["chain_status"],
            "san_dns_names": first.get("san_dns_names", []),
            "replaces_cert_id": first.get("replaces_cert_id"),
            "notes": first.get("notes", ""),
            "name": first["subject"] or first["host"],
            "host": first["host"],
            "host_id": first.get("host_id"),
            "host_count": len(group),
            "healthy_count": sum(1 for h in group if h["urgency"] == "healthy"),
            "urgency_summary": urgency_counts,
            "hosts": group,
            "last_scanned_at": first.get("last_scanned_at"),
            "scan_status": first.get("scan_status"),
            "scan_error": first.get("scan_error"),
            "added_at": first.get("added_at"),
            "owner_name": first.get("owner_name", ""),
            "owner_email": first.get("owner_email", ""),
            "owner_slack": first.get("owner_slack", ""),
            "renewal_status": first.get("renewal_status", "pending"),
            "renewal_method": first.get("renewal_method", ""),
            "runbook_url": first.get("runbook_url", ""),
            "tags": first.get("tags", ""),
        })

    return result
