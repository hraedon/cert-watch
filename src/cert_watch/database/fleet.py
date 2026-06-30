"""Fleet pivot and grouping queries."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard import _load_unified_filtered
from cert_watch.database.schema import init_schema

_URGENCY_ORDER = ("expired", "critical", "warning", "healthy", "gray")

def list_fleet_pivot(
    db_path: str | Path,
    pivot: str,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Return fleet pivot groups using SQL-level aggregation.

    Each group has ``key``, ``count``, ``worst_urgency``, ``earliest_expiry``.
    The ``entries`` field is ``None`` — use :func:`get_pivot_group_entries`
    to fetch entries for a specific group on demand (BC-048).

    ``scope_tags`` restricts results to hosts/certificates whose effective tags
    include at least one supplied tag (WI-051).
    """
    from cert_watch.database.dashboard import _add_effective_tag_filter
    from cert_watch.filters import friendly_issuer

    init_schema(db_path)

    _METHOD_LABELS = {
        "acme": "ACME",
        "cert-manager": "cert-manager",
        "manual": "Manual",
    }

    # Determine the grouping column for scanned leaf certs
    if pivot == "issuer":
        group_col = "c.issuer"
    elif pivot == "owner":
        group_col = "COALESCE(h.owner_name, '')"
    elif pivot == "renewal_method":
        group_col = "COALESCE(h.renewal_method, '')"
    else:
        group_col = "'unknown'"

    with _connect(db_path) as conn:
        # Scanned hosts: aggregate per group from leaf certificates
        scanned_sql = f"""
            SELECT {group_col} AS grp,
                   CAST(MIN(CASE
                        -- Expired certs map to -1 so the group's worst_urgency
                        -- reaches "expired" (min_days < 0). Using julianday keeps
                        -- the comparison robust to the stored T-separated ISO format;
                        -- a plain string compare against datetime('now') (space-sep)
                        -- and CAST-toward-zero would both miss same-day expiries.
                        WHEN julianday(c.not_after) < julianday('now') THEN -1
                        ELSE CAST(
                            (julianday(c.not_after) - julianday('now'))
                            AS INTEGER
                        )
                   END) AS INTEGER) AS min_days,
                   COUNT(*) AS cnt
            FROM certificates c
            JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
            WHERE c.is_leaf = 1
        """
        scanned_params: list[Any] = []
        scanned_sql, scanned_params = _add_effective_tag_filter(
            scanned_sql, scanned_params, scope_tags or (), col_cert="c.tags", col_host="h.tags"
        )
        scanned_sql += " GROUP BY grp"
        rows = conn.execute(scanned_sql, scanned_params).fetchall()

        # Pending hosts: hosts with no leaf certificate
        # For issuer pivot, pending hosts have no cert so group by "Unknown"
        pending_group_col = "''" if pivot == "issuer" else group_col
        pending_sql = f"""
            SELECT {pending_group_col} AS grp,
                   COUNT(*) AS cnt
            FROM hosts h
            WHERE NOT EXISTS (
                SELECT 1 FROM certificates c
                WHERE c.hostname = h.hostname AND c.port = h.port AND c.is_leaf = 1
            )
        """
        pending_params: list[Any] = []
        pending_sql, pending_params = _add_effective_tag_filter(
            pending_sql, pending_params, scope_tags or (), col_cert=None, col_host="h.tags"
        )
        pending_sql += " GROUP BY grp"
        pending_rows = conn.execute(pending_sql, pending_params).fetchall()

    result: list[dict[str, Any]] = []

    for r in rows:
        d = dict(r)
        raw_key = d["grp"] or ""
        min_days = d["min_days"]

        if min_days is not None and min_days < 0:
            urgency = "expired"
        elif min_days is not None and min_days < 7:
            urgency = "critical"
        elif min_days is not None and min_days < 30:
            urgency = "warning"
        else:
            urgency = "healthy"

        result.append({
            "key": raw_key,
            "count": d["cnt"],
            "worst_urgency": urgency,
            "earliest_expiry": min_days,
            "entries": None,
        })

    for r in pending_rows:
        d = dict(r)
        raw_key = d["grp"] or ""
        existing = next((g for g in result if g["key"] == raw_key), None)
        if existing:
            existing["count"] += d["cnt"]
            if existing["worst_urgency"] == "healthy":
                existing["worst_urgency"] = "gray"
        else:
            result.append({
                "key": raw_key,
                "count": d["cnt"],
                "worst_urgency": "gray",
                "earliest_expiry": None,
                "entries": None,
            })

    # Apply friendly labels to group keys
    for g in result:
        raw = g["key"] or ""
        if pivot == "issuer":
            g["key"] = friendly_issuer(raw) if raw else "Unknown"
        elif pivot == "owner":
            g["key"] = raw or "Unassigned"
        elif pivot == "renewal_method":
            g["key"] = _METHOD_LABELS.get(raw, raw) if raw else "Unknown"

    result.sort(key=lambda g: g["count"], reverse=True)
    return result


def get_pivot_group_entries(
    db_path: str | Path,
    pivot: str,
    group_key: str,
) -> list[dict[str, Any]]:
    """Return unified entries for a single pivot group.

    Used to lazily load entries when a pivot group is expanded (BC-048).
    ``group_key`` is the *friendly* key as displayed in the pivot table
    (e.g. "Let's Encrypt", "alice", "ACME").

    Uses SQL-level filtering so only matching hosts and their certs are
    materialised at fleet scale.
    """
    from cert_watch.filters import friendly_issuer

    _METHOD_LABELS = {
        "acme": "ACME",
        "cert-manager": "cert-manager",
        "manual": "Manual",
    }

    # Map the friendly group_key back to raw DB values for SQL filtering
    if pivot == "issuer":
        entries = _load_unified_filtered(db_path)
    elif pivot == "owner":
        if group_key == "Unassigned":
            entries = _load_unified_filtered(
                db_path, filter_col="owner_name", filter_values=[""], filter_include_null=True,
            )
        else:
            entries = _load_unified_filtered(
                db_path, filter_col="owner_name", filter_values=[group_key],
            )
    elif pivot == "renewal_method":
        if group_key == "Unknown":
            entries = _load_unified_filtered(
                db_path, filter_col="renewal_method", filter_values=[""], filter_include_null=True,
            )
        else:
            # Reverse-label lookup: accept any raw value that maps to the friendly label
            raw_methods = [k for k, v in _METHOD_LABELS.items() if v == group_key]
            if raw_methods:
                entries = _load_unified_filtered(
                    db_path, filter_col="renewal_method", filter_values=raw_methods,
                )
            else:
                entries = _load_unified_filtered(
                    db_path, filter_col="renewal_method", filter_values=[group_key],
                )
    else:
        entries = _load_unified_filtered(db_path)

    for e in entries:
        if pivot == "issuer":
            raw = e.get("issuer") or ""
            key = friendly_issuer(raw) if raw else "Unknown"
        elif pivot == "owner":
            key = e.get("owner_name") or "Unassigned"
        elif pivot == "renewal_method":
            raw = e.get("renewal_method") or ""
            key = _METHOD_LABELS.get(raw, raw) if raw else "Unknown"
        else:
            key = "Unknown"
        e["_pivot_key"] = key

    return [e for e in entries if e.get("_pivot_key") == group_key]


def group_entries_by_fingerprint(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

        if not fp or len(fp_groups.get(fp, [])) <= 1:
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
        })

    return result
