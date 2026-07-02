"""Unified-entry builders and filtered loaders.

Provides the shared entry-building helpers used by the paginated and grouped
dashboard query paths: ``_build_unified_from_dash`` (merge dashboard rows with
host/scan context), ``_build_pending_entries`` (hosts with no leaf cert),
``_build_unified_for_leaf_ids`` (fetch + build for a specific leaf set), and
``_load_unified_filtered`` (SQL-level filtered loader backing
``list_unified_entries``).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_rows import _build_dashboard_rows
from cert_watch.database.schema import init_schema
from cert_watch.filters import subject_cn
from cert_watch.tags import format_tags, merge_tags


def _build_unified_from_dash(
    dash: list[dict[str, Any]],
    host_rows: list[Any],
    scan_rows: list[Any],
    *,
    include_uploaded: bool = True,
) -> list[dict[str, Any]]:
    """Build unified entries from dashboard rows, host rows, and scan rows."""
    latest_scan: dict[tuple[str, int], dict[str, Any]] = {
        (r["hostname"], r["port"]): dict(r) for r in scan_rows
    }

    scanned_map: dict[str, dict[str, Any]] = {}
    uploaded: list[dict[str, Any]] = []
    for c in dash:
        if c["source"] == "scanned":
            scanned_map[c["host"]] = c
        else:
            uploaded.append(c)

    host_id_map: dict[tuple[str, int], str] = {
        (h["hostname"], h["port"]): h["id"] for h in host_rows
    }
    host_tags_map: dict[tuple[str, int], str] = {
        (h["hostname"], h["port"]): (h["tags"] or "") for h in host_rows
    }

    entries: list[dict[str, Any]] = []
    for h in host_rows:
        host_key = f"{h['hostname']}:{h['port']}"
        scan = latest_scan.get((h["hostname"], h["port"]))
        owner_info = {
            "owner_name": dict(h).get("owner_name", ""),
            "owner_email": dict(h).get("owner_email", ""),
            "owner_slack": dict(h).get("owner_slack", ""),
            "renewal_status": dict(h).get("renewal_status", "pending"),
            "renewal_method": dict(h).get("renewal_method", ""),
            "runbook_url": dict(h).get("runbook_url", ""),
            "notes": dict(h).get("notes", ""),
        }
        if host_key in scanned_map:
            row = scanned_map[host_key]
            row["kind"] = "scanned"
            row["host_id"] = host_id_map.get((h["hostname"], h["port"]))
            row["last_scanned_at"] = scan["scanned_at"] if scan else None
            row["scan_status"] = scan["status"] if scan else None
            row["scan_error"] = scan.get("error_message") if scan else None
            row["added_at"] = h["added_at"]
            # WI-053: dashboard shows effective tags (cert tags ∪ host tags).
            host_tags = host_tags_map.get((h["hostname"], h["port"]), "")
            row["tags"] = format_tags(merge_tags(row.get("tags", ""), host_tags))
            row.update(owner_info)
            entries.append(row)
        else:
            entries.append(
                {
                    "id": h["id"],
                    "host_id": h["id"],
                    "kind": "pending",
                    "name": host_key,
                    "host": host_key,
                    "source": "scanned",
                    "subject": None,
                    "issuer": None,
                    "not_before": None,
                    "not_after": None,
                    "days_remaining": None,
                    "urgency": "gray",
                    "leaf_urgency": "gray",
                    "chain": [],
                    "chain_valid": None,
                    "chain_status": None,
                    "replaces_cert_id": None,
                    "notes": "",
                    "fingerprint_sha256": None,
                    "san_dns_names": [],
                    "last_scanned_at": scan["scanned_at"] if scan else None,
                    "scan_status": scan["status"] if scan else None,
                    "scan_error": scan.get("error_message") if scan else None,
                    "added_at": h["added_at"],
                    **owner_info,
                }
            )

    if include_uploaded:
        for u in uploaded:
            u["kind"] = "uploaded"
            u["name"] = subject_cn(u["subject"] or "")
            u["last_scanned_at"] = None
            u["scan_status"] = None
            u["scan_error"] = None
            u["added_at"] = None
            entries.append(u)

    return entries


def _build_pending_entries(host_rows: list[Any], scan_rows: list[Any]) -> list[dict[str, Any]]:
    """Build pending unified entries (hosts with no leaf cert) for given hosts."""
    if not host_rows:
        return []
    latest_scan: dict[tuple[str, int], dict[str, Any]] = {
        (r["hostname"], r["port"]): dict(r) for r in scan_rows
    }
    entries: list[dict[str, Any]] = []
    for h in host_rows:
        host_key = f"{h['hostname']}:{h['port']}"
        scan = latest_scan.get((h["hostname"], h["port"]))
        owner_info = {
            "owner_name": dict(h).get("owner_name", ""),
            "owner_email": dict(h).get("owner_email", ""),
            "owner_slack": dict(h).get("owner_slack", ""),
            "renewal_status": dict(h).get("renewal_status", "pending"),
            "renewal_method": dict(h).get("renewal_method", ""),
            "runbook_url": dict(h).get("runbook_url", ""),
            "notes": dict(h).get("notes", ""),
        }
        entries.append({
            "id": h["id"],
            "host_id": h["id"],
            "kind": "pending",
            "name": host_key,
            "host": host_key,
            "tags": dict(h).get("tags", ""),
            "source": "scanned",
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "urgency": "gray",
            "leaf_urgency": "gray",
            "chain": [],
            "chain_valid": None,
            "chain_status": None,
            "replaces_cert_id": None,
            "notes": "",
            "fingerprint_sha256": None,
            "san_dns_names": [],
            "last_scanned_at": scan["scanned_at"] if scan else None,
            "scan_status": scan["status"] if scan else None,
            "scan_error": scan.get("error_message") if scan else None,
            "added_at": h["added_at"],
            **owner_info,
        })
    return entries


def _build_unified_for_leaf_ids(
    conn: Any,
    leaf_ids: list[str],
    *,
    host_rows: list[Any],
    scan_rows: list[Any],
    anchor_rows: list[Any],
) -> list[dict[str, Any]]:
    """Build scanned/uploaded unified entries for a specific set of leaf ids.

    Fetches the leaf rows + their chain children, builds dashboard rows, and
    merges in host/scan context.  Pending hosts (no leaf) are added by the
    caller via :func:`_build_unified_from_dash`-style logic; this helper only
    covers leaf-backed entries (scanned + uploaded).
    """
    if not leaf_ids:
        return []
    ph = ",".join("?" * len(leaf_ids))
    leaf_rows = conn.execute(
        f"SELECT * FROM certificates WHERE id IN ({ph})", leaf_ids
    ).fetchall()
    chain_rows = conn.execute(
        f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})", leaf_ids
    ).fetchall()
    dash = _build_dashboard_rows(list(leaf_rows) + list(chain_rows), anchor_rows)
    return _build_unified_from_dash(dash, host_rows, scan_rows)


def _build_host_filter(
    col: str,
    values: list[str] | tuple[str, ...],
    *,
    include_null: bool = False,
) -> tuple[str, tuple[Any, ...]]:
    """Build a parameterised SQL WHERE clause for host filtering.

    *col* must be a bare column name (e.g. ``"owner_name"``) validated
    against a whitelist — never derived from user input.  The returned
    fragment is safe to interpolate into SQL via f-string because only the
    whitelisted column name and ``?`` placeholders are inserted.

    Returns ``(clause, params)`` ready for ``conn.execute(sql, params)``.
    """
    _ALLOWED = {"owner_name", "renewal_method"}
    if col not in _ALLOWED:
        raise ValueError(f"disallowed filter column: {col}")
    prefixed = f"h.{col}"
    if not values:
        if include_null:
            return f"{prefixed} IS NULL", ()
        return "1=0", ()
    if len(values) == 1:
        eq = f"{prefixed} = ?"
        if include_null:
            return f"COALESCE({prefixed}, '') = ? OR {prefixed} IS NULL", (values[0],)
        return eq, (values[0],)
    ph = ",".join("?" * len(values))
    clause = f"{prefixed} IN ({ph})"
    if include_null:
        clause = f"COALESCE({prefixed}, '') IN ({ph}) OR {prefixed} IS NULL"
    return clause, tuple(values)


def _load_unified_filtered(
    db_path: str | Path,
    *,
    filter_col: str | None = None,
    filter_values: list[str] | tuple[str, ...] | None = None,
    filter_include_null: bool = False,
    include_uploaded: bool = False,
) -> list[dict[str, Any]]:
    """Load unified entries for scanned/pending hosts, optionally filtered.

    Uses SQL-level filtering via an EXISTS subquery on the *hosts* table so
    only matching rows are materialised.

    Filtering is column-based: *filter_col* is validated against a whitelist,
    and *filter_values* are passed as parameterised ``?`` placeholders — no
    user input reaches the SQL text.

    When *include_uploaded* is True (and no *filter_col* is set), uploaded
    certificates (those without a matching host) are included in the result.
    This is the mode used by :func:`list_unified_entries`.  When False (the
    default), only certificates linked to a host row are returned.
    """
    if filter_col and filter_values is not None:
        host_where, host_params = _build_host_filter(
            filter_col, filter_values, include_null=filter_include_null,
        )
    else:
        host_where, host_params = None, ()

    init_schema(db_path)
    with _connect(db_path) as conn:
        if host_where:
            host_rows = conn.execute(
                f"SELECT * FROM hosts WHERE {host_where} ORDER BY added_at",
                host_params,
            ).fetchall()
        else:
            host_rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()

        if host_where:
            exists_clause = (
                f"EXISTS (SELECT 1 FROM hosts h WHERE h.hostname = c.hostname "
                f"AND h.port = c.port AND {host_where})"
            )
        elif include_uploaded:
            exists_clause = "1=1"
        else:
            exists_clause = "c.hostname IS NOT NULL"

        cert_rows = conn.execute(
            f"SELECT * FROM certificates c WHERE c.is_leaf = 1 "
            f"AND {exists_clause} ORDER BY created_at",
            host_params,
        ).fetchall()
        leaf_ids = [r["id"] for r in cert_rows]
        if leaf_ids:
            ph = ",".join("?" * len(leaf_ids))
            chain_rows = conn.execute(
                f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})",
                leaf_ids,
            ).fetchall()
        else:
            chain_rows = []

        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        if host_where:
            scan_exists = (
                f"EXISTS (SELECT 1 FROM hosts h WHERE h.hostname = sh1.hostname "
                f"AND h.port = sh1.port AND {host_where})"
            )
        else:
            scan_exists = "1=1"
        scan_rows = conn.execute(
            f"""
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            AND {scan_exists}
            """,
            host_params,
        ).fetchall()

    dash = _build_dashboard_rows(list(cert_rows) + list(chain_rows), anchor_rows)
    return _build_unified_from_dash(dash, host_rows, scan_rows, include_uploaded=include_uploaded)


def list_unified_entries(db_path: str | Path) -> list[dict[str, Any]]:
    """Return a merged list of hosts (pending or scanned) and uploaded certificates.

    Each entry has a ``kind`` of ``scanned``, ``uploaded``, or ``pending``.
    Pending hosts carry cert fields set to ``None`` and urgency ``gray``.

    Uses SQL-level filtering via :func:`_load_unified_filtered` so the full
    inventory is not materialised in Python (BC-073).
    """
    return _load_unified_filtered(db_path, include_uploaded=True)
