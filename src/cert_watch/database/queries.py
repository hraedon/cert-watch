"""Dashboard and utility queries."""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database.connection import _connect, _iso, _parse_iso, _row_to_cert
from cert_watch.database.schema import init_schema


def replace_scanned(
    db_path: str | Path,
    hostname: str,
    port: int,
    leaf: Certificate,
    chain: list[Certificate],
    chain_valid: bool | None,
) -> str:
    """Atomically replace all certs for host:port with new leaf + chain.

    Deletes old leaf + chain children, inserts new ones, all in a single
    transaction. Returns the new leaf cert_id.  Records a renewal diff
    when the certificate fingerprint changed.
    """
    from cert_watch.cert_chain import validate_chain_order

    if chain_valid is None:
        chain_valid = validate_chain_order([leaf, *chain])

    now = _iso(datetime.now(UTC))
    leaf_id = str(uuid.uuid4())

    with _connect(db_path) as conn:
        old_leaves = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1",
                (hostname, port),
            ).fetchall()
        ]
        replaces_id: str | None = old_leaves[0] if old_leaves else None

        old_leaf_row = None
        if replaces_id:
            old_leaf_row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (replaces_id,)
            ).fetchone()

        for old_id in old_leaves:
            conn.execute(
                "DELETE FROM certificates WHERE parent_cert_id = ?", (old_id,)
            )
        conn.execute(
            "DELETE FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1",
            (hostname, port),
        )
        old_all_ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM certificates WHERE hostname = ? AND port = ?",
                (hostname, port),
            ).fetchall()
        ]
        if old_all_ids:
            ph = ",".join("?" * len(old_all_ids))
            conn.execute(
                f"DELETE FROM alerts WHERE cert_id IN ({ph})", old_all_ids
            )

        cv: int | None = None if chain_valid is None else (1 if chain_valid else 0)
        conn.execute(
            """
            INSERT INTO certificates
            (id, subject, issuer, not_before, not_after, san_dns_names,
             fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
             parent_cert_id, chain_valid, replaces_cert_id, notes,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                leaf_id,
                leaf.subject,
                leaf.issuer,
                _iso(leaf.not_before),
                _iso(leaf.not_after),
                json.dumps(leaf.san_dns_names),
                leaf.fingerprint_sha256,
                leaf.raw_der,
                "scanned",
                hostname,
                port,
                1,
                None,
                cv,
                replaces_id,
                "",
                now,
                now,
            ),
        )

        for chain_cert in chain:
            chain_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO certificates
                (id, subject, issuer, not_before, not_after, san_dns_names,
                 fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
                 parent_cert_id, chain_valid, replaces_cert_id, notes,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_id,
                    chain_cert.subject,
                    chain_cert.issuer,
                    _iso(chain_cert.not_before),
                    _iso(chain_cert.not_after),
                    json.dumps(chain_cert.san_dns_names),
                    chain_cert.fingerprint_sha256,
                    chain_cert.raw_der,
                    "scanned",
                    hostname,
                    port,
                    0,
                    leaf_id,
                    None,
                    None,
                    "",
                    now,
                    now,
                ),
            )
        conn.commit()

    if old_leaf_row is not None and leaf.fingerprint_sha256 != old_leaf_row["fingerprint_sha256"]:
        changes = _compute_renewal_diff(old_leaf_row, leaf)
        if changes:
            import logging
            logging.getLogger("cert_watch.database").info(
                "certificate renewed for %s:%s — %s",
                hostname, port, "; ".join(changes),
            )

    return leaf_id


def _compute_renewal_diff(old_row, new_leaf: Certificate) -> list[str]:
    """Compute human-readable diff between old and new leaf certificates."""
    changes: list[str] = []
    old_na = old_row["not_after"]
    if old_na:
        old_expiry = _parse_iso(old_na)
        days_added = (new_leaf.not_after - old_expiry).days
        if days_added > 0:
            changes.append(f"expiry extended by {days_added} days")
    old_sans = set(json.loads(old_row["san_dns_names"]))
    new_sans = set(new_leaf.san_dns_names)
    added = new_sans - old_sans
    removed = old_sans - new_sans
    if added:
        changes.append(f"SAN added: {', '.join(sorted(added))}")
    if removed:
        changes.append(f"SAN removed: {', '.join(sorted(removed))}")
    if old_row["issuer"] != new_leaf.issuer:
        changes.append(f"issuer changed to {new_leaf.issuer}")
    return changes


def delete_certificate_cascade(db_path: str | Path, cert_id: str) -> bool:
    """Delete a leaf cert, its chain children, and associated alerts."""
    with _connect(db_path) as conn:
        r = conn.execute(
            "SELECT id FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        if not r:
            return False
        child_ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM certificates WHERE parent_cert_id = ?", (cert_id,)
            ).fetchall()
        ]
        all_ids = [cert_id, *child_ids]
        placeholders = ",".join("?" * len(all_ids))
        conn.execute(
            f"DELETE FROM alerts WHERE cert_id IN ({placeholders})", all_ids
        )
        conn.execute("DELETE FROM certificates WHERE parent_cert_id = ?", (cert_id,))
        conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
        conn.commit()
    return True


def list_alerts_with_subject(db_path: str | Path) -> list[dict]:
    """Return alerts joined with the cert subject, newest first."""
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT a.id, a.created_at, a.alert_type, a.status, a.threshold_days,
                   a.sent_at, a.error_message, a.message, c.subject AS subject
            FROM alerts a
            LEFT JOIN certificates c ON c.id = a.cert_id
            ORDER BY a.created_at DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


def list_scan_history(db_path: str | Path) -> list[dict]:
    """Return scan_history rows, newest first."""
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY scanned_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- Dashboard helpers ----------

def _build_dashboard_rows(
    cert_rows,
    anchor_rows,
) -> list[dict]:
    """Build rich dashboard rows from raw certificate and anchor rows."""
    from cert_watch.cert_chain import chain_status

    anchors = [_row_to_cert(r) for r in anchor_rows]

    leaf_rows: list[dict] = []
    children_by_leaf: dict[str, list[dict]] = {}
    for r in cert_rows:
        d = dict(r)
        if d["is_leaf"]:
            leaf_rows.append(d)
        else:
            children_by_leaf.setdefault(d["parent_cert_id"] or "", []).append(d)

    def _days(iso_str: str) -> int:
        return (_parse_iso(iso_str) - datetime.now(UTC)).days

    def _urgency(days: int) -> str:
        if days < 0:
            return "expired"
        if days <= 7:
            return "critical"
        if days <= 14:
            return "warning"
        return "healthy"

    dash: list[dict] = []
    for leaf in leaf_rows:
        chain = children_by_leaf.get(leaf["id"], [])
        leaf_days = _days(leaf["not_after"])
        chain_view = []
        for c in chain:
            days = _days(c["not_after"])
            chain_view.append({
                "id": c["id"],
                "subject": c["subject"],
                "issuer": c["issuer"],
                "not_before": c["not_before"],
                "not_after": c["not_after"],
                "days_remaining": days,
                "urgency": _urgency(days),
            })
        all_days = [leaf_days, *[c["days_remaining"] for c in chain_view]]
        min_days = min(all_days)
        host = (
            f"{leaf['hostname']}:{leaf['port']}"
            if leaf["hostname"]
            else f"(uploaded:{leaf['source']})"
        )
        leaf_cert = _row_to_cert(leaf)
        chain_certs = [_row_to_cert(c) for c in chain]
        _chain_status = chain_status(leaf_cert, chain_certs, anchors)
        dash.append(
            {
                "id": leaf["id"],
                "host": host,
                "source": leaf["source"],
                "subject": leaf["subject"],
                "issuer": leaf["issuer"],
                "not_before": leaf["not_before"],
                "not_after": leaf["not_after"],
                "days_remaining": leaf_days,
                "urgency": _urgency(min_days),
                "leaf_urgency": _urgency(leaf_days),
                "chain": chain_view,
                "chain_valid": (
                    None if leaf["chain_valid"] is None else bool(leaf["chain_valid"])
                ),
                "chain_status": _chain_status,
                "replaces_cert_id": leaf.get("replaces_cert_id"),
                "notes": dict(leaf).get("notes", ""),
                "fingerprint_sha256": leaf.get("fingerprint_sha256", ""),
                "san_dns_names": json.loads(leaf.get("san_dns_names", "[]")),
            }
        )

    return dash


def list_dashboard_rows(
    db_path: str | Path,
    *,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    per_page: int = 0,
) -> list[dict]:
    """
    Return rich rows for the dashboard. Per the scope extension, each scanned host
    or uploaded bundle surfaces leaf + intermediate + root, and the row's urgency
    is driven by the most-urgent cert in that group.

    When per_page > 0, applies pagination at the SQL level for leaf certificates
    and fetches only the chain children needed for that page.
    """
    init_schema(db_path)

    # Map sort_by to SQL ORDER BY for leaf certificates
    _sort_map = {
        "name": "subject",
        "issue_date": "not_before",
        "expiry": "not_after",
        "days": "not_after",
        "last_scan": "not_after",
    }
    sql_col = _sort_map.get(sort_by, "not_after")
    sql_dir = "ASC" if sort_order == "asc" else "DESC"

    with _connect(db_path) as conn:
        if per_page > 0:
            offset = max(0, (page - 1) * per_page)
            leaf_rows = conn.execute(
                f"SELECT * FROM certificates WHERE is_leaf = 1 "
                f"ORDER BY {sql_col} {sql_dir} LIMIT ? OFFSET ?",
                (per_page, offset),
            ).fetchall()
            leaf_ids = [r["id"] for r in leaf_rows]
            if leaf_ids:
                ph = ",".join("?" * len(leaf_ids))
                chain_rows = conn.execute(
                    f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})",
                    leaf_ids,
                ).fetchall()
            else:
                chain_rows = []
            rows = list(leaf_rows) + list(chain_rows)
        else:
            rows = conn.execute(
                "SELECT * FROM certificates ORDER BY created_at"
            ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

    dash = _build_dashboard_rows(rows, anchor_rows)
    if per_page == 0:
        dash.sort(
            key=lambda d: min(
                [d["days_remaining"], *[c["days_remaining"] for c in d["chain"]]]
            )
        )
    return dash


def count_dashboard_leaves(db_path: str | Path) -> int:
    """Return the total number of leaf certificates for pagination."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE is_leaf = 1"
        ).fetchone()
    return row[0] if row else 0


def list_unified_entries(db_path: str | Path) -> list[dict]:
    """Return a merged list of hosts (pending or scanned) and uploaded certificates.

    Each entry has a ``kind`` of ``scanned``, ``uploaded``, or ``pending``.
    Pending hosts carry cert fields set to ``None`` and urgency ``gray``.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        cert_rows = conn.execute(
            "SELECT * FROM certificates ORDER BY created_at"
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()
        host_rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()
        # Only fetch the latest scan per host directly in SQL (BC-028)
        scan_rows = conn.execute(
            """
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            """
        ).fetchall()

    dash = _build_dashboard_rows(cert_rows, anchor_rows)

    # Latest scan per host
    latest_scan: dict[tuple[str, int], dict] = {
        (r["hostname"], r["port"]): dict(r) for r in scan_rows
    }

    # Map scanned certs by host key
    scanned_map: dict[str, dict] = {}
    uploaded: list[dict] = []
    for c in dash:
        if c["source"] == "scanned":
            scanned_map[c["host"]] = c
        else:
            uploaded.append(c)

    # Host id lookup for scanned/pending entries
    host_id_map: dict[tuple[str, int], str] = {
        (h["hostname"], h["port"]): h["id"] for h in host_rows
    }

    entries: list[dict] = []
    for h in host_rows:
        host_key = f"{h['hostname']}:{h['port']}"
        scan = latest_scan.get((h["hostname"], h["port"]))
        owner_info = {
            "owner_name": dict(h).get("owner_name", ""),
            "owner_email": dict(h).get("owner_email", ""),
            "owner_slack": dict(h).get("owner_slack", ""),
            "renewal_status": dict(h).get("renewal_status", "pending"),
        }
        if host_key in scanned_map:
            row = scanned_map[host_key]
            row["kind"] = "scanned"
            row["host_id"] = host_id_map.get((h["hostname"], h["port"]))
            row["last_scanned_at"] = scan["scanned_at"] if scan else None
            row["scan_status"] = scan["status"] if scan else None
            row["scan_error"] = scan.get("error_message") if scan else None
            row["added_at"] = h["added_at"]
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

    for u in uploaded:
        u["kind"] = "uploaded"
        u["name"] = u["subject"]
        u["last_scanned_at"] = None
        u["scan_status"] = None
        u["scan_error"] = None
        u["added_at"] = None
        entries.append(u)

    return entries


_URGENCY_ORDER = ("expired", "critical", "warning", "healthy", "gray")


def group_entries_by_fingerprint(entries: list[dict]) -> list[dict]:
    """Group scanned entries sharing the same leaf fingerprint into single rows.

    Entries with ``kind != "scanned"`` or no fingerprint pass through unchanged.
    Groups of size 1 also pass through.  Only scanned entries with a matching
    fingerprint and 2+ hosts are collapsed into a ``kind == "grouped"`` entry.
    """
    fp_groups: dict[str, list[dict]] = {}
    first_seen: dict[str, int] = {}

    for idx, e in enumerate(entries):
        fp = e.get("fingerprint_sha256") if e.get("kind") == "scanned" else None
        if fp:
            fp_groups.setdefault(fp, []).append(e)
            first_seen.setdefault(fp, idx)

    result: list[dict] = []
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
        })

    return result
