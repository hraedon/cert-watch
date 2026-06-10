"""Certificate store operations (replace, delete, renewal diff)."""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database.connection import _connect, _iso, _parse_iso
from cert_watch.database.schema import init_schema


def distinct_tags(db_path: str | Path) -> list[str]:
    """Return the sorted set of distinct tags across all hosts and certificates."""
    from cert_watch.tags import merge_tags

    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT tags FROM hosts UNION ALL SELECT tags FROM certificates"
        ).fetchall()
    all_tags = merge_tags(*[r["tags"] for r in rows])
    return sorted(all_tags, key=str.casefold)


def replace_scanned(
    db_path: str | Path,
    hostname: str,
    port: int,
    leaf: Certificate,
    chain: list[Certificate],
    chain_valid: bool | None,
) -> tuple[str, str | None]:
    """Atomically replace all certs for host:port with new leaf + chain.

    Deletes old leaf + chain children, inserts new ones, all in a single
    transaction. Returns ``(new_leaf_id, replaced_cert_id)`` — the
    ``replaced_cert_id`` is the old leaf's id when a cert was replaced
    (None when this is a fresh insert with no prior leaf).
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

        # Collect all old cert IDs (leaves + chain children) BEFORE deleting
        # them, so we can clean up their alerts.
        old_all_ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM certificates WHERE hostname = ? AND port = ?",
                (hostname, port),
            ).fetchall()
        ]

        for old_id in old_leaves:
            conn.execute(
                "DELETE FROM certificates WHERE parent_cert_id = ?", (old_id,)
            )
        conn.execute(
            "DELETE FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1",
            (hostname, port),
        )
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
        with _connect(db_path) as conn:
            conn.execute(
                "UPDATE hosts SET renewal_status = 'pending' "
                "WHERE hostname = ? AND port = ? AND renewal_status = 'renewed'",
                (hostname, port),
            )
            conn.commit()

    return leaf_id, replaces_id


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
        conn.execute(
            f"DELETE FROM scan_posture WHERE cert_id IN ({placeholders})", all_ids
        )
        conn.execute(
            f"DELETE FROM cert_history WHERE fingerprint_sha256 IN "
            f"(SELECT fingerprint_sha256 FROM certificates WHERE id IN ({placeholders}))",
            all_ids,
        )
        conn.execute(
            f"DELETE FROM alert_group_certs WHERE cert_id IN ({placeholders})", all_ids
        )
        conn.execute("DELETE FROM certificates WHERE parent_cert_id = ?", (cert_id,))
        conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
        conn.commit()
    return True

def get_renewal_history(
    db_path: str | Path, cert_id: str, limit: int = 10
) -> list[dict]:
    """Walk the replaces_cert_id chain backwards from this cert.

    Returns list of dicts oldest-first: [{id, subject, fingerprint_sha256,
    not_before, not_after, replaces_cert_id, created_at, is_current}, ...].
    The given cert_id is marked is_current=True.
    """
    init_schema(db_path)
    entries: list[dict] = []
    current_id = cert_id
    seen: set[str] = set()
    while current_id and current_id not in seen and len(entries) < limit:
        seen.add(current_id)
        with _connect(db_path) as conn:
            row = conn.execute(
                "SELECT id, subject, fingerprint_sha256, not_before, not_after, "
                "replaces_cert_id, created_at FROM certificates WHERE id = ?",
                (current_id,),
            ).fetchone()
        if not row:
            break
        entries.append({
            "id": row["id"],
            "subject": row["subject"],
            "fingerprint_sha256": dict(row).get("fingerprint_sha256", ""),
            "not_before": row["not_before"],
            "not_after": row["not_after"],
            "replaces_cert_id": row["replaces_cert_id"],
            "created_at": row["created_at"],
            "is_current": row["id"] == cert_id,
        })
        current_id = row["replaces_cert_id"]
    entries.reverse()
    return entries
