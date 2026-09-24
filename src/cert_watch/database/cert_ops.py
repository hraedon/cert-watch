"""Certificate store operations (replace, delete, renewal diff)."""
from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.certificate_model import Certificate
from cert_watch.database.connection import (
    _connect,
    _iso,
    _parse_iso,
    begin_immediate,
    get_write_lock,
    parse_san_dns_names,
)
from cert_watch.database.schema import init_schema

# Every ``certificates`` column falls in exactly one of these sets (a test
# enforces it). A scan writes the first set from what it observed; the second
# is set by people and must survive the row rewrite a scan performs -- on an
# unchanged rescan and on a renewal alike, since it describes the endpoint's
# certificate (#113).
SCAN_CERT_COLUMNS = (
    "id", "subject", "issuer", "not_before", "not_after", "san_dns_names",
    "fingerprint_sha256", "raw_der", "source", "hostname", "port", "is_leaf",
    "parent_cert_id", "chain_valid", "replaces_cert_id", "created_at", "updated_at",
)
CARRIED_CERT_COLUMNS = ("tags",)

# What happens to each stored reference to a certificate id when a scan
# rewrites an endpoint's rows. A test introspects the schema and fails when a
# column that names a certificate appears without an entry here (#113).
#
#   KEPT       unchanged rescan: the row keeps its id, so the reference stays
#              valid as is.
#   FOLLOWS    renewal: moved to the successor leaf (operator intent about the
#              endpoint's certificate, e.g. a manual alert-group assignment).
#   HISTORY    never rewritten: it records what happened to that certificate
#              (an alert that fired, an event, an audit entry). A renewal
#              leaves it naming the old id, which the stable-link resolver maps
#              to the endpoint's current certificate.
#   REDERIVED  rewritten by the scan itself (chain rows, posture).
#   ENDPOINT   the value names the endpoint + fingerprint, not a row id, for
#              scanned certificates; a scan never changes it.
CERT_ID_REFERENCES: dict[str, tuple[str, str]] = {
    # column: (unchanged rescan, renewal)
    "certificates.id": ("KEPT", "REDERIVED"),
    "certificates.parent_cert_id": ("REDERIVED", "REDERIVED"),
    "certificates.replaces_cert_id": ("KEPT", "REDERIVED"),
    "alert_group_certs.cert_id": ("KEPT", "FOLLOWS"),
    "alerts.cert_id": ("KEPT", "HISTORY"),
    "alerts.trigger_cert_id": ("HISTORY", "HISTORY"),
    "alerts.dedupe_key": ("ENDPOINT", "ENDPOINT"),
    "rule_firings.dedupe_key": ("ENDPOINT", "ENDPOINT"),
    "scan_posture.cert_id": ("REDERIVED", "REDERIVED"),
    "event_log.payload": ("HISTORY", "HISTORY"),
    "audit_log.target_id": ("HISTORY", "HISTORY"),
    "audit_log.detail": ("HISTORY", "HISTORY"),
}

def distinct_tags(
    db_path: str | Path, *, scope_tags: tuple[str, ...] = ()
) -> list[str]:
    """Return tags from resources visible under the effective-tag scope."""
    from cert_watch.database.dashboard_helpers import _add_effective_tag_filter
    from cert_watch.tags import merge_tags

    init_schema(db_path)
    with _connect(db_path) as conn:
        host_sql, host_params = _add_effective_tag_filter(
            "SELECT h.tags FROM hosts h WHERE 1=1", [], scope_tags, col_cert=None,
        )
        cert_sql, cert_params = _add_effective_tag_filter(
            "SELECT c.tags, h.tags AS host_tags FROM certificates c "
            "LEFT JOIN hosts h ON c.hostname=h.hostname AND c.port=h.port WHERE 1=1",
            [], scope_tags,
        )
        host_rows = conn.execute(host_sql, host_params).fetchall()
        cert_rows = conn.execute(cert_sql, cert_params).fetchall()
    all_tags = merge_tags(
        *[r["tags"] for r in host_rows],
        *[value for r in cert_rows for value in (r["tags"], r["host_tags"])],
    )
    return sorted(all_tags, key=str.casefold)


def _select_predecessors(
    old_leaf_rows: list[sqlite3.Row], fingerprint: str
) -> tuple[list[sqlite3.Row], bool]:
    """The row(s) a scan of *fingerprint* continues from, and whether it is an
    unchanged rescan (#115 review).

    Chosen by lineage, never by time: timestamps can go backwards and a stale
    duplicate can be inserted after the live row. A *head* is a leaf that no
    other row names as its ``replaces_cert_id`` -- a row something replaced is
    stale however new its timestamp. A head holding exactly the scanned bytes
    makes this an unchanged rescan of it; otherwise it is a renewal from the
    heads. One row is the unambiguous predecessor. Several are ambiguous, and
    the caller carries only what they all share. (A lineage cycle leaves no
    head; every leaf then counts as one.) Rows come newest first, which
    orders ties for the lineage fields only.
    """
    # A row naming itself is not replaced by anything (#115 review): treating
    # it as a one-node cycle kept the self-reference, and the expiry rules
    # then skipped the row as superseded -- no alert, ever.
    replaced = {
        row["replaces_cert_id"]
        for row in old_leaf_rows
        if row["replaces_cert_id"] and row["replaces_cert_id"] != row["id"]
    }
    heads = [row for row in old_leaf_rows if row["id"] not in replaced] or list(old_leaf_rows)
    same_bytes_heads = [row for row in heads if row["fingerprint_sha256"] == fingerprint]
    if same_bytes_heads:
        return same_bytes_heads, True
    return heads, False


def _carried_operator_data(
    conn: sqlite3.Connection, predecessors: list[sqlite3.Row]
) -> tuple[str, list[str]]:
    """Tags and manual alert-group ids to carry: the predecessor's own, or,
    when several rows are equally current, only those common to all of them.
    Carried data grants scope and routes alerts, so an ambiguous endpoint
    fails closed rather than unioning a stale row's grants into the live one."""
    from cert_watch.tags import format_tags, parse_tags

    if not predecessors:
        return "", []
    tag_sets = [parse_tags(row["tags"]) for row in predecessors]
    common = {t.casefold() for t in tag_sets[0]}
    for tags in tag_sets[1:]:
        common &= {t.casefold() for t in tags}
    carried_tags = format_tags(t for t in tag_sets[0] if t.casefold() in common)
    group_sets = [
        [
            str(row["group_id"])
            for row in conn.execute(
                "SELECT group_id FROM alert_group_certs WHERE cert_id = ? ORDER BY group_id",
                (predecessor["id"],),
            ).fetchall()
        ]
        for predecessor in predecessors
    ]
    shared = set(group_sets[0]).intersection(*map(set, group_sets[1:]))
    return carried_tags, [g for g in group_sets[0] if g in shared]


def _do_replace(
    db_path: str | Path,
    conn: sqlite3.Connection,
    hostname: str,
    port: int,
    leaf: Certificate,
    chain: list[Certificate],
    chain_valid: bool | None,
) -> tuple[str, str | None, bool]:
    """Inner implementation of replace_scanned using an existing connection."""
    from cert_watch.cert_chain import validate_chain_order

    if chain_valid is None:
        chain_valid = validate_chain_order([leaf, *chain])

    now = _iso(datetime.now(UTC))
    leaf_id = str(uuid.uuid4())
    old_leaf_rows = conn.execute(
        "SELECT * FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1 "
        "ORDER BY created_at DESC, rowid DESC",
        (hostname, port),
    ).fetchall()
    old_leaves = [row["id"] for row in old_leaf_rows]
    predecessors, unchanged = _select_predecessors(old_leaf_rows, leaf.fingerprint_sha256)
    # Lineage fields (the kept id, ``replaces_cert_id``) need exactly one row;
    # among ambiguous heads the newest is only a tie-break for those. It never
    # decides what operator data is carried -- see _carried_operator_data.
    old_leaf_row = predecessors[0] if predecessors else None
    replaces_id: str | None = old_leaf_row["id"] if old_leaf_row is not None else None
    if len(predecessors) > 1:
        import logging

        logging.getLogger("cert_watch.database").warning(
            "%s:%s holds %d current leaf certificates (%s); carrying only the "
            "tags and alert-group assignments they all share",
            hostname, port, len(predecessors), ", ".join(r["id"] for r in predecessors),
        )
    same_bytes = [
        row for row in old_leaf_rows if row["fingerprint_sha256"] == leaf.fingerprint_sha256
    ]

    # Collect all old cert IDs (leaves + chain children) BEFORE deleting
    # them, so we can clean up their alerts.
    old_all_ids = [
        row["id"]
        for row in conn.execute(
            "SELECT id FROM certificates WHERE hostname = ? AND port = ?",
            (hostname, port),
        ).fetchall()
    ]

    # A rescan that sees the same bytes has not replaced anything: it is the
    # same certificate, observed again. Its inventory row is still rewritten
    # (the chain and posture rows are re-derived), now under the same id, and
    # the alerts must stay on that id or they are orphaned on one that no
    # longer exists -- and `evaluate_thresholds` dedups by exactly that id.
    # Alerts on any other row holding the same bytes move to the kept id too
    # (they describe the same certificate); alerts on a different
    # certificate's row are closed below. Orphaning them made every threshold
    # fire again on the next cycle: one
    # unchanged certificate inside its expiry window re-alerted, and re-mailed,
    # once per scan, for ever.
    carried: list[str] = [row["id"] for row in same_bytes] if unchanged else []
    # The same certificate keeps its id (#113): detail links, bookmarks and
    # webhook URLs name that id, and every rescan used to break them. Its
    # lineage is kept too -- the row must not "replace" itself, or the expiry
    # and renewal rules would treat it as superseded.
    lineage_id: str | None = replaces_id
    if unchanged and old_leaf_row is not None:
        leaf_id = old_leaf_row["id"]
        lineage_id = old_leaf_row["replaces_cert_id"]
        if lineage_id == leaf_id:
            lineage_id = None  # never keep a self-reference
    # Operator-set data on the predecessor: the certificate's own tags and
    # its manual alert-group assignments. The rows are deleted and re-inserted
    # below, and until #113 the new row was written without either, so every
    # scan -- changed or not -- silently narrowed tag scope, compliance scope
    # and alert routing. Both move to the rewritten row, or to the successor
    # on a renewal (see CERT_ID_REFERENCES).
    carried_tags, carried_groups = _carried_operator_data(conn, predecessors)
    if old_all_ids:
        from cert_watch.database.alert_store import AlertStore

        ph = ",".join("?" * len(old_all_ids))
        conn.execute(
            f"DELETE FROM scan_posture WHERE cert_id IN ({ph})", old_all_ids
        )
        if carried:
            # Carry the whole history forward, pending included: a pending
            # alert is still deliverable and keeps its original created_at,
            # which is what the undelivered-after-24h signal reads. Deleting
            # and re-creating it each cycle reset that clock daily.
            cph = ",".join("?" * len(carried))
            conn.execute(
                f"UPDATE alerts SET cert_id = ? WHERE cert_id IN ({cph})",
                (leaf_id, *carried),
            )
        stale = [cert_id for cert_id in old_all_ids if cert_id not in set(carried)]
        if stale:
            # Preserve alert history. Pending stale work is cancelled and sent
            # conditions are closed; a dispatcher holding a live lease keeps
            # ownership of its row and is never cancelled or deleted here.
            AlertStore(db_path, initialize=False).close_for_cert_ids(
                stale,
                conn=conn,
                reason="certificate replaced before delivery",
            )
        conn.execute(
            f"DELETE FROM alert_group_certs WHERE cert_id IN ({ph})",
            old_all_ids,
        )
    for old_id in old_leaves:
        conn.execute(
            "DELETE FROM certificates WHERE parent_cert_id = ?", (old_id,)
        )
    conn.execute(
        "DELETE FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1",
        (hostname, port),
    )

    cv: int | None = None if chain_valid is None else (1 if chain_valid else 0)
    conn.execute(
        """
        INSERT INTO certificates
        (id, subject, issuer, not_before, not_after, san_dns_names,
         fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
         parent_cert_id, chain_valid, replaces_cert_id,
         created_at, updated_at, tags)
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
            lineage_id,
            now,
            now,
            carried_tags,
        ),
    )
    for group_id in carried_groups:
        conn.execute(
            "INSERT OR IGNORE INTO alert_group_certs (group_id, cert_id) VALUES (?, ?)",
            (group_id, leaf_id),
        )

    for chain_cert in chain:
        chain_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO certificates
            (id, subject, issuer, not_before, not_after, san_dns_names,
             fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
             parent_cert_id, chain_valid, replaces_cert_id,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                now,
                now,
            ),
        )
    # Reset renewal_status on every successful scan (not just fingerprint
    # change) so same-fingerprint re-issuances don't leave stale
    # renewal_status='renewed' suppressing alerts (C1/M2).
    conn.execute(
        "UPDATE hosts SET renewal_status = 'pending' "
        "WHERE hostname = ? AND port = ? AND renewal_status = 'renewed'",
        (hostname, port),
    )

    if (
        old_leaf_row is not None
        and leaf.fingerprint_sha256 != old_leaf_row["fingerprint_sha256"]
    ):
        changes = _compute_renewal_diff(dict(old_leaf_row), leaf)
        if changes:
            import logging
            logging.getLogger("cert_watch.database").info(
                "certificate renewed for %s:%s — %s",
                hostname, port, "; ".join(changes),
            )
    return leaf_id, replaces_id, unchanged


def replace_scanned(
    db_path: str | Path,
    hostname: str,
    port: int,
    leaf: Certificate,
    chain: list[Certificate],
    chain_valid: bool | None,
    *,
    conn: sqlite3.Connection | None = None,
) -> tuple[str, str | None, bool]:
    """Atomically replace all certs for host:port with new leaf + chain.

    Deletes old leaf + chain children, inserts new ones. When *conn* is
    provided it is used directly and the caller owns the transaction (which
    should be ``BEGIN IMMEDIATE``, as ``store_scanned`` uses) and commit;
    otherwise a ``BEGIN IMMEDIATE`` transaction is opened and committed.
    Returns ``(new_leaf_id, replaced_cert_id, unchanged)`` —
    ``replaced_cert_id`` is the old leaf's id when a prior leaf existed
    (None on a fresh insert); ``unchanged`` is True when that prior leaf had
    the same fingerprint, i.e. a routine rescan rather than a renewal.
    """
    if conn is None:
        with get_write_lock(), _connect(db_path) as conn:
            begin_immediate(conn)
            result = _do_replace(db_path, conn, hostname, port, leaf, chain, chain_valid)
            conn.commit()
        return result
    return _do_replace(db_path, conn, hostname, port, leaf, chain, chain_valid)


def _compute_renewal_diff(old_row: dict[str, Any], new_leaf: Certificate) -> list[str]:
    """Compute human-readable diff between old and new leaf certificates."""
    changes: list[str] = []
    old_na = old_row["not_after"]
    if old_na:
        old_expiry = _parse_iso(old_na)
        days_added = (new_leaf.not_after - old_expiry).days
        if days_added > 0:
            changes.append(f"expiry extended by {days_added} days")
    old_sans = set(parse_san_dns_names(old_row["san_dns_names"]))
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


def delete_certificate_cascade(
    db_path: str | Path,
    cert_id: str,
    *,
    guard: Callable[[sqlite3.Connection], None] | None = None,
) -> bool:
    """Delete a leaf and chain, retaining associated alerts as closed history.

    Runs in one ``BEGIN IMMEDIATE`` transaction; *guard* runs first inside it
    and may raise to refuse the delete (see ``certificate_identity``).
    """
    with get_write_lock(), _connect(db_path) as conn:
        begin_immediate(conn)
        if guard is not None:
            guard(conn)
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
        from cert_watch.database.alert_store import AlertStore
        AlertStore(db_path, initialize=False).close_for_cert_ids(
            all_ids,
            conn=conn,
            reason="certificate deleted before delivery",
        )
        conn.execute(
            f"DELETE FROM scan_posture WHERE cert_id IN ({placeholders})", all_ids
        )
        # Scope cert_history cleanup to the deleted cert's host:port + fingerprint.
        # Deleting by fingerprint alone erased other hosts' history when the same
        # cert (wildcard / load-balanced / shared corporate cert) is deployed
        # across multiple host:port pairs — silently destroying their renewal
        # analytics (lead time, cadence, automation classification).
        leaf_row = conn.execute(
            "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        fps = [
            r["fingerprint_sha256"]
            for r in conn.execute(
                f"SELECT DISTINCT fingerprint_sha256 FROM certificates "
                f"WHERE id IN ({placeholders})",
                all_ids,
            ).fetchall()
        ]
        if leaf_row is not None and fps:
            fp_placeholders = ",".join("?" * len(fps))
            conn.execute(
                f"DELETE FROM cert_history WHERE hostname = ? AND port = ? "
                f"AND fingerprint_sha256 IN ({fp_placeholders})",
                (leaf_row["hostname"], leaf_row["port"], *fps),
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
) -> list[dict[str, Any]]:
    """Walk the replaces_cert_id chain backwards from this cert.

    Returns list of dicts oldest-first: [{id, subject, fingerprint_sha256,
    not_before, not_after, replaces_cert_id, created_at, is_current}, ...].
    The given cert_id is marked is_current=True.
    """
    init_schema(db_path)
    entries: list[dict[str, Any]] = []
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
