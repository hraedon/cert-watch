"""The cached chain status that SQL status counts read, and its validity rule.

A leaf's chain status (:func:`cert_watch.cert_chain.chain_status`) needs
signature verification against the uploaded trust anchors and the system trust
store, so SQL cannot compute it. Aggregating the status rule in SQL
(:mod:`cert_watch.status_rule`) therefore reads a cached copy on the leaf row.

The cache validates itself instead of trusting every write path to maintain
it. ``chain_status_basis`` records exactly what the status was computed from:

    <trust digest>:<leaf fingerprint>:<chain fingerprints, in stored order>

where the trust digest covers the uploaded anchors and the system store. SQL
uses a cached status only while its basis equals the basis the row has *now*
(:func:`verified_chain_status_sql`). A row whose basis moved -- a rescan, an
upload, an anchor added or removed, a chain certificate swapped for another
with the same count, a restored backup, an upgraded CA bundle, a hand edit --
reads as ``unverified``, which the status rule treats like any unverified
chain: never Healthy. The cache can therefore be missing or stale without
ever making a certificate look healthier than it is (it fails closed).

:func:`refresh_chain_status` recomputes the rows whose basis moved and
publishes each status with compare-and-set: inside the write transaction it
re-reads the trust digest and each row's current basis, and writes only when
both still equal the inputs the status was computed from. A concurrent anchor
change or rescan leaves the row unverified until the next refresh instead of
publishing a status computed from inputs that no longer hold.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect, _iso, _row_to_cert, get_write_lock

logger = logging.getLogger("cert_watch.database.chain_status_cache")

UNVERIFIED = "unverified"

_CHUNK = 500
_ATTEMPTS = 3

_system_digest: str | None = None


class _ChainIds:
    """SQL aggregate: chain fingerprints joined in stored (rowid) order.

    Order matters to chain validation, and ``group_concat`` promises none, so
    the order is imposed here rather than trusted to the query plan.
    """

    def __init__(self) -> None:
        self.items: list[tuple[int, str]] = []

    def step(self, rowid: int, fingerprint: str | None) -> None:
        self.items.append((rowid, fingerprint or ""))

    def finalize(self) -> str:
        return ",".join(fp for _, fp in sorted(self.items))


def register_sql_functions(conn: sqlite3.Connection) -> None:
    conn.create_aggregate("cw_chain_ids", 2, _ChainIds)  # type: ignore[arg-type]


def basis_sql(alias: str = "c") -> str:
    """SQL for the basis leaf row *alias* has now; binds one ``?`` (trust digest)."""
    return (
        f"(? || ':' || COALESCE({alias}.fingerprint_sha256, '') || ':' || COALESCE(("
        f"SELECT cw_chain_ids(ch.rowid, ch.fingerprint_sha256) FROM certificates ch"
        f" WHERE ch.parent_cert_id = {alias}.id), ''))"
    )


def verified_chain_status_sql(alias: str = "c") -> str:
    """SQL for the chain status of *alias* the status rule may use; binds one ``?``.

    The cached status while it is current, else ``unverified``.
    """
    return (
        f"(CASE WHEN {alias}.chain_status IS NOT NULL"
        f" AND {alias}.chain_status_basis = {basis_sql(alias)}"
        f" THEN {alias}.chain_status ELSE '{UNVERIFIED}' END)"
    )


def _basis(trust: str, leaf_fp: str | None, chain_fps: list[str | None]) -> str:
    return f"{trust}:{leaf_fp or ''}:{','.join(fp or '' for fp in chain_fps)}"


def _system_store_digest() -> str:
    """Digest of the system trust store this process verifies against."""
    global _system_digest
    if _system_digest is None:
        from cryptography.hazmat.primitives import hashes

        from cert_watch.cert_chain import _load_system_ca_cache

        _, by_subject = _load_system_ca_cache()
        fingerprints = sorted(
            cert.fingerprint(hashes.SHA256()).hex()
            for certs in by_subject.values()
            for cert in certs
        )
        _system_digest = hashlib.sha256(",".join(fingerprints).encode()).hexdigest()
    return _system_digest


def _trust_digest(anchor_fingerprints: list[str]) -> str:
    material = (
        "anchors:" + ",".join(sorted(anchor_fingerprints)) + "|system:" + _system_store_digest()
    )
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def trust_basis(conn: sqlite3.Connection) -> str:
    """Digest of every trust input a leaf's chain status depends on."""
    return _trust_digest(
        [row[0] for row in conn.execute("SELECT fingerprint_sha256 FROM trust_anchors")]
    )


@dataclass(frozen=True)
class StatusContext:
    """One request's inputs to the SQL status rule: one instant, one trust digest."""

    now: datetime
    trust: str

    @property
    def sql_now(self) -> str:
        return _iso(self.now)


def prepare_status(db_path: str | Path, now: datetime | None = None) -> StatusContext:
    """Refresh the cache, then fix the instant and trust digest for one request."""
    refresh_chain_status(db_path)
    with _connect(db_path) as conn:
        trust = trust_basis(conn)
    return StatusContext(now or datetime.now(UTC), trust)


def _compute(
    conn: sqlite3.Connection, leaf_ids: list[str], anchors: list[Any], trust: str
) -> list[tuple[str, str, str]]:
    """``(status, basis, leaf id)`` for each leaf, from the rows read now."""
    from cert_watch import cert_chain

    ph = ",".join("?" * len(leaf_ids))
    leaves = conn.execute(f"SELECT * FROM certificates WHERE id IN ({ph})", leaf_ids).fetchall()
    children: dict[str, list[Any]] = {}
    for row in conn.execute(
        f"SELECT rowid AS _rowid, * FROM certificates WHERE parent_cert_id IN ({ph})"
        " ORDER BY rowid",
        leaf_ids,
    ).fetchall():
        children.setdefault(row["parent_cert_id"], []).append(row)
    updates: list[tuple[str, str, str]] = []
    for leaf in leaves:
        chain = children.get(leaf["id"], [])
        try:
            status = cert_chain.chain_status(
                _row_to_cert(leaf), [_row_to_cert(c) for c in chain], anchors
            )
        except Exception:  # one unreadable row must not block the rest
            logger.warning("chain status failed for certificate %s", leaf["id"], exc_info=True)
            continue  # left unverified, which the status rule never calls healthy
        basis = _basis(trust, leaf["fingerprint_sha256"], [c["fingerprint_sha256"] for c in chain])
        updates.append((status, basis, leaf["id"]))
    return updates


def refresh_chain_status(db_path: str | Path) -> int:
    """Recompute and publish the cached status of every leaf whose basis moved.

    Returns how many statuses were published. Reads never depend on this
    succeeding: a row it could not publish stays ``unverified``.
    """
    published = 0
    for _ in range(_ATTEMPTS):
        with _connect(db_path) as conn:
            anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()
            # The digest comes from the same rows the statuses are computed
            # against, so the two cannot describe different anchor sets.
            trust = _trust_digest([r["fingerprint_sha256"] for r in anchor_rows])
            stale = [
                row[0]
                for row in conn.execute(
                    "SELECT c.id FROM certificates c WHERE c.is_leaf = 1"
                    f" AND c.chain_status_basis IS NOT {basis_sql('c')}",
                    (trust,),
                )
            ]
            if not stale:
                return published
            anchors = [_row_to_cert({**dict(r), "is_leaf": 0}) for r in anchor_rows]
            updates: list[tuple[str, str, str]] = []
            for start in range(0, len(stale), _CHUNK):
                updates += _compute(conn, stale[start : start + _CHUNK], anchors, trust)
        try:
            with get_write_lock(), _connect(db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    if trust_basis(conn) != trust:
                        conn.rollback()
                        continue  # anchors changed while computing: start again
                    cursor = conn.executemany(
                        "UPDATE certificates SET chain_status = ?, chain_status_basis = ?"
                        f" WHERE id = ? AND {basis_sql('certificates')} = ?",
                        [(status, basis, leaf_id, trust, basis)
                         for status, basis, leaf_id in updates],
                    )
                    published += cursor.rowcount
                    conn.commit()
                except BaseException:
                    conn.rollback()
                    raise
        except sqlite3.Error:
            logger.warning("could not store %d chain statuses", len(updates), exc_info=True)
            return published
        return published
    return published
