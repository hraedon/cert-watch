"""Single-certificate detail query (targeted JOIN replacement)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cert_watch.certificate_model import Certificate
from cert_watch.database.connection import _connect, _row_to_cert
from cert_watch.database.dashboard_rows import _build_dashboard_rows
from cert_watch.database.dashboard_unified import _build_unified_from_dash
from cert_watch.database.posture import get_posture_for_cert
from cert_watch.database.repo import HostEntry, SqliteHostRepository
from cert_watch.database.schema import init_schema


@dataclass(frozen=True)
class LatestScanRecord:
    status: str
    scanned_at: str
    error_message: str | None


@dataclass(frozen=True)
class StoredCertificateDetailRecords:
    cert: Certificate
    chain: tuple[tuple[str, Certificate], ...]
    hostname: str
    port: int
    host: HostEntry | None


@dataclass(frozen=True)
class PendingHostDetailRecords:
    host: HostEntry
    latest_scan: LatestScanRecord | None


def get_stored_certificate_detail_records(
    db_path: str | Path, cert_id: str
) -> StoredCertificateDetailRecords | None:
    """Load the certificate, chain, endpoint, and host context in one place."""
    init_schema(db_path)
    with _connect(db_path) as conn:
        leaf = conn.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if leaf is None:
            return None
        chain_rows = conn.execute(
            "SELECT * FROM certificates WHERE parent_cert_id = ? AND is_leaf = 0",
            (cert_id,),
        ).fetchall()
        hostname = leaf["hostname"] or ""
        port = leaf["port"] or 443
        host_row = None
        if hostname:
            host_row = conn.execute(
                "SELECT * FROM hosts WHERE hostname = ? AND port = ?",
                (hostname, port),
            ).fetchone()
    return StoredCertificateDetailRecords(
        cert=_row_to_cert(leaf),
        chain=tuple((row["id"], _row_to_cert(row)) for row in chain_rows),
        hostname=hostname,
        port=port,
        host=(SqliteHostRepository._row_to_host(host_row) if host_row is not None else None),
    )


@dataclass(frozen=True)
class CurrentCertificateRef:
    """Where an id that no longer names a certificate row now points."""

    cert_id: str
    # True when the id named an earlier certificate for the endpoint (a
    # renewal replaced it); False when it was the endpoint's own host id.
    superseded: bool


def _current_leaf_for_endpoint(conn: Any, hostname: str, port: int) -> str | None:
    row = conn.execute(
        "SELECT id FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1 "
        "ORDER BY created_at DESC LIMIT 1",
        (hostname, port),
    ).fetchone()
    return str(row["id"]) if row is not None else None


def resolve_current_certificate(
    db_path: str | Path, stale_id: str
) -> CurrentCertificateRef | None:
    """Map an id with no certificate row to the certificate to show instead.

    1. A host id (the stable address of an endpoint) opens the endpoint's
       current certificate.
    2. A certificate id that renewals replaced opens the certificate they
       lead to, found by :func:`~cert_watch.database.cert_lineage.navigation_hint`
       -- the same resolver the mutation routes use for their "renewed,
       nothing was changed" answer, so the two never disagree. It follows
       lineage only from the id's own issuance event, on that endpoint, one
       unambiguous step at a time; anything else resolves to nothing.

    An id whose certificate was deleted (not renewed), or whose events have
    aged out of the event log, is not resolved. Performs no scope check: the
    caller must authorize the returned certificate.
    """
    from cert_watch.database.cert_lineage import navigation_hint

    init_schema(db_path)
    with _connect(db_path) as conn:
        host = conn.execute(
            "SELECT hostname, port FROM hosts WHERE id = ?", (stale_id,)
        ).fetchone()
        if host is not None:
            current = _current_leaf_for_endpoint(conn, host["hostname"], host["port"])
            return CurrentCertificateRef(current, superseded=False) if current else None
        head = navigation_hint(conn, stale_id)
    return CurrentCertificateRef(head, superseded=True) if head is not None else None


def get_pending_host_detail_records(
    db_path: str | Path, host_id: str
) -> PendingHostDetailRecords | None:
    """Load a registered host and its latest scan result."""
    init_schema(db_path)
    with _connect(db_path) as conn:
        host_row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if host_row is None:
            return None
    return PendingHostDetailRecords(
        host=SqliteHostRepository._row_to_host(host_row),
        latest_scan=get_latest_scan_record(db_path, host_row["hostname"], host_row["port"]),
    )


def get_latest_scan_record(
    db_path: str | Path, hostname: str, port: int
) -> LatestScanRecord | None:
    """The endpoint's most recent scan attempt, whatever its outcome."""
    with _connect(db_path) as conn:
        scan_row = conn.execute(
            "SELECT status, scanned_at, error_message FROM scan_history "
            "WHERE hostname = ? AND port = ? "
            "ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (hostname, port),
        ).fetchone()
    if scan_row is None:
        return None
    return LatestScanRecord(
        status=scan_row["status"],
        scanned_at=scan_row["scanned_at"],
        error_message=scan_row["error_message"],
    )


def get_cert_detail(db_path: str | Path, cert_id: str) -> dict[str, Any] | None:
    """Return a single leaf certificate's dashboard row with chain + posture.

    Targeted JOIN replacement for scanning the full unified list to find one
    cert.  Returns a rich dashboard dict (same shape as the dashboard rows)
    augmented with ``posture`` (latest posture evaluation or ``None``) and
    host context (owner/renewal fields) when the cert maps to a tracked host.
    Returns ``None`` if no leaf cert with that id exists.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        leaf = conn.execute(
            "SELECT * FROM certificates WHERE id = ? AND is_leaf = 1", (cert_id,)
        ).fetchone()
        if leaf is None:
            return None
        chain_rows = conn.execute(
            "SELECT * FROM certificates WHERE parent_cert_id = ?", (cert_id,)
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        host_rows = []
        scan_rows = []
        if leaf["hostname"]:
            host_rows = conn.execute(
                "SELECT * FROM hosts WHERE hostname = ? AND port = ?",
                (leaf["hostname"], leaf["port"]),
            ).fetchall()
            scan_rows = conn.execute(
                """
                SELECT hostname, port, status, scanned_at, error_message
                FROM scan_history sh1
                WHERE sh1.hostname = ? AND sh1.port = ?
                  AND scanned_at = (
                    SELECT MAX(scanned_at) FROM scan_history sh2
                    WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
                  )
                """,
                (leaf["hostname"], leaf["port"]),
            ).fetchall()

    dash = _build_dashboard_rows([leaf, *chain_rows], anchor_rows)
    if not dash:
        return None
    if host_rows:
        unified = _build_unified_from_dash(dash, host_rows, scan_rows)
        row = next((e for e in unified if e.get("id") == cert_id), dash[0])
    else:
        row = dash[0]
        row["kind"] = "uploaded" if leaf["source"] != "scanned" else "scanned"
    row["posture"] = get_posture_for_cert(db_path, cert_id)
    return row
