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


def _endpoint_from_alerts(conn: Any, stale_id: str) -> tuple[str, int] | None:
    """The one endpoint the alerts on *stale_id* name, or ``None``.

    A scanned certificate's dedupe key is ``<rule>:<host>:<port>:...`` (see
    ``certificate_alert_key``). Each port monitored under the alert's host
    name is matched against that prefix exactly; an alert without a key, or
    keys naming no single endpoint, resolve nothing rather than guess.
    """
    rows = conn.execute(
        "SELECT hostname, dedupe_key FROM alerts "
        "WHERE (cert_id = ? OR trigger_cert_id = ?) AND hostname != '' "
        "AND dedupe_key IS NOT NULL",
        (stale_id, stale_id),
    ).fetchall()
    endpoints: set[tuple[str, int]] = set()
    for row in rows:
        hostname = str(row["hostname"])
        _, _, identity = str(row["dedupe_key"]).partition(":")
        ports = conn.execute(
            "SELECT port FROM hosts WHERE hostname = ? "
            "UNION SELECT port FROM certificates WHERE hostname = ? AND is_leaf = 1",
            (hostname, hostname),
        ).fetchall()
        for port_row in ports:
            if port_row["port"] is not None and identity.startswith(
                f"{hostname}:{int(port_row['port'])}:"
            ):
                endpoints.add((hostname, int(port_row["port"])))
    return endpoints.pop() if len(endpoints) == 1 else None


def resolve_current_certificate(
    db_path: str | Path, stale_id: str
) -> CurrentCertificateRef | None:
    """Map an id with no certificate row to the endpoint's current leaf.

    Certificate ids change when a certificate is renewed (and, before #113,
    on every rescan), so links to them go stale. The endpoint survives, and
    each of these still records which endpoint an old id belonged to:

    1. a host id (the stable address of an endpoint);
    2. the successor row, whose ``replaces_cert_id`` names the old id;
    3. the ``cert_added`` / ``cert_renewed`` lifecycle event written when the
       id was issued (kept for the event-log retention period);
    4. an alert that fired on the id. Alerts record the host name but no
       port column, so the endpoint is taken from the alert's dedupe key,
       which names ``host:port`` for a scanned certificate. The host name
       alone is never enough: it can't tell ``host:443`` from ``host:8443``.

    Returns ``None`` when none of them knows the id. Performs no scope
    check: the caller must authorize the returned certificate.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        host = conn.execute(
            "SELECT hostname, port FROM hosts WHERE id = ?", (stale_id,)
        ).fetchone()
        if host is not None:
            current = _current_leaf_for_endpoint(conn, host["hostname"], host["port"])
            return CurrentCertificateRef(current, superseded=False) if current else None

        successor = conn.execute(
            "SELECT hostname, port FROM certificates "
            "WHERE replaces_cert_id = ? AND is_leaf = 1 AND hostname IS NOT NULL",
            (stale_id,),
        ).fetchone()
        endpoint: tuple[str, int] | None = (
            (successor["hostname"], successor["port"]) if successor is not None else None
        )

        if endpoint is None:
            event = conn.execute(
                "SELECT json_extract(payload, '$.hostname') AS hostname, "
                "json_extract(payload, '$.port') AS port FROM event_log "
                "WHERE event_type IN ('cert_added', 'cert_renewed') "
                "AND (json_extract(payload, '$.cert_id') = ? "
                "OR json_extract(payload, '$.replaced_cert_id') = ?) "
                "ORDER BY id DESC LIMIT 1",
                (stale_id, stale_id),
            ).fetchone()
            if event is not None and event["hostname"] and event["port"] is not None:
                endpoint = (str(event["hostname"]), int(event["port"]))

        if endpoint is None:
            endpoint = _endpoint_from_alerts(conn, stale_id)
        if endpoint is None:
            return None

        current = _current_leaf_for_endpoint(conn, *endpoint)
    if current is None or current == stale_id:
        return None
    return CurrentCertificateRef(current, superseded=True)


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
