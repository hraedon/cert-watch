"""Drift detection and certificate history queries."""
from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database.connection import _connect, _iso, _parse_iso
from cert_watch.database.schema import init_schema


@dataclass
class DriftEvent:
    """A single field-level change detected between two scans."""
    field: str
    old: str
    new: str
    severity: str  # "high" | "info"


_GRADE_ORDER = {"A+": 5, "A": 4, "B": 3, "C": 2, "F": 1, "": 0}

_TLS_ORDER = {"TLSv1.3": 3, "TLSv1.2": 2, "TLSv1.1": 1, "TLSv1.0": 0}


def _grade_value(grade: str) -> int:
    return _GRADE_ORDER.get(grade, 0)


def _tls_value(version: str) -> int:
    return _TLS_ORDER.get(version, -1)


def _parse_key_algo(algo_str: str) -> tuple[str, int]:
    """Extract (type, size) from key algo string like 'RSA-2048' or 'EC-P256'."""
    if not algo_str:
        return ("", 0)
    parts = algo_str.split("-", 1)
    if len(parts) == 2:
        try:
            return (parts[0], int(parts[1]))
        except ValueError:
            return (parts[0], 0)
    return (algo_str, 0)


def _is_sha1_algo(algo: str) -> bool:
    return "sha1" in algo.lower() or "SHA-1" in algo


def _extract_key_algo(raw_der: bytes) -> str:
    """Extract key algorithm string from DER-encoded certificate."""
    try:
        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        cert = x509.load_der_x509_certificate(raw_der)
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return f"RSA-{key.key_size}"
        if isinstance(key, ec.EllipticCurvePublicKey):
            return f"EC-{key.curve.name}"
        return type(key).__name__
    except (ValueError, TypeError, ImportError, UnsupportedAlgorithm):
        return ""


def _extract_sig_algo(raw_der: bytes) -> str:
    """Extract signature algorithm string from DER-encoded certificate."""
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(raw_der)
        oid = cert.signature_algorithm_oid
        return oid._name if hasattr(oid, "_name") else oid.dotted_string
    except (ValueError, TypeError, ImportError):
        return ""


def _compute_drift_events(
    old: dict,
    new_leaf: Certificate,
    new_posture_grade: str = "",
    new_protocol_version: str = "",
    new_key_algo: str = "",
    new_sig_algo: str = "",
) -> list[DriftEvent]:
    """Compare a previous cert_history row with a new scan.

    Returns a list of DriftEvent with severity classification.
    """
    events: list[DriftEvent] = []

    # Issuer change → high
    old_issuer = old.get("issuer", "")
    if old_issuer and old_issuer != new_leaf.issuer:
        events.append(DriftEvent("issuer", old_issuer, new_leaf.issuer, "high"))

    # Key algorithm change — check for key size drop → high
    old_key = old.get("key_algo", "")
    new_key = new_key_algo
    if old_key and new_key and old_key != new_key:
        old_type, old_size = _parse_key_algo(old_key)
        new_type, new_size = _parse_key_algo(new_key)
        if old_type == new_type and new_size > 0 and old_size > 0 and new_size < old_size:
            events.append(DriftEvent("key_algo", old_key, new_key, "high"))
        else:
            events.append(DriftEvent("key_algo", old_key, new_key, "info"))

    # Signature algorithm weakened (e.g. SHA-256 → SHA-1) → high
    old_sig = old.get("sig_algo", "")
    new_sig = new_sig_algo
    if old_sig and new_sig and old_sig != new_sig:
        if _is_sha1_algo(new_sig) and not _is_sha1_algo(old_sig):
            events.append(DriftEvent("sig_algo", old_sig, new_sig, "high"))
        else:
            events.append(DriftEvent("sig_algo", old_sig, new_sig, "info"))

    # Posture grade dropped → high
    old_grade = old.get("posture_grade", "")
    grade = new_posture_grade
    if old_grade and grade and old_grade != grade:
        if _grade_value(grade) < _grade_value(old_grade):
            events.append(DriftEvent("posture_grade", old_grade, grade, "high"))
        else:
            events.append(DriftEvent("posture_grade", old_grade, grade, "info"))

    # Protocol version downgraded → high
    old_proto = old.get("protocol_version", "")
    proto = new_protocol_version
    if old_proto and proto and old_proto != proto:
        if _tls_value(proto) < _tls_value(old_proto):
            events.append(DriftEvent("protocol_version", old_proto, proto, "high"))
        else:
            events.append(DriftEvent("protocol_version", old_proto, proto, "info"))

    # SAN count changed → info
    old_san_count = old.get("san_count")
    new_san_count = len(new_leaf.san_dns_names)
    if old_san_count is not None and old_san_count != new_san_count:
        events.append(DriftEvent("san_count", str(old_san_count), str(new_san_count), "info"))

    # Expiry shift — benign renewal (same issuer, later not_after) = info
    old_not_after = old.get("not_after", "")
    if old_not_after:
        old_expiry = _parse_iso(old_not_after)
        days_added = (new_leaf.not_after - old_expiry).days
        if days_added > 0 and old_issuer == new_leaf.issuer:
            events.append(DriftEvent("not_after", old_not_after, _iso(new_leaf.not_after), "info"))

    return events


def detect_drift(
    db_path: str | Path,
    hostname: str,
    port: int,
    new_leaf: Certificate,
    posture_grade: str = "",
    protocol_version: str = "",
    key_algo: str = "",
    sig_algo: str = "",
    *,
    conn: sqlite3.Connection | None = None,
) -> list[DriftEvent]:
    """Look up the most recent cert_history row for host:port and compare with the new scan.

    Returns DriftEvents (empty if no previous history or no changes). When
    *conn* is provided it is used directly and the caller owns commit/rollback.
    """
    if conn is None:
        init_schema(db_path)
        with _connect(db_path) as conn:
            row = conn.execute(
                """SELECT fingerprint_sha256, issuer, not_after, key_algo, sig_algo,
                          posture_grade, protocol_version, san_count
                   FROM cert_history
                   WHERE hostname = ? AND port = ?
                   ORDER BY scanned_at DESC
                   LIMIT 1""",
                (hostname, port),
            ).fetchone()
    else:
        row = conn.execute(
            """SELECT fingerprint_sha256, issuer, not_after, key_algo, sig_algo,
                      posture_grade, protocol_version, san_count
               FROM cert_history
               WHERE hostname = ? AND port = ?
               ORDER BY scanned_at DESC
               LIMIT 1""",
            (hostname, port),
        ).fetchone()
    if row is None:
        return []
    return _compute_drift_events(
        dict(row), new_leaf,
        new_posture_grade=posture_grade,
        new_protocol_version=protocol_version,
        new_key_algo=key_algo,
        new_sig_algo=sig_algo,
    )


def _drift_summary(events: list[DriftEvent]) -> str:
    """Format drift events into a human-readable summary line."""
    if not events:
        return ""
    high = [e for e in events if e.severity == "high"]
    if high:
        parts = [f"{e.field}: {e.old} -> {e.new}" for e in high]
        return "DRIFT " + "; ".join(parts)
    parts = [f"{e.field}: {e.old} -> {e.new}" for e in events]
    return "drift " + "; ".join(parts)


def create_drift_alert(
    db_path: str | Path,
    cert_id: str,
    hostname: str,
    port: int,
    events: list[DriftEvent],
    extra_recipients: list[str] | None = None,
    *,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Create a drift alert if any high-severity events exist.

    Returns the alert id if created, None otherwise. When *conn* is provided
    it is used directly and the caller owns commit/rollback.
    """
    from cert_watch.database.repo import Alert, SqliteAlertRepository

    high = [e for e in events if e.severity == "high"]
    if not high:
        return None

    summary = _drift_summary(events)
    message = f"{hostname}:{port} — {summary}"

    subject = ""
    if conn is None:
        with _connect(db_path) as c:
            row = c.execute("SELECT subject FROM certificates WHERE id = ?", (cert_id,)).fetchone()
            if row:
                subject = row["subject"] or ""
        # Let the repository open its own connection so it can commit.
        alert_conn = None
    else:
        row = conn.execute("SELECT subject FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if row:
            subject = row["subject"] or ""
        alert_conn = conn

    alert = Alert(
        cert_id=cert_id,
        alert_type="drift",
        status="pending",
        message=message,
        extra_recipients=extra_recipients or [],
        hostname=hostname,
        subject=subject,
    )
    alert_repo = SqliteAlertRepository(db_path)
    return alert_repo.create(alert, conn=alert_conn)


def record_cert_history(
    db_path: str | Path,
    hostname: str,
    port: int,
    leaf: Certificate,
    posture_grade: str = "",
    protocol_version: str = "",
    scanned_at: str | None = None,
    *,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Append a per-scan snapshot row to cert_history.

    Called after every successful leaf scan. Returns the new row id. When
    *conn* is provided it is used directly and the caller owns commit/rollback.
    """
    if conn is None:
        init_schema(db_path)
    row_id = str(uuid.uuid4())
    if scanned_at is None:
        scanned_at = _iso(datetime.now(UTC))

    key_algo = _extract_key_algo(leaf.raw_der) if leaf.raw_der else ""
    sig_algo = _extract_sig_algo(leaf.raw_der) if leaf.raw_der else ""

    params = (
        row_id,
        hostname,
        port,
        leaf.fingerprint_sha256,
        leaf.issuer,
        _iso(leaf.not_after),
        key_algo,
        sig_algo,
        posture_grade,
        protocol_version,
        len(leaf.san_dns_names),
        scanned_at,
        _iso(leaf.not_before),
    )

    if conn is None:
        with _connect(db_path) as conn:
            conn.execute(
                """INSERT INTO cert_history
                (id, hostname, port, fingerprint_sha256, issuer, not_after,
                 key_algo, sig_algo, posture_grade, protocol_version, san_count,
                 scanned_at, not_before)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                params,
            )
            conn.commit()
    else:
        conn.execute(
            """INSERT INTO cert_history
            (id, hostname, port, fingerprint_sha256, issuer, not_after,
             key_algo, sig_algo, posture_grade, protocol_version, san_count,
             scanned_at, not_before)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            params,
        )
    return row_id


def purge_old_history(db_path: str | Path, retention_days: int) -> int:
    """Delete cert_history rows older than *retention_days*. Returns count deleted.

    A non-positive ``retention_days`` disables purging (returns 0).
    """
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    try:
        init_schema(db_path)
        with _connect(db_path) as conn:
            cur = conn.execute("DELETE FROM cert_history WHERE scanned_at < ?", (cutoff,))
            deleted = cur.rowcount
            conn.commit()
        if deleted:
            import logging
            logging.getLogger("cert_watch.database").info(
                "purged %d cert_history rows older than %d days", deleted, retention_days
            )
        return deleted
    except (sqlite3.Error, OSError):
        import logging
        logging.getLogger("cert_watch.database").warning("cert_history purge failed", exc_info=True)
        return 0


def purge_old_scan_history(db_path: str | Path, retention_days: int) -> int:
    """Delete scan_history rows older than *retention_days*. Returns count deleted.

    A non-positive ``retention_days`` disables purging (returns 0).
    """
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    try:
        init_schema(db_path)
        with _connect(db_path) as conn:
            cur = conn.execute("DELETE FROM scan_history WHERE scanned_at < ?", (cutoff,))
            deleted = cur.rowcount
            conn.commit()
        if deleted:
            import logging
            logging.getLogger("cert_watch.database").info(
                "purged %d scan_history rows older than %d days", deleted, retention_days
            )
        return deleted
    except (sqlite3.Error, OSError):
        import logging
        logging.getLogger("cert_watch.database").warning("scan_history purge failed", exc_info=True)
        return 0


def list_cert_history(
    db_path: str | Path,
    hostname: str,
    port: int,
    limit: int = 365,
) -> list[dict]:
    """Return scan history for a specific host:port, newest first."""
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT id, hostname, port, fingerprint_sha256, issuer, not_after,
                      key_algo, sig_algo, posture_grade, protocol_version,
                      san_count, scanned_at
               FROM cert_history
               WHERE hostname = ? AND port = ?
               ORDER BY scanned_at DESC
               LIMIT ?""",
            (hostname, port, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def list_tls_version_trends(
    db_path: str | Path,
    days: int = 30,
) -> list[dict]:
    """Fleet TLS version distribution over time.

    Returns [{date, protocol_version, count}] for the last *days* days.
    """
    init_schema(db_path)
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT DATE(scanned_at) as date, protocol_version, COUNT(*) as count
               FROM cert_history
               WHERE scanned_at >= ? AND protocol_version IS NOT NULL AND protocol_version != ''
               GROUP BY DATE(scanned_at), protocol_version
               ORDER BY date DESC""",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_grade_trends(
    db_path: str | Path,
    days: int = 30,
) -> list[dict]:
    """Fleet posture grade distribution over time.

    Returns [{date, posture_grade, count}] for the last *days* days.
    """
    init_schema(db_path)
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT DATE(scanned_at) as date, posture_grade, COUNT(*) as count
               FROM cert_history
               WHERE scanned_at >= ? AND posture_grade IS NOT NULL AND posture_grade != ''
               GROUP BY DATE(scanned_at), posture_grade
               ORDER BY date DESC""",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]
