"""SQLite implementation of repository ABCs.

This is the PRIMARY database implementation for cert-watch v1.
Future versions may add MSSQL or PostgreSQL implementations.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from ..core.config import Settings
from ..models.alert import Alert, AlertStatus, AlertType
from ..models.certificate import Certificate, CertificateSource, CertificateType
from ..models.scan_history import ScanHistory, ScanStatus
from .base import AlertRepository, CertificateRepository, ScanHistoryRepository


# Naive UTC datetime adapter for SQLite
def adapt_datetime(dt: datetime) -> str:
    return dt.isoformat()


def convert_datetime(val: bytes) -> datetime:
    return datetime.fromisoformat(val.decode())


sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_datetime)


class SQLiteConnectionPool:
    """Simple connection pool for SQLite.

    Provides thread-local connections.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        """Create database tables if they don't exist."""
        with self.get_connection() as conn:
            conn.executescript(_SCHEMA_SQL)

    @contextmanager
    def get_connection(self):
        """Get a database connection as a context manager.

        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,  # FastAPI handles thread safety
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# Database schema - agents should NOT modify this file
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_type TEXT NOT NULL CHECK(certificate_type IN ('leaf', 'intermediate', 'root')),
    source TEXT NOT NULL CHECK(source IN ('scanned', 'uploaded')),
    hostname TEXT,
    port INTEGER,
    label TEXT,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    serial_number TEXT NOT NULL,
    chain_fingerprint TEXT,
    chain_position INTEGER DEFAULT 0,
    pem_data BLOB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at TIMESTAMP,
    source_hostname TEXT,
    source_port INTEGER
);

CREATE INDEX IF NOT EXISTS idx_certificates_fingerprint ON certificates(fingerprint);
CREATE INDEX IF NOT EXISTS idx_certificates_hostname ON certificates(hostname);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_chain ON certificates(chain_fingerprint);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL CHECK(alert_type IN ('expiry_warning', 'expired', 'scan_failure')),
    days_remaining INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed')),
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_certificate ON alerts(certificate_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'success' CHECK(status IN ('success', 'partial', 'failure')),
    total_hosts INTEGER DEFAULT 0,
    successful_hosts INTEGER DEFAULT 0,
    failed_hosts INTEGER DEFAULT 0,
    updated_certificates INTEGER DEFAULT 0,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_history_started ON scan_history(started_at);
"""


class SQLiteCertificateRepository(CertificateRepository):
    """SQLite implementation of CertificateRepository."""

    def __init__(self, pool: SQLiteConnectionPool):
        self._pool = pool

    def _row_to_certificate(self, row: sqlite3.Row) -> Certificate:
        """Convert a database row to a Certificate model."""
        return Certificate(
            id=row["id"],
            certificate_type=CertificateType[row["certificate_type"].upper()],
            source=CertificateSource[row["source"].upper()],
            hostname=row["hostname"],
            port=row["port"],
            label=row["label"],
            subject=row["subject"],
            issuer=row["issuer"],
            not_before=row["not_before"],
            not_after=row["not_after"],
            fingerprint=row["fingerprint"],
            serial_number=row["serial_number"],
            chain_fingerprint=row["chain_fingerprint"],
            chain_position=row["chain_position"] or 0,
            pem_data=row["pem_data"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_scanned_at=row["last_scanned_at"],
            source_hostname=row["source_hostname"],
            source_port=row["source_port"],
        )

    async def get_by_id(self, cert_id: int) -> Certificate | None:
        """Get certificate by ID."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_certificate(row)

    async def get_by_fingerprint(self, fingerprint: str) -> Certificate | None:
        """Get certificate by fingerprint."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_certificate(row)

    async def get_all(self, limit: int = 1000) -> list[Certificate]:
        """Get all certificates, sorted by urgency (days remaining ascending)."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """SELECT * FROM certificates
                   ORDER BY not_after ASC
                   LIMIT ?""",
                (limit,),
            )
            rows = cursor.fetchall()
            return [self._row_to_certificate(row) for row in rows]

    async def get_by_hostname(self, hostname: str, port: int | None = None) -> list[Certificate]:
        """Get certificates by hostname."""
        with self._pool.get_connection() as conn:
            if port is not None:
                cursor = conn.execute(
                    """SELECT * FROM certificates WHERE hostname = ? AND port = ?
                       ORDER BY not_after ASC""",
                    (hostname, port),
                )
            else:
                cursor = conn.execute(
                    """SELECT * FROM certificates WHERE hostname = ?
                       ORDER BY not_after ASC""",
                    (hostname,),
                )
            rows = cursor.fetchall()
            return [self._row_to_certificate(row) for row in rows]

    async def create(self, cert: Certificate) -> Certificate:
        """Create new certificate entry."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO certificates (
                    certificate_type, source, hostname, port, label,
                    subject, issuer, not_before, not_after, fingerprint,
                    serial_number, chain_fingerprint, chain_position, pem_data,
                    created_at, updated_at, last_scanned_at,
                    source_hostname, source_port
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert.certificate_type.name.lower(),
                    cert.source.name.lower(),
                    cert.hostname,
                    cert.port,
                    cert.label,
                    cert.subject,
                    cert.issuer,
                    cert.not_before,
                    cert.not_after,
                    cert.fingerprint,
                    cert.serial_number,
                    cert.chain_fingerprint,
                    cert.chain_position,
                    cert.pem_data,
                    cert.created_at,
                    cert.updated_at,
                    cert.last_scanned_at,
                    cert.source_hostname,
                    cert.source_port,
                ),
            )
            cert.id = cursor.lastrowid
            return cert

    async def update(self, cert: Certificate) -> Certificate:
        """Update existing certificate."""
        with self._pool.get_connection() as conn:
            conn.execute(
                """UPDATE certificates SET
                    certificate_type = ?,
                    source = ?,
                    hostname = ?,
                    port = ?,
                    label = ?,
                    subject = ?,
                    issuer = ?,
                    not_before = ?,
                    not_after = ?,
                    fingerprint = ?,
                    serial_number = ?,
                    chain_fingerprint = ?,
                    chain_position = ?,
                    pem_data = ?,
                    updated_at = ?,
                    last_scanned_at = ?,
                    source_hostname = ?,
                    source_port = ?
                WHERE id = ?
                """,
                (
                    cert.certificate_type.name.lower(),
                    cert.source.name.lower(),
                    cert.hostname,
                    cert.port,
                    cert.label,
                    cert.subject,
                    cert.issuer,
                    cert.not_before,
                    cert.not_after,
                    cert.fingerprint,
                    cert.serial_number,
                    cert.chain_fingerprint,
                    cert.chain_position,
                    cert.pem_data,
                    datetime.utcnow(),
                    cert.last_scanned_at,
                    cert.source_hostname,
                    cert.source_port,
                    cert.id,
                ),
            )
            return cert

    async def delete(self, cert_id: int) -> bool:
        """Delete certificate by ID."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
            return cursor.rowcount > 0

    async def get_chain_for_leaf(self, leaf_fingerprint: str) -> list[Certificate]:
        """Get chain certificates for a given leaf."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """SELECT * FROM certificates
                   WHERE chain_fingerprint = ?
                   ORDER BY chain_position ASC""",
                (leaf_fingerprint,),
            )
            rows = cursor.fetchall()
            return [self._row_to_certificate(row) for row in rows]


class SQLiteAlertRepository(AlertRepository):
    """SQLite implementation of AlertRepository."""

    def __init__(self, pool: SQLiteConnectionPool):
        self._pool = pool

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        """Convert a database row to an Alert model."""
        return Alert(
            id=row["id"],
            certificate_id=row["certificate_id"],
            alert_type=AlertType[row["alert_type"].upper()],
            days_remaining=row["days_remaining"],
            status=AlertStatus[row["status"].upper()],
            recipient=row["recipient"],
            subject=row["subject"],
            body=row["body"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            sent_at=row["sent_at"],
        )

    async def get_by_id(self, alert_id: int) -> Alert | None:
        """Get alert by ID."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_alert(row)

    async def get_pending(self) -> list[Alert]:
        """Get all pending alerts."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """SELECT * FROM alerts WHERE status = 'pending'
                   ORDER BY created_at ASC"""
            )
            rows = cursor.fetchall()
            return [self._row_to_alert(row) for row in rows]

    async def get_for_certificate(self, cert_id: int, limit: int = 100) -> list[Alert]:
        """Get alerts for a specific certificate."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """SELECT * FROM alerts WHERE certificate_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (cert_id, limit),
            )
            rows = cursor.fetchall()
            return [self._row_to_alert(row) for row in rows]

    async def create(self, alert: Alert) -> Alert:
        """Create new alert."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO alerts (
                    certificate_id, alert_type, days_remaining, status,
                    recipient, subject, body, error_message, created_at, sent_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.certificate_id,
                    alert.alert_type.name.lower(),
                    alert.days_remaining,
                    alert.status.name.lower(),
                    alert.recipient,
                    alert.subject,
                    alert.body,
                    alert.error_message,
                    alert.created_at,
                    alert.sent_at,
                ),
            )
            alert.id = cursor.lastrowid
            return alert

    async def mark_sent(self, alert_id: int) -> bool:
        """Mark alert as sent."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """UPDATE alerts SET
                    status = 'sent',
                    sent_at = ?
                WHERE id = ?
                """,
                (datetime.utcnow(), alert_id),
            )
            return cursor.rowcount > 0

    async def mark_failed(self, alert_id: int, error: str) -> bool:
        """Mark alert as failed with error message."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """UPDATE alerts SET
                    status = 'failed',
                    error_message = ?
                WHERE id = ?
                """,
                (error, alert_id),
            )
            return cursor.rowcount > 0


class SQLiteScanHistoryRepository(ScanHistoryRepository):
    """SQLite implementation of ScanHistoryRepository."""

    def __init__(self, pool: SQLiteConnectionPool):
        self._pool = pool

    def _row_to_scan_history(self, row: sqlite3.Row) -> ScanHistory:
        """Convert a database row to a ScanHistory model."""
        return ScanHistory(
            id=row["id"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=ScanStatus[row["status"].upper()],
            total_hosts=row["total_hosts"],
            successful_hosts=row["successful_hosts"],
            failed_hosts=row["failed_hosts"],
            updated_certificates=row["updated_certificates"],
            error_message=row["error_message"],
        )

    async def get_by_id(self, scan_id: int) -> ScanHistory | None:
        """Get scan history by ID."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_scan_history(row)

    async def get_recent(self, limit: int = 100) -> list[ScanHistory]:
        """Get recent scan history entries."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """SELECT * FROM scan_history
                   ORDER BY started_at DESC
                   LIMIT ?""",
                (limit,),
            )
            rows = cursor.fetchall()
            return [self._row_to_scan_history(row) for row in rows]

    async def create(self, scan: ScanHistory) -> ScanHistory:
        """Create new scan history entry."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO scan_history (
                    started_at, completed_at, status, total_hosts,
                    successful_hosts, failed_hosts, updated_certificates,
                    error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.started_at,
                    scan.completed_at,
                    scan.status.name.lower(),
                    scan.total_hosts,
                    scan.successful_hosts,
                    scan.failed_hosts,
                    scan.updated_certificates,
                    scan.error_message,
                ),
            )
            scan.id = cursor.lastrowid
            return scan

    async def complete(self, scan_id: int, status: ScanStatus, **kwargs) -> bool:
        """Mark scan as complete with status and results."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """UPDATE scan_history SET
                    completed_at = ?,
                    status = ?,
                    total_hosts = ?,
                    successful_hosts = ?,
                    failed_hosts = ?,
                    updated_certificates = ?,
                    error_message = ?
                WHERE id = ?
                """,
                (
                    datetime.utcnow(),
                    status.name.lower(),
                    kwargs.get("total_hosts", 0),
                    kwargs.get("successful_hosts", 0),
                    kwargs.get("failed_hosts", 0),
                    kwargs.get("updated_certificates", 0),
                    kwargs.get("error_message"),
                    scan_id,
                ),
            )
            return cursor.rowcount > 0


def create_pool(settings: Settings | None = None) -> SQLiteConnectionPool:
    """Factory function to create connection pool."""
    if settings is None:
        settings = Settings.get()
    return SQLiteConnectionPool(settings.database_path)
