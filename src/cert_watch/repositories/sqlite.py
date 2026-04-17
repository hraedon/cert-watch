"""SQLite implementation of repository ABCs.

This is the PRIMARY database implementation for cert-watch v1.
Future versions may add MSSQL or PostgreSQL implementations.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from ..core.config import Settings
from ..models.alert import Alert
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

    def _row_to_cert(self, row: sqlite3.Row) -> Certificate:
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
            chain_position=row["chain_position"],
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
            if row:
                return self._row_to_cert(row)
            return None

    async def get_by_fingerprint(self, fingerprint: str) -> Certificate | None:
        """Get certificate by fingerprint."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_cert(row)
            return None

    async def get_all(self, limit: int = 1000) -> list[Certificate]:
        """Get all certificates, sorted by urgency."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM certificates ORDER BY not_after ASC LIMIT ?", (limit,)
            )
            return [self._row_to_cert(row) for row in cursor.fetchall()]

    async def get_by_hostname(self, hostname: str, port: int | None = None) -> list[Certificate]:
        """Get certificates by hostname."""
        with self._pool.get_connection() as conn:
            if port is not None:
                cursor = conn.execute(
                    "SELECT * FROM certificates WHERE hostname = ? AND port = ?", (hostname, port)
                )
            else:
                cursor = conn.execute("SELECT * FROM certificates WHERE hostname = ?", (hostname,))
            return [self._row_to_cert(row) for row in cursor.fetchall()]

    async def create(self, cert: Certificate) -> Certificate:
        """Create new certificate entry."""
        with self._pool.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO certificates (
                    certificate_type, source, hostname, port, label, subject, issuer,
                    not_before, not_after, fingerprint, serial_number, chain_fingerprint,
                    chain_position, pem_data, created_at, updated_at, last_scanned_at,
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
        cert.updated_at = datetime.utcnow()
        with self._pool.get_connection() as conn:
            conn.execute(
                """
                UPDATE certificates SET
                    certificate_type = ?, source = ?, hostname = ?, port = ?, label = ?,
                    subject = ?, issuer = ?, not_before = ?, not_after = ?, fingerprint = ?,
                    serial_number = ?, chain_fingerprint = ?, chain_position = ?, pem_data = ?,
                    updated_at = ?, last_scanned_at = ?, source_hostname = ?, source_port = ?
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
                    cert.updated_at,
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
                "SELECT * FROM certificates WHERE chain_fingerprint = ? ORDER BY chain_position ASC",
                (leaf_fingerprint,),
            )
            return [self._row_to_cert(row) for row in cursor.fetchall()]


class SQLiteAlertRepository(AlertRepository):
    """SQLite implementation of AlertRepository."""

    def __init__(self, pool: SQLiteConnectionPool):
        self._pool = pool

    async def get_by_id(self, alert_id: int) -> Alert | None:
        """Get alert by ID."""
        raise NotImplementedError

    async def get_pending(self) -> list[Alert]:
        """Get all pending alerts."""
        raise NotImplementedError

    async def get_for_certificate(self, cert_id: int, limit: int = 100) -> list[Alert]:
        """Get alerts for a specific certificate."""
        raise NotImplementedError

    async def create(self, alert: Alert) -> Alert:
        """Create new alert."""
        raise NotImplementedError

    async def mark_sent(self, alert_id: int) -> bool:
        """Mark alert as sent."""
        raise NotImplementedError

    async def mark_failed(self, alert_id: int, error: str) -> bool:
        """Mark alert as failed with error message."""
        raise NotImplementedError


class SQLiteScanHistoryRepository(ScanHistoryRepository):
    """SQLite implementation of ScanHistoryRepository."""

    def __init__(self, pool: SQLiteConnectionPool):
        self._pool = pool

    async def get_by_id(self, scan_id: int) -> ScanHistory | None:
        """Get scan history by ID."""
        raise NotImplementedError

    async def get_recent(self, limit: int = 100) -> list[ScanHistory]:
        """Get recent scan history entries."""
        raise NotImplementedError

    async def create(self, scan: ScanHistory) -> ScanHistory:
        """Create new scan history entry."""
        raise NotImplementedError

    async def complete(self, scan_id: int, status: ScanStatus, **kwargs) -> bool:
        """Mark scan as complete with status and results."""
        raise NotImplementedError


def create_pool(settings: Settings | None = None) -> SQLiteConnectionPool:
    """Factory function to create connection pool."""
    if settings is None:
        settings = Settings.get()
    return SQLiteConnectionPool(settings.database_path)
