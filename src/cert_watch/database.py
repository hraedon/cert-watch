"""SQLite persistence. See spec wi_database_layer.md."""

from __future__ import annotations

import json
import sqlite3
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate

# ---------- Alert dataclass (AC-05) ----------


@dataclass
class Alert:
    cert_id: str
    alert_type: str  # "expiry_warning" | "expired" | "scan_failure"
    status: str  # "pending" | "sent" | "failed"
    message: str
    id: str = ""
    threshold_days: int | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    sent_at: datetime | None = None
    error_message: str | None = None


# ---------- Schema ----------


_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    san_dns_names TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    raw_der BLOB NOT NULL,
    source TEXT NOT NULL DEFAULT 'unknown',
    hostname TEXT,
    port INTEGER,
    is_leaf INTEGER NOT NULL DEFAULT 1,
    parent_cert_id TEXT,
    chain_valid INTEGER,
    replaces_cert_id TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_fp ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_parent ON certificates(parent_cert_id);
CREATE INDEX IF NOT EXISTS idx_cert_replaces ON certificates(replaces_cert_id);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    threshold_days INTEGER,
    created_at TEXT NOT NULL,
    sent_at TEXT,
    error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_cert ON alerts(cert_id);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    threshold_days INTEGER,
    added_at TEXT NOT NULL,
    UNIQUE(hostname, port)
);

CREATE TABLE IF NOT EXISTS trust_anchors (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    san_dns_names TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    raw_der BLOB NOT NULL,
    created_at TEXT NOT NULL
);
"""


def init_schema(db_path: str | Path) -> None:
    """Create all tables if they do not exist. Idempotent. See AC-06."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(_SCHEMA)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(certificates)").fetchall()}
        if "chain_valid" not in cols:
            conn.execute("ALTER TABLE certificates ADD COLUMN chain_valid INTEGER")
        if "replaces_cert_id" not in cols:
            conn.execute("ALTER TABLE certificates ADD COLUMN replaces_cert_id TEXT")
        if "notes" not in cols:
            conn.execute("ALTER TABLE certificates ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
        host_cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()}
        if "threshold_days" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN threshold_days INTEGER")
        # trust_anchors migration
        ta_cols = {r[1] for r in conn.execute("PRAGMA table_info(trust_anchors)").fetchall()}
        if not ta_cols:
            conn.execute(
                """
                CREATE TABLE trust_anchors (
                    id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    san_dns_names TEXT NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    raw_der BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
        # Idempotent unique-index migration for hosts(hostname, port) — BC-019
        indexes = {r[1] for r in conn.execute("PRAGMA index_list('hosts')").fetchall()}
        if "ux_hosts_hostname_port" not in indexes:
            conn.execute(
                """
                DELETE FROM hosts
                WHERE rowid NOT IN (
                    SELECT MIN(rowid)
                    FROM hosts
                    GROUP BY hostname, port
                )
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_hosts_hostname_port ON hosts(hostname, port)"
            )
        conn.commit()


def _connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _row_to_cert(row: sqlite3.Row) -> Certificate:
    cert = Certificate(
        subject=row["subject"],
        issuer=row["issuer"],
        not_before=_parse_iso(row["not_before"]),
        not_after=_parse_iso(row["not_after"]),
        san_dns_names=json.loads(row["san_dns_names"]),
        fingerprint_sha256=row["fingerprint_sha256"],
        raw_der=bytes(row["raw_der"]),
        is_leaf=bool(row["is_leaf"]),
        notes=dict(row).get("notes", ""),
    )
    return cert


# ---------- Certificate Repository (AC-01, AC-02) ----------


class CertificateRepository(ABC):
    @abstractmethod
    def add(self, cert: Certificate) -> str: ...

    @abstractmethod
    def get_by_id(self, cert_id: str) -> Certificate | None: ...

    @abstractmethod
    def list_all(self) -> list[Certificate]: ...

    @abstractmethod
    def list_expiring_within(self, days: int) -> list[Certificate]: ...

    @abstractmethod
    def update_expiry(self, cert_id: str, not_after: datetime) -> None: ...

    @abstractmethod
    def delete(self, cert_id: str) -> None: ...


class SqliteCertificateRepository(CertificateRepository):
    def __init__(
        self,
        db_path: str | Path,
        *,
        source: str = "unknown",
        hostname: str | None = None,
        port: int | None = None,
        parent_cert_id: str | None = None,
        chain_valid: bool | None = None,
        replaces_cert_id: str | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        init_schema(self.db_path)
        self.source = source
        self.hostname = hostname
        self.port = port
        self.parent_cert_id = parent_cert_id
        self.chain_valid = chain_valid
        self.replaces_cert_id = replaces_cert_id

    def add(self, cert: Certificate) -> str:
        cert_id = str(uuid.uuid4())
        now = _iso(datetime.now(UTC))
        cv: int | None = (
            None if self.chain_valid is None else (1 if self.chain_valid else 0)
        )
        with _connect(self.db_path) as conn:
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
                    cert_id,
                    cert.subject,
                    cert.issuer,
                    _iso(cert.not_before),
                    _iso(cert.not_after),
                    json.dumps(cert.san_dns_names),
                    cert.fingerprint_sha256,
                    cert.raw_der,
                    self.source,
                    self.hostname,
                    self.port,
                    1 if cert.is_leaf else 0,
                    self.parent_cert_id,
                    cv,
                    self.replaces_cert_id,
                    cert.notes,
                    now,
                    now,
                ),
            )
            conn.commit()
        return cert_id

    def get_by_id(self, cert_id: str) -> Certificate | None:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        return _row_to_cert(row) if row else None

    def list_all(self) -> list[Certificate]:
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM certificates").fetchall()
        return [_row_to_cert(r) for r in rows]

    def list_expiring_within(self, days: int) -> list[Certificate]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM certificates "
                "WHERE julianday(not_after) <= julianday('now', '+' || ? || ' days')",
                (days,),
            ).fetchall()
        return [_row_to_cert(r) for r in rows]

    def update_expiry(self, cert_id: str, not_after: datetime) -> None:
        now = _iso(datetime.now(UTC))
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE certificates SET not_after = ?, updated_at = ? WHERE id = ?",
                (_iso(not_after), now, cert_id),
            )
            conn.commit()

    def delete(self, cert_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
            conn.commit()

    def update_notes(self, cert_id: str, notes: str) -> None:
        now = _iso(datetime.now(UTC))
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE certificates SET notes = ?, updated_at = ? WHERE id = ?",
                (notes, now, cert_id),
            )
            conn.commit()


# ---------- Alert Repository (AC-03, AC-04) ----------


class AlertRepository(ABC):
    @abstractmethod
    def create(self, alert: Alert) -> str: ...

    @abstractmethod
    def list_pending(self) -> list[Alert]: ...

    @abstractmethod
    def mark_sent(self, alert_id: str) -> None: ...

    @abstractmethod
    def mark_failed(self, alert_id: str, error_message: str) -> None: ...


class SqliteAlertRepository(AlertRepository):
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        init_schema(self.db_path)

    def create(self, alert: Alert) -> str:
        alert_id = alert.id or str(uuid.uuid4())
        with _connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO alerts
                (id, cert_id, alert_type, status, message, threshold_days,
                 created_at, sent_at, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    alert.cert_id,
                    alert.alert_type,
                    alert.status,
                    alert.message,
                    alert.threshold_days,
                    _iso(alert.created_at),
                    _iso(alert.sent_at) if alert.sent_at else None,
                    alert.error_message,
                ),
            )
            conn.commit()
        return alert_id

    def list_pending(self) -> list[Alert]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE status = 'pending'"
            ).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def list_all(self) -> list[Alert]:
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM alerts").fetchall()
        return [self._row_to_alert(r) for r in rows]

    def list_for_cert(self, cert_id: str) -> list[Alert]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE cert_id = ?", (cert_id,)
            ).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def mark_sent(self, alert_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE alerts SET status = 'sent', sent_at = ? WHERE id = ?",
                (_iso(datetime.now(UTC)), alert_id),
            )
            conn.commit()

    def mark_failed(self, alert_id: str, error_message: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE alerts SET status = 'failed', error_message = ? WHERE id = ?",
                (error_message, alert_id),
            )
            conn.commit()

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            cert_id=row["cert_id"],
            alert_type=row["alert_type"],
            status=row["status"],
            message=row["message"],
            threshold_days=row["threshold_days"],
            created_at=_parse_iso(row["created_at"]),
            sent_at=_parse_iso(row["sent_at"]) if row["sent_at"] else None,
            error_message=row["error_message"],
        )


# ---------- Trust Anchors ----------

class SqliteTrustAnchorRepository:
    """Store user-uploaded root / CA certificates for private-chain validation."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        init_schema(self.db_path)

    def add(self, cert: Certificate) -> str:
        anchor_id = str(uuid.uuid4())
        now = _iso(datetime.now(UTC))
        with _connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO trust_anchors
                (id, subject, issuer, not_before, not_after, san_dns_names,
                 fingerprint_sha256, raw_der, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    anchor_id,
                    cert.subject,
                    cert.issuer,
                    _iso(cert.not_before),
                    _iso(cert.not_after),
                    json.dumps(cert.san_dns_names),
                    cert.fingerprint_sha256,
                    cert.raw_der,
                    now,
                ),
            )
            conn.commit()
        return anchor_id

    def list_all(self) -> list[Certificate]:
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM trust_anchors ORDER BY created_at").fetchall()
        return [_row_to_cert(r) for r in rows]

    def list_entries(self) -> list[TrustAnchorEntry]:
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM trust_anchors ORDER BY created_at").fetchall()
        return [
            TrustAnchorEntry(
                id=r["id"],
                subject=r["subject"],
                issuer=r["issuer"],
                not_before=_parse_iso(r["not_before"]),
                not_after=_parse_iso(r["not_after"]),
                san_dns_names=json.loads(r["san_dns_names"]),
                fingerprint_sha256=r["fingerprint_sha256"],
                raw_der=bytes(r["raw_der"]),
                created_at=_parse_iso(r["created_at"]),
            )
            for r in rows
        ]

    def delete(self, anchor_id: str) -> bool:
        with _connect(self.db_path) as conn:
            r = conn.execute("DELETE FROM trust_anchors WHERE id = ?", (anchor_id,))
            conn.commit()
            return r.rowcount > 0


# ---------- Host list (for the add-host UI extension) ----------


@dataclass
class TrustAnchorEntry:
    id: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: datetime = field(default_factory=lambda: datetime.now(UTC))
    not_after: datetime = field(default_factory=lambda: datetime.now(UTC))
    san_dns_names: list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""
    raw_der: bytes = b""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class HostEntry:
    hostname: str
    port: int = 443
    id: str = ""
    threshold_days: int | None = None
    added_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class SqliteHostRepository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        init_schema(self.db_path)

    def add(self, hostname: str, port: int = 443, threshold_days: int | None = None) -> str:
        host_id = str(uuid.uuid4())
        with _connect(self.db_path) as conn:
            try:
                conn.execute(
                    "INSERT INTO hosts"
                    " (id, hostname, port, threshold_days, added_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (host_id, hostname, port, threshold_days, _iso(datetime.now(UTC))),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT id FROM hosts WHERE hostname = ? AND port = ?",
                    (hostname, port),
                ).fetchone()
                return row["id"] if row else host_id
        return host_id

    def list_all(self) -> list[HostEntry]:
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()
        return [
            HostEntry(
                id=r["id"],
                hostname=r["hostname"],
                port=r["port"],
                threshold_days=dict(r).get("threshold_days"),
                added_at=_parse_iso(r["added_at"]),
            )
            for r in rows
        ]

    def get(self, host_id: str) -> HostEntry | None:
        with _connect(self.db_path) as conn:
            r = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if not r:
            return None
        return HostEntry(
            id=r["id"],
            hostname=r["hostname"],
            port=r["port"],
            threshold_days=dict(r).get("threshold_days"),
            added_at=_parse_iso(r["added_at"]),
        )

    def delete(self, host_id: str) -> bool:
        """Delete the host and cascade-delete its scanned certs and alerts."""
        with _connect(self.db_path) as conn:
            r = conn.execute(
                "SELECT hostname, port FROM hosts WHERE id = ?", (host_id,)
            ).fetchone()
            if not r:
                return False
            hostname, port = r["hostname"], r["port"]
            leaf_ids = [
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1",
                    (hostname, port),
                ).fetchall()
            ]
            all_cert_ids = [
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM certificates WHERE hostname = ? AND port = ?",
                    (hostname, port),
                ).fetchall()
            ]
            for lid in leaf_ids:
                conn.execute(
                    "DELETE FROM certificates WHERE parent_cert_id = ?", (lid,)
                )
            if all_cert_ids:
                placeholders = ",".join("?" * len(all_cert_ids))
                conn.execute(
                    f"DELETE FROM alerts WHERE cert_id IN ({placeholders})",
                    all_cert_ids,
                )
            conn.execute(
                "DELETE FROM certificates WHERE hostname = ? AND port = ?",
                (hostname, port),
            )
            conn.execute(
                "DELETE FROM scan_history WHERE hostname = ? AND port = ?",
                (hostname, port),
            )
            conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
            conn.commit()
        return True


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
    transaction. Returns the new leaf cert_id.
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

    return leaf_id


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


def list_dashboard_rows(db_path: str | Path) -> list[dict]:
    """
    Return rich rows for the dashboard. Per the scope extension, each scanned host
    or uploaded bundle surfaces leaf + intermediate + root, and the row's urgency
    is driven by the most-urgent cert in that group.
    """
    from cert_watch.cert_chain import chain_status

    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM certificates ORDER BY created_at"
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

    anchors = [_row_to_cert(r) for r in anchor_rows]

    # Group by (source, hostname, port, parent_cert_id-or-self).
    # For uploaded bundles, leaf has no parent and intermediates point to the leaf id.
    # For scanned hosts, same shape.
    leaf_rows: list[dict] = []
    children_by_leaf: dict[str, list[dict]] = {}
    for r in rows:
        d = dict(r)
        if d["is_leaf"]:
            leaf_rows.append(d)
        else:
            children_by_leaf.setdefault(d["parent_cert_id"] or "", []).append(d)

    def _days(iso_str: str) -> int:
        """Floor days remaining — same semantics as Certificate.days_until_expiry()."""
        return (_parse_iso(iso_str) - datetime.now(UTC)).days

    def _urgency(days: int) -> str:
        if days < 7:
            return "red"
        if days < 30:
            return "yellow"
        return "green"

    dash: list[dict] = []
    for leaf in leaf_rows:
        chain = children_by_leaf.get(leaf["id"], [])
        leaf_days = _days(leaf["not_after"])
        chain_view = []
        for c in chain:
            days = _days(c["not_after"])
            chain_view.append({
                "subject": c["subject"],
                "issuer": c["issuer"],
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
        # Build Certificate objects for chain_status evaluation
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
            }
        )

    dash.sort(key=lambda d: min([d["days_remaining"], *[c["days_remaining"] for c in d["chain"]]]))
    return dash
