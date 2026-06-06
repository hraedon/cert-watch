"""Repository implementations."""
from __future__ import annotations

import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database.connection import _connect, _iso, _parse_iso

# ---------- dataclasses ----------

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
    extra_recipients: list[str] = field(default_factory=list)


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
    tags: str = ""
    scan_interval_hours: int | None = None
    owner_name: str = ""
    owner_email: str = ""
    owner_slack: str = ""
    renewal_status: str = "pending"
    renewal_method: str = ""
    runbook_url: str = ""
    added_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------- Certificate Repository ----------

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
        from cert_watch.database.connection import _row_to_cert
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        return _row_to_cert(row) if row else None

    def list_all(self) -> list[Certificate]:
        from cert_watch.database.connection import _row_to_cert
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM certificates").fetchall()
        return [_row_to_cert(r) for r in rows]

    def list_expiring_within(self, days: int) -> list[Certificate]:
        from cert_watch.database.connection import _row_to_cert
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

    def get_tags(self, cert_id: str) -> str:
        """Return the cert's own (normalized) tag string, or '' if not found."""
        from cert_watch.tags import format_tags, parse_tags

        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT tags FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        return format_tags(parse_tags(row["tags"])) if row else ""

    def set_tags(self, cert_id: str, tags: str) -> None:
        """Set the cert's own tags (normalized before storage)."""
        from cert_watch.tags import format_tags, parse_tags

        now = _iso(datetime.now(UTC))
        normalized = format_tags(parse_tags(tags))
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE certificates SET tags = ?, updated_at = ? WHERE id = ?",
                (normalized, now, cert_id),
            )
            conn.commit()

    def effective_tags(self, cert_id: str) -> list[str]:
        """Cert's own tags unioned with its host's tags (plan 013 inheritance)."""
        from cert_watch.tags import merge_tags

        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT c.tags AS cert_tags, h.tags AS host_tags"
                " FROM certificates c"
                " LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port"
                " WHERE c.id = ?",
                (cert_id,),
            ).fetchone()
        if not row:
            return []
        d = dict(row)
        return merge_tags(d.get("cert_tags"), d.get("host_tags"))


# ---------- Alert Repository ----------

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

    def create(self, alert: Alert) -> str:
        alert_id = alert.id or str(uuid.uuid4())
        with _connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO alerts
                (id, cert_id, alert_type, status, message, threshold_days,
                 extra_recipients, created_at, sent_at, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    alert.cert_id,
                    alert.alert_type,
                    alert.status,
                    alert.message,
                    alert.threshold_days,
                    json.dumps(alert.extra_recipients or []),
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
    def _row_to_alert(row) -> Alert:
        row_dict = dict(row)
        extra = row_dict.get("extra_recipients", "[]")
        try:
            extra_recipients = json.loads(extra) if extra else []
        except (json.JSONDecodeError, TypeError):
            extra_recipients = []
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
            extra_recipients=extra_recipients,
        )


# ---------- Trust Anchors ----------

class SqliteTrustAnchorRepository:
    """Store user-uploaded root / CA certificates for private-chain validation."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

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
        from cert_watch.database.connection import _row_to_cert
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


# ---------- Hosts ----------

class SqliteHostRepository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def add(
        self,
        hostname: str,
        port: int = 443,
        threshold_days: int | None = None,
        tags: str = "",
        scan_interval_hours: int | None = None,
        owner_name: str = "",
        owner_email: str = "",
        owner_slack: str = "",
        renewal_status: str = "pending",
        renewal_method: str = "",
        runbook_url: str = "",
    ) -> str:
        import sqlite3
        host_id = str(uuid.uuid4())
        with _connect(self.db_path) as conn:
            try:
                conn.execute(
                    "INSERT INTO hosts"
                    " (id, hostname, port, threshold_days, tags, scan_interval_hours,"
                    "  owner_name, owner_email, owner_slack, renewal_status,"
                    "  renewal_method, runbook_url, added_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        host_id, hostname, port, threshold_days, tags,
                        scan_interval_hours, owner_name, owner_email,
                        owner_slack, renewal_status, renewal_method,
                        runbook_url, _iso(datetime.now(UTC)),
                    ),
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
                tags=dict(r).get("tags", ""),
                scan_interval_hours=dict(r).get("scan_interval_hours"),
                owner_name=dict(r).get("owner_name", ""),
                owner_email=dict(r).get("owner_email", ""),
                owner_slack=dict(r).get("owner_slack", ""),
                renewal_status=dict(r).get("renewal_status", "pending"),
                renewal_method=dict(r).get("renewal_method", ""),
                runbook_url=dict(r).get("runbook_url", ""),
                added_at=_parse_iso(r["added_at"]),
            )
            for r in rows
        ]

    def list_page(self, *, offset: int = 0, limit: int = 50) -> list[HostEntry]:
        """Return a paginated slice of hosts ordered by `added_at`."""
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM hosts ORDER BY added_at LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            HostEntry(
                id=r["id"],
                hostname=r["hostname"],
                port=r["port"],
                threshold_days=dict(r).get("threshold_days"),
                tags=dict(r).get("tags", ""),
                scan_interval_hours=dict(r).get("scan_interval_hours"),
                owner_name=dict(r).get("owner_name", ""),
                owner_email=dict(r).get("owner_email", ""),
                owner_slack=dict(r).get("owner_slack", ""),
                renewal_status=dict(r).get("renewal_status", "pending"),
                renewal_method=dict(r).get("renewal_method", ""),
                runbook_url=dict(r).get("runbook_url", ""),
                added_at=_parse_iso(r["added_at"]),
            )
            for r in rows
        ]

    def count_all(self) -> int:
        with _connect(self.db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()
        return row[0] if row else 0

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
            tags=dict(r).get("tags", ""),
            scan_interval_hours=dict(r).get("scan_interval_hours"),
            owner_name=dict(r).get("owner_name", ""),
            owner_email=dict(r).get("owner_email", ""),
            owner_slack=dict(r).get("owner_slack", ""),
            renewal_status=dict(r).get("renewal_status", "pending"),
            renewal_method=dict(r).get("renewal_method", ""),
            runbook_url=dict(r).get("runbook_url", ""),
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
                    f"DELETE FROM scan_posture WHERE cert_id IN ({placeholders})",
                    all_cert_ids,
                )
                conn.execute(
                    f"DELETE FROM alert_group_certs WHERE cert_id IN ({placeholders})",
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
            conn.execute(
                "DELETE FROM cert_history WHERE hostname = ? AND port = ?",
                (hostname, port),
            )
            conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
            conn.commit()
        return True

    def update_owner(
        self,
        host_id: str,
        *,
        owner_name: str | None = None,
        owner_email: str | None = None,
        owner_slack: str | None = None,
        renewal_status: str | None = None,
    ) -> bool:
        """Update owner/contact and renewal status for a host."""
        with _connect(self.db_path) as conn:
            r = conn.execute("SELECT id FROM hosts WHERE id = ?", (host_id,)).fetchone()
            if not r:
                return False
            sets: list[str] = []
            params: list = []
            if owner_name is not None:
                sets.append("owner_name = ?")
                params.append(owner_name)
            if owner_email is not None:
                sets.append("owner_email = ?")
                params.append(owner_email)
            if owner_slack is not None:
                sets.append("owner_slack = ?")
                params.append(owner_slack)
            if renewal_status is not None:
                sets.append("renewal_status = ?")
                params.append(renewal_status)
            if not sets:
                return True
            params.append(host_id)
            conn.execute(
                f"UPDATE hosts SET {', '.join(sets)} WHERE id = ?",
                params,
            )
            conn.commit()
        return True

    def set_tags(self, host_id: str, tags: str) -> bool:
        """Set a host's tags (normalized before storage). Returns False if no such host."""
        from cert_watch.tags import format_tags, parse_tags

        normalized = format_tags(parse_tags(tags))
        with _connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE hosts SET tags = ? WHERE id = ?", (normalized, host_id)
            )
            conn.commit()
        return cur.rowcount > 0

    def update_renewal(
        self,
        host_id: str,
        *,
        renewal_method: str | None = None,
        runbook_url: str | None = None,
        renewal_status: str | None = None,
    ) -> bool:
        """Update renewal_method, runbook_url, and renewal_status for a host."""
        with _connect(self.db_path) as conn:
            r = conn.execute(
                "SELECT id FROM hosts WHERE id = ?", (host_id,)
            ).fetchone()
            if not r:
                return False
            sets: list[str] = []
            params: list = []
            if renewal_method is not None:
                sets.append("renewal_method = ?")
                params.append(renewal_method)
            if runbook_url is not None:
                sets.append("runbook_url = ?")
                params.append(runbook_url)
            if renewal_status is not None:
                sets.append("renewal_status = ?")
                params.append(renewal_status)
            if not sets:
                return True
            params.append(host_id)
            conn.execute(
                f"UPDATE hosts SET {', '.join(sets)} WHERE id = ?",
                params,
            )
            conn.commit()
        return True


# ---------- Alert Groups (Plan 015) ----------

@dataclass
class AlertGroup:
    id: str = ""
    name: str = ""
    recipients: list[str] = field(default_factory=list)
    match_tags: list[str] = field(default_factory=list)
    webhook_url: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class SqliteAlertGroupRepository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def create(
        self,
        name: str,
        recipients: list[str],
        match_tags: list[str],
        webhook_url: str = "",
    ) -> str:
        from cert_watch.tags import format_tags

        group_id = str(uuid.uuid4())
        now = _iso(datetime.now(UTC))
        rec_str = format_tags(recipients)
        tags_str = format_tags(match_tags)
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO alert_groups"
                " (id, name, recipients, webhook_url, match_tags, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (group_id, name, rec_str, webhook_url, tags_str, now),
            )
            conn.commit()
        return group_id

    def get(self, group_id: str) -> AlertGroup | None:
        from cert_watch.tags import parse_tags

        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM alert_groups WHERE id = ?", (group_id,)
            ).fetchone()
        if not row:
            return None
        return AlertGroup(
            id=row["id"],
            name=row["name"],
            recipients=parse_tags(row["recipients"]),
            match_tags=parse_tags(row["match_tags"]),
            webhook_url=row["webhook_url"],
            created_at=_parse_iso(row["created_at"]),
        )

    def get_by_name(self, name: str) -> AlertGroup | None:
        from cert_watch.tags import parse_tags

        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM alert_groups WHERE name = ?", (name,)
            ).fetchone()
        if not row:
            return None
        return AlertGroup(
            id=row["id"],
            name=row["name"],
            recipients=parse_tags(row["recipients"]),
            match_tags=parse_tags(row["match_tags"]),
            webhook_url=row["webhook_url"],
            created_at=_parse_iso(row["created_at"]),
        )

    def list_all(self) -> list[AlertGroup]:
        from cert_watch.tags import parse_tags

        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM alert_groups ORDER BY name"
            ).fetchall()
        return [
            AlertGroup(
                id=r["id"],
                name=r["name"],
                recipients=parse_tags(r["recipients"]),
                match_tags=parse_tags(r["match_tags"]),
                webhook_url=r["webhook_url"],
                created_at=_parse_iso(r["created_at"]),
            )
            for r in rows
        ]

    def update(
        self,
        group_id: str,
        *,
        name: str | None = None,
        recipients: list[str] | None = None,
        match_tags: list[str] | None = None,
        webhook_url: str | None = None,
    ) -> bool:
        from cert_watch.tags import format_tags

        with _connect(self.db_path) as conn:
            r = conn.execute(
                "SELECT id FROM alert_groups WHERE id = ?", (group_id,)
            ).fetchone()
            if not r:
                return False
            sets: list[str] = []
            params: list = []
            if name is not None:
                sets.append("name = ?")
                params.append(name)
            if recipients is not None:
                sets.append("recipients = ?")
                params.append(format_tags(recipients))
            if match_tags is not None:
                sets.append("match_tags = ?")
                params.append(format_tags(match_tags))
            if webhook_url is not None:
                sets.append("webhook_url = ?")
                params.append(webhook_url)
            if not sets:
                return True
            params.append(group_id)
            conn.execute(
                f"UPDATE alert_groups SET {', '.join(sets)} WHERE id = ?",
                params,
            )
            conn.commit()
        return True

    def delete(self, group_id: str) -> bool:
        with _connect(self.db_path) as conn:
            r = conn.execute(
                "DELETE FROM alert_groups WHERE id = ?", (group_id,)
            )
            conn.execute(
                "DELETE FROM alert_group_certs WHERE group_id = ?", (group_id,)
            )
            conn.commit()
            return r.rowcount > 0

    def assign_cert(self, group_id: str, cert_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO alert_group_certs (group_id, cert_id)"
                " VALUES (?, ?)",
                (group_id, cert_id),
            )
            conn.commit()

    def unassign_cert(self, group_id: str, cert_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM alert_group_certs WHERE group_id = ? AND cert_id = ?",
                (group_id, cert_id),
            )
            conn.commit()

    def groups_for_cert_manual(self, cert_id: str) -> list[str]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT group_id FROM alert_group_certs WHERE cert_id = ?",
                (cert_id,),
            ).fetchall()
        return [r["group_id"] for r in rows]
