"""Dashboard and utility queries."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database.connection import _connect, _iso, _parse_iso, _row_to_cert
from cert_watch.database.schema import init_schema

_logger = logging.getLogger("cert_watch.database.queries")

# ---------- BC-082: at-rest encryption for sensitive kv_store values ----------

_ENCRYPTED_PREFIX = "enc:v1:"


def derive_encryption_key(signing_key: str) -> str:
    """Derive a Fernet-compatible key from the app signing key."""
    raw = hashlib.sha256(signing_key.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode()


def fernet_encrypt(plaintext: str, key: str) -> str:
    """Encrypt a value; return ``enc:v1:<token>``."""
    from cryptography.fernet import Fernet

    return _ENCRYPTED_PREFIX + Fernet(key.encode()).encrypt(plaintext.encode()).decode()


def fernet_decrypt(value: str, key: str) -> str:
    """Decrypt an ``enc:v1:`` value; pass through plaintext unchanged."""
    if not value.startswith(_ENCRYPTED_PREFIX):
        return value
    from cryptography.fernet import Fernet, InvalidToken

    try:
        return Fernet(key.encode()).decrypt(value[len(_ENCRYPTED_PREFIX) :].encode()).decode()
    except (InvalidToken, Exception):
        _logger.warning("kv: failed to decrypt value (wrong key or corrupted); returning raw")
        return value


def check_encrypted_values(db_path: str | Path, encryption_key: str) -> list[str]:
    """Return list of kv_store keys whose enc:v1: values fail to decrypt.

    Used at startup to warn if the signing key changed (e.g. .auth_secret
    was deleted/regenerated) and encrypted values are now unreadable.
    """
    init_schema(db_path)
    undecryptable: list[str] = []
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
    for row in rows:
        val = row["value"]
        if val and val.startswith(_ENCRYPTED_PREFIX):
            from cryptography.fernet import Fernet, InvalidToken
            try:
                Fernet(encryption_key.encode()).decrypt(
                    val[len(_ENCRYPTED_PREFIX) :].encode()
                )
            except (InvalidToken, Exception):
                undecryptable.append(row["key"])
    return undecryptable


def re_encrypt_kv_store(db_path: str | Path, old_key: str, new_key: str) -> int:
    """Re-encrypt all enc:v1: kv_store values from *old_key* to *new_key*.

    Returns the number of values re-encrypted. Values that cannot be decrypted
    with *old_key* are skipped (logged as warnings).
    """
    init_schema(db_path)
    count = 0
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
    for row in rows:
        val = row["value"]
        if not val or not val.startswith(_ENCRYPTED_PREFIX):
            continue
        plaintext = fernet_decrypt(val, old_key)
        if plaintext.startswith(_ENCRYPTED_PREFIX):
            _logger.warning("re_encrypt: skipping key %s — cannot decrypt with old key", row["key"])
            continue
        new_val = fernet_encrypt(plaintext, new_key)
        with _connect(db_path) as conn2:
            conn2.execute(
                "UPDATE kv_store SET value = ? WHERE key = ?", (new_val, row["key"])
            )
            conn2.commit()
        count += 1
    return count


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
) -> str:
    """Atomically replace all certs for host:port with new leaf + chain.

    Deletes old leaf + chain children, inserts new ones, all in a single
    transaction. Returns the new leaf cert_id.  Records a renewal diff
    when the certificate fingerprint changed.
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

    return leaf_id


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


# ---------- Drift detection (Plan 016 Slice 2) ----------


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
) -> list[DriftEvent]:
    """Look up the most recent cert_history row for host:port and compare with the new scan.

    Returns DriftEvents (empty if no previous history or no changes).
    """
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
) -> str | None:
    """Create a drift alert if any high-severity events exist.

    Returns the alert id if created, None otherwise.
    """
    from cert_watch.database.repo import Alert, SqliteAlertRepository

    high = [e for e in events if e.severity == "high"]
    if not high:
        return None

    summary = _drift_summary(events)
    message = f"{hostname}:{port} — {summary}"

    alert = Alert(
        cert_id=cert_id,
        alert_type="drift",
        status="pending",
        message=message,
        extra_recipients=extra_recipients or [],
    )
    alert_repo = SqliteAlertRepository(db_path)
    return alert_repo.create(alert)


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


def list_alerts_with_subject(db_path: str | Path, *, page: int = 1, limit: int = 0) -> list[dict]:
    """Return alerts joined with the cert subject, newest first.

    When ``limit > 0``, applies SQL-level pagination.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        if limit > 0:
            offset = max(0, (page - 1) * limit)
            rows = conn.execute(
                """
                SELECT a.id, a.cert_id, a.created_at, a.alert_type, a.status,
                       a.threshold_days, a.sent_at, a.error_message, a.message,
                       c.subject AS subject
                FROM alerts a
                LEFT JOIN certificates c ON c.id = a.cert_id
                ORDER BY a.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT a.id, a.cert_id, a.created_at, a.alert_type, a.status,
                       a.threshold_days, a.sent_at, a.error_message, a.message,
                       c.subject AS subject
                FROM alerts a
                LEFT JOIN certificates c ON c.id = a.cert_id
                ORDER BY a.created_at DESC
                """
            ).fetchall()
    return [dict(r) for r in rows]


# ---------- Pagination helpers ----------


def _total_alerts(db_path: str | Path) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    return row[0] if row else 0


def _total_scan_history(db_path: str | Path) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()
    return row[0] if row else 0


def list_scan_history(db_path: str | Path, *, page: int = 1, limit: int = 0) -> list[dict]:
    """Return scan_history rows, newest first.

    When ``limit > 0``, applies SQL-level pagination.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        if limit > 0:
            offset = max(0, (page - 1) * limit)
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY scanned_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


# ---------- Dashboard helpers ----------

def _build_dashboard_rows(
    cert_rows,
    anchor_rows,
) -> list[dict]:
    """Build rich dashboard rows from raw certificate and anchor rows."""
    from cert_watch.cert_chain import chain_status

    anchors = [_row_to_cert(r) for r in anchor_rows]

    leaf_rows: list[dict] = []
    children_by_leaf: dict[str, list[dict]] = {}
    for r in cert_rows:
        d = dict(r)
        if d["is_leaf"]:
            leaf_rows.append(d)
        else:
            children_by_leaf.setdefault(d["parent_cert_id"] or "", []).append(d)

    def _days(iso_str: str) -> int:
        return (_parse_iso(iso_str) - datetime.now(UTC)).days

    def _urgency(days: int) -> str:
        if days < 0:
            return "expired"
        if days < 7:
            return "critical"
        if days < 30:
            return "warning"
        return "healthy"

    dash: list[dict] = []
    for leaf in leaf_rows:
        chain = children_by_leaf.get(leaf["id"], [])
        leaf_days = _days(leaf["not_after"])
        chain_view = []
        for c in chain:
            days = _days(c["not_after"])
            chain_view.append({
                "id": c["id"],
                "subject": c["subject"],
                "issuer": c["issuer"],
                "not_before": c["not_before"],
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
        leaf_cert = _row_to_cert(leaf)
        chain_certs = [_row_to_cert(c) for c in chain]
        _chain_status = chain_status(leaf_cert, chain_certs, anchors)
        row_urgency = _urgency(min_days)
        if _chain_status in ("incomplete", "invalid") and row_urgency == "healthy":
            row_urgency = "warning"
        dash.append(
            {
                "id": leaf["id"],
                "host": host,
                "source": leaf["source"],
                "subject": leaf["subject"],
                "issuer": leaf["issuer"],
                "not_before": leaf["not_before"],
                "not_after": leaf["not_after"],
                "days_remaining": leaf_days,
                "urgency": row_urgency,
                "leaf_urgency": _urgency(leaf_days),
                "chain": chain_view,
                "chain_valid": (
                    None if leaf["chain_valid"] is None else bool(leaf["chain_valid"])
                ),
                "chain_status": _chain_status,
                "replaces_cert_id": leaf.get("replaces_cert_id"),
                "notes": dict(leaf).get("notes", ""),
                "fingerprint_sha256": leaf.get("fingerprint_sha256", ""),
                "san_dns_names": json.loads(leaf.get("san_dns_names", "[]")),
            }
        )

    return dash


def list_dashboard_rows(
    db_path: str | Path,
    *,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    per_page: int = 0,
) -> list[dict]:
    """
    Return rich rows for the dashboard. Per the scope extension, each scanned host
    or uploaded bundle surfaces leaf + intermediate + root, and the row's urgency
    is driven by the most-urgent cert in that group.

    When per_page > 0, applies pagination at the SQL level for leaf certificates
    and fetches only the chain children needed for that page.
    """
    init_schema(db_path)

    # Map sort_by to SQL ORDER BY for leaf certificates
    _sort_map = {
        "name": "subject",
        "issue_date": "not_before",
        "expiry": "not_after",
        "days": "not_after",
        "last_scan": "not_after",
    }
    sql_col = _sort_map.get(sort_by, "not_after")
    sql_dir = "ASC" if sort_order == "asc" else "DESC"

    with _connect(db_path) as conn:
        if per_page > 0:
            offset = max(0, (page - 1) * per_page)
            leaf_rows = conn.execute(
                f"SELECT * FROM certificates WHERE is_leaf = 1 "
                f"ORDER BY {sql_col} {sql_dir} LIMIT ? OFFSET ?",
                (per_page, offset),
            ).fetchall()
            leaf_ids = [r["id"] for r in leaf_rows]
            if leaf_ids:
                ph = ",".join("?" * len(leaf_ids))
                chain_rows = conn.execute(
                    f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})",
                    leaf_ids,
                ).fetchall()
            else:
                chain_rows = []
            rows = list(leaf_rows) + list(chain_rows)
        else:
            rows = conn.execute(
                "SELECT * FROM certificates ORDER BY created_at"
            ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

    dash = _build_dashboard_rows(rows, anchor_rows)
    if per_page == 0:
        dash.sort(
            key=lambda d: min(
                [d["days_remaining"], *[c["days_remaining"] for c in d["chain"]]]
            )
        )
    return dash


def count_dashboard_leaves(db_path: str | Path) -> int:
    """Return the total number of leaf certificates for pagination."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE is_leaf = 1"
        ).fetchone()
    return row[0] if row else 0


def list_unified_entries(db_path: str | Path) -> list[dict]:
    """Return a merged list of hosts (pending or scanned) and uploaded certificates.

    Each entry has a ``kind`` of ``scanned``, ``uploaded``, or ``pending``.
    Pending hosts carry cert fields set to ``None`` and urgency ``gray``.
    """
    return _list_unified_entries_raw(db_path)


def _matches_q(e: dict, ql: str) -> bool:
    """Python text match used by the dashboard filter (case-insensitive)."""
    fields = [e.get("name"), e.get("subject"), e.get("issuer"), e.get("host")]
    if e.get("kind") == "grouped":
        for h in e.get("hosts", []):
            fields.extend([h.get("host"), h.get("name")])
    return any(ql in (f or "").lower() for f in fields)


def _filter_unified(
    entries: list[dict],
    *,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
) -> list[dict]:
    """Apply the dashboard q/urgency/source filters to built unified entries.

    This mirrors the filter semantics used by the dashboard route exactly so
    grouped and ungrouped paths stay identical.
    """
    if q:
        ql = q.lower()
        entries = [e for e in entries if _matches_q(e, ql)]
    if urgency:
        entries = [e for e in entries if e.get("urgency") == urgency]
    if source:
        if source == "scanned":
            entries = [
                e for e in entries
                if e.get("kind") in ("scanned", "pending", "grouped")
            ]
        else:
            entries = [e for e in entries if e.get("source") == source]
    return entries


_UNIFIED_SORT_KEYS = {
    "name": lambda e: (e.get("name") or "").lower(),
    "issue_date": lambda e: e.get("not_before") or "9999-12-31T23:59:59",
    "last_scan": lambda e: e.get("last_scanned_at") or "0000-01-01T00:00:00",
    "expiry": lambda e: e.get("not_after") or "9999-12-31T23:59:59",
    "days": lambda e: (
        e["days_remaining"] if e.get("days_remaining") is not None else 9999
    ),
}


def _sort_unified(
    entries: list[dict], *, sort_by: str = "days", sort_order: str = "asc"
) -> list[dict]:
    """Sort built unified entries with the dashboard's sort semantics."""
    key_fn = _UNIFIED_SORT_KEYS.get(sort_by, _UNIFIED_SORT_KEYS["days"])
    entries.sort(key=key_fn, reverse=(sort_order == "desc"))
    return entries


def list_unified_entries_page(
    db_path: str | Path,
    *,
    offset: int = 0,
    limit: int = 0,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
) -> tuple[list[dict], int]:
    """Return a paginated slice of unified entries plus the total count.

    Thin compatibility wrapper kept for callers and tests that predate the
    purpose-built dashboard queries (BC-047/BC-073).  Delegates to
    :func:`list_dashboard_page`, which pushes filtering, sorting and
    pagination into SQL where it can.
    """
    page = (offset // limit) + 1 if limit > 0 else 1
    per_page = limit if limit > 0 else 0
    return list_dashboard_page(
        db_path,
        urgency=urgency,
        source=source,
        q=q,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


def _build_unified_for_leaf_ids(
    conn,
    leaf_ids: list[str],
    *,
    host_rows,
    scan_rows,
    anchor_rows,
) -> list[dict]:
    """Build scanned/uploaded unified entries for a specific set of leaf ids.

    Fetches the leaf rows + their chain children, builds dashboard rows, and
    merges in host/scan context.  Pending hosts (no leaf) are added by the
    caller via :func:`_build_unified_from_dash`-style logic; this helper only
    covers leaf-backed entries (scanned + uploaded).
    """
    if not leaf_ids:
        return []
    ph = ",".join("?" * len(leaf_ids))
    leaf_rows = conn.execute(
        f"SELECT * FROM certificates WHERE id IN ({ph})", leaf_ids
    ).fetchall()
    chain_rows = conn.execute(
        f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})", leaf_ids
    ).fetchall()
    dash = _build_dashboard_rows(list(leaf_rows) + list(chain_rows), anchor_rows)
    return _build_unified_from_dash(dash, host_rows, scan_rows)


def _clamp_page(page: int, total: int, per_page: int) -> int:
    """Clamp a 1-based page index into the valid range for ``total`` rows."""
    if per_page <= 0:
        return 1
    total_pages = max((total + per_page - 1) // per_page, 1)
    return max(1, min(page, total_pages))


def list_dashboard_page(
    db_path: str | Path,
    *,
    urgency: str | None = None,
    source: str | None = None,
    q: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Return a SQL-filtered, sorted, paginated page of unified dashboard rows.

    Ungrouped dashboard path (BC-073).  Filtering on ``source``/``q`` and the
    chosen sort + LIMIT/OFFSET are pushed into SQL via a UNION over leaf
    certificates, pending hosts (no leaf), and uploaded certs.  Only the rows
    for the requested page are then materialised into rich dashboard dicts.

    ``urgency`` filtering depends on computed chain status (which cannot be
    expressed faithfully in SQL), so when an ``urgency`` filter is requested the
    SQL-narrowed candidate set is built and filtered in Python before
    pagination.  Returns ``(rows, total)``.
    """
    init_schema(db_path)

    _SORT_COLS = {
        "name": "sort_name",
        "issue_date": "sort_issue",
        "last_scan": "sort_scan",
        "expiry": "sort_expiry",
        "days": "sort_expiry",
    }
    sort_col = _SORT_COLS.get(sort_by, "sort_expiry")
    sql_dir = "DESC" if sort_order == "desc" else "ASC"

    # Source filter pushed to SQL: which candidate kinds to include.
    include_scanned = True
    include_uploaded = True
    if source:
        if source == "scanned":
            include_uploaded = False
        else:  # "uploaded" (or any explicit source value): leaf certs only
            include_scanned = False

    # q is pushed to SQL for leaf/host candidates; grouped cross-host search
    # never applies to the ungrouped path, so per-field LIKE is faithful.
    like = f"%{q.lower()}%" if q else None

    with _connect(db_path) as conn:
        host_rows = conn.execute(
            "SELECT * FROM hosts ORDER BY added_at"
        ).fetchall()
        scan_rows = conn.execute(
            """
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            """
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        # Build the ordered candidate set in SQL.  Each candidate carries the
        # entity kind + key plus the four sort keys so ORDER BY matches the
        # Python sort semantics (NULL cert fields fall back to sentinels).
        select_parts: list[str] = []
        params: list = []

        if include_scanned:
            # Scanned leaf certs.
            scanned_sql = """
                SELECT 'leaf' AS etype, c.id AS ekey,
                       LOWER(c.subject) AS sort_name,
                       c.not_before AS sort_issue,
                       COALESCE((
                           SELECT MAX(sh.scanned_at) FROM scan_history sh
                           WHERE sh.hostname = c.hostname AND sh.port = c.port
                       ), '0000-01-01T00:00:00') AS sort_scan,
                       c.not_after AS sort_expiry
                FROM certificates c
                JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
                WHERE c.is_leaf = 1 AND c.source = 'scanned'
            """
            scanned_params: list = []
            if like:
                scanned_sql += (
                    " AND (LOWER(c.subject) LIKE ? OR LOWER(c.issuer) LIKE ?"
                    " OR LOWER(c.hostname || ':' || c.port) LIKE ?)"
                )
                scanned_params += [like, like, like]
            select_parts.append(scanned_sql)
            params += scanned_params

            # Pending hosts (no leaf certificate).
            pending_sql = """
                SELECT 'pending' AS etype, h.id AS ekey,
                       LOWER(h.hostname || ':' || h.port) AS sort_name,
                       '9999-12-31T23:59:59' AS sort_issue,
                       COALESCE((
                           SELECT MAX(sh.scanned_at) FROM scan_history sh
                           WHERE sh.hostname = h.hostname AND sh.port = h.port
                       ), '0000-01-01T00:00:00') AS sort_scan,
                       '9999-12-31T23:59:59' AS sort_expiry
                FROM hosts h
                WHERE NOT EXISTS (
                    SELECT 1 FROM certificates c
                    WHERE c.hostname = h.hostname AND c.port = h.port
                      AND c.is_leaf = 1
                )
            """
            pending_params: list = []
            if like:
                pending_sql += (
                    " AND LOWER(h.hostname || ':' || h.port) LIKE ?"
                )
                pending_params += [like]
            select_parts.append(pending_sql)
            params += pending_params

        if include_uploaded:
            uploaded_sql = """
                SELECT 'leaf' AS etype, c.id AS ekey,
                       LOWER(c.subject) AS sort_name,
                       c.not_before AS sort_issue,
                       '0000-01-01T00:00:00' AS sort_scan,
                       c.not_after AS sort_expiry
                FROM certificates c
                WHERE c.is_leaf = 1 AND c.source != 'scanned'
            """
            uploaded_params: list = []
            if like:
                uploaded_sql += (
                    " AND (LOWER(c.subject) LIKE ? OR LOWER(c.issuer) LIKE ?)"
                )
                uploaded_params += [like, like]
            select_parts.append(uploaded_sql)
            params += uploaded_params

        if not select_parts:
            return [], 0

        union_sql = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in select_parts)

        if urgency:
            # Urgency depends on computed chain status — build the full
            # candidate set, then filter + paginate in Python.
            ordered = conn.execute(
                f"SELECT etype, ekey FROM ({union_sql}) "
                f"ORDER BY {sort_col} {sql_dir}",
                params,
            ).fetchall()
            leaf_ids = [r["ekey"] for r in ordered if r["etype"] == "leaf"]
            pending_ids = {r["ekey"] for r in ordered if r["etype"] == "pending"}
            built = _build_unified_for_leaf_ids(
                conn, leaf_ids,
                host_rows=host_rows, scan_rows=scan_rows, anchor_rows=anchor_rows,
            )
            built += _build_pending_entries(
                [h for h in host_rows if h["id"] in pending_ids], scan_rows
            )
            built = _reorder_by_candidates(built, ordered)
            built = _filter_unified(built, urgency=urgency)
            total = len(built)
            if per_page > 0:
                clamped = _clamp_page(page, total, per_page)
                start = (clamped - 1) * per_page
                built = built[start : start + per_page]
            return built, total

        # No urgency filter: pagination is fully SQL-level.
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM ({union_sql})", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        page_sql = f"SELECT etype, ekey FROM ({union_sql}) ORDER BY {sort_col} {sql_dir}"
        page_params = list(params)
        if per_page > 0:
            clamped = _clamp_page(page, total, per_page)
            offset = (clamped - 1) * per_page
            page_sql += " LIMIT ? OFFSET ?"
            page_params += [per_page, offset]
        ordered = conn.execute(page_sql, page_params).fetchall()

        leaf_ids = [r["ekey"] for r in ordered if r["etype"] == "leaf"]
        pending_ids = {r["ekey"] for r in ordered if r["etype"] == "pending"}
        built = _build_unified_for_leaf_ids(
            conn, leaf_ids,
            host_rows=host_rows, scan_rows=scan_rows, anchor_rows=anchor_rows,
        )
        built += _build_pending_entries(
            [h for h in host_rows if h["id"] in pending_ids], scan_rows
        )
        built = _reorder_by_candidates(built, ordered)
    return built, total


def _reorder_by_candidates(entries: list[dict], ordered) -> list[dict]:
    """Reorder built entries to match the SQL candidate ordering by id."""
    by_id: dict[str, dict] = {e["id"]: e for e in entries}
    result: list[dict] = []
    for r in ordered:
        e = by_id.get(r["ekey"])
        if e is not None:
            result.append(e)
    return result


def _build_pending_entries(host_rows, scan_rows) -> list[dict]:
    """Build pending unified entries (hosts with no leaf cert) for given hosts."""
    if not host_rows:
        return []
    latest_scan: dict[tuple[str, int], dict] = {
        (r["hostname"], r["port"]): dict(r) for r in scan_rows
    }
    entries: list[dict] = []
    for h in host_rows:
        host_key = f"{h['hostname']}:{h['port']}"
        scan = latest_scan.get((h["hostname"], h["port"]))
        owner_info = {
            "owner_name": dict(h).get("owner_name", ""),
            "owner_email": dict(h).get("owner_email", ""),
            "owner_slack": dict(h).get("owner_slack", ""),
            "renewal_status": dict(h).get("renewal_status", "pending"),
            "renewal_method": dict(h).get("renewal_method", ""),
            "runbook_url": dict(h).get("runbook_url", ""),
        }
        entries.append({
            "id": h["id"],
            "host_id": h["id"],
            "kind": "pending",
            "name": host_key,
            "host": host_key,
            "source": "scanned",
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "urgency": "gray",
            "leaf_urgency": "gray",
            "chain": [],
            "chain_valid": None,
            "chain_status": None,
            "replaces_cert_id": None,
            "notes": "",
            "fingerprint_sha256": None,
            "san_dns_names": [],
            "last_scanned_at": scan["scanned_at"] if scan else None,
            "scan_status": scan["status"] if scan else None,
            "scan_error": scan.get("error_message") if scan else None,
            "added_at": h["added_at"],
            **owner_info,
        })
    return entries


def list_dashboard_grouped_page(
    db_path: str | Path,
    *,
    urgency: str | None = None,
    source: str | None = None,
    q: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Return a SQL-grouped, filtered, sorted, paginated page of dashboard rows.

    Grouped dashboard path (BC-073).  Scanned entries sharing a leaf
    fingerprint collapse into a single row whose urgency is the worst urgency
    across the group and whose host count is the number of hosts in the group.
    Uploaded and pending entries pass through ungrouped.

    Scanned-entry grouping uses SQL ``GROUP BY`` so only the visible page of
    grouped rows is materialised with full cert/host/scan detail.  Ungrouped
    entries (uploaded, pending) are loaded and merged in Python.  Returns
    ``(rows, total)``.
    """
    init_schema(db_path)

    _URGENCY_SQL = {
        "expired": "WHEN julianday(c.not_after) - julianday('now') < 0 THEN 0",
        "critical": "WHEN julianday(c.not_after) - julianday('now') < 7 THEN 1",
        "warning": "WHEN julianday(c.not_after) - julianday('now') < 30 THEN 2",
        "healthy": "ELSE 3",
    }
    _URGENCY_ORDER_SQL = ("expired", "critical", "warning", "healthy")
    _URGENCY_RANK = {u: i for i, u in enumerate(_URGENCY_ORDER_SQL)}

    _SORT_COLS = {
        "name": "LOWER(COALESCE(c.subject, c.hostname || ':' || c.port))",
        "issue_date": "c.not_before",
        "last_scan": "COALESCE(last_scan_at, '0000-01-01T00:00:00')",
        "expiry": "c.not_after",
        "days": "c.not_after",
    }
    sort_col = _SORT_COLS.get(sort_by, _SORT_COLS["days"])
    sql_dir = "DESC" if sort_order == "desc" else "ASC"

    like = f"%{q.lower()}%" if q else None

    with _connect(db_path) as conn:
        # Step 1: SQL GROUP BY fingerprint for scanned entries.
        grouped_sql = f"""
            SELECT
                c.fingerprint_sha256,
                COUNT(DISTINCT c.hostname || ':' || c.port) AS host_count,
                MIN(c.not_after) AS earliest_expiry,
                MIN(julianday(c.not_after) - julianday('now')) AS min_days_remaining,
                CASE
                    {_URGENCY_SQL['expired']}
                    {_URGENCY_SQL['critical']}
                    {_URGENCY_SQL['warning']}
                    {_URGENCY_SQL['healthy']}
                END AS worst_urgency_rank,
                {sort_col} AS sort_val
            FROM certificates c
            WHERE c.is_leaf = 1
              AND c.source = 'scanned'
              AND c.fingerprint_sha256 IS NOT NULL
              AND c.fingerprint_sha256 != ''
        """
        params: list = []

        if like:
            grouped_sql += (
                " AND (LOWER(c.subject) LIKE ? OR LOWER(c.issuer) LIKE ?"
                " OR LOWER(c.hostname || ':' || c.port) LIKE ?)"
            )
            params.extend([like, like, like])

        grouped_sql += " GROUP BY c.fingerprint_sha256"

        if urgency:
            rank = _URGENCY_RANK.get(urgency)
            if rank is not None:
                grouped_sql += " HAVING worst_urgency_rank = ?"
                params.append(rank)

        grouped_sql += f" ORDER BY sort_val {sql_dir}"

        rows = conn.execute(grouped_sql, params).fetchall()

        fingerprints = [r["fingerprint_sha256"] for r in rows]

        # Step 2: Load full details for grouped scanned entries.
        cert_rows: list = []
        chain_rows: list = []
        if fingerprints:
            ph = ",".join("?" * len(fingerprints))
            cert_rows = conn.execute(
                f"SELECT * FROM certificates c"
                f" WHERE c.fingerprint_sha256 IN ({ph}) AND c.is_leaf = 1"
                f" ORDER BY c.hostname, c.port",
                fingerprints,
            ).fetchall()
            leaf_ids = [r["id"] for r in cert_rows]
            if leaf_ids:
                cph = ",".join("?" * len(leaf_ids))
                chain_rows = conn.execute(
                    f"SELECT * FROM certificates WHERE parent_cert_id IN ({cph})",
                    leaf_ids,
                ).fetchall()

        host_rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()
        scan_rows = conn.execute(
            """
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            """
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

    # Step 3: Build rich dashboard rows for scanned entries and group them.
    all_rows = list(cert_rows) + list(chain_rows)
    dash = _build_dashboard_rows(all_rows, anchor_rows)
    entries = _build_unified_from_dash(dash, host_rows, scan_rows, include_uploaded=False)

    entries_by_fp: dict[str, list[dict]] = {}
    for e in entries:
        fp = e.get("fingerprint_sha256")
        if fp:
            entries_by_fp.setdefault(fp, []).append(e)

    grouped_entries: list[dict] = []
    group_idx = 0
    for row in rows:
        fp = row["fingerprint_sha256"]
        group = entries_by_fp.get(fp, [])
        if not group:
            continue
        group_idx += 1
        first = group[0]

        urgency_counts: dict[str, int] = {}
        for h in group:
            u = h["urgency"]
            urgency_counts[u] = urgency_counts.get(u, 0) + 1

        group_urgency = "healthy"
        for u in _URGENCY_ORDER:
            if urgency_counts.get(u, 0) > 0:
                group_urgency = u
                break

        grouped_entries.append({
            "id": first["id"],
            "fingerprint_sha256": fp,
            "group_id": group_idx,
            "kind": "grouped",
            "source": "scanned",
            "subject": first["subject"],
            "issuer": first["issuer"],
            "not_before": first["not_before"],
            "not_after": first["not_after"],
            "days_remaining": first["days_remaining"],
            "urgency": group_urgency,
            "leaf_urgency": first["leaf_urgency"],
            "chain": first["chain"],
            "chain_valid": first["chain_valid"],
            "chain_status": first["chain_status"],
            "san_dns_names": first.get("san_dns_names", []),
            "replaces_cert_id": first.get("replaces_cert_id"),
            "notes": first.get("notes", ""),
            "name": first["subject"] or first["host"],
            "host": first["host"],
            "host_id": first.get("host_id"),
            "host_count": len(group),
            "healthy_count": sum(1 for h in group if h["urgency"] == "healthy"),
            "urgency_summary": urgency_counts,
            "hosts": group,
            "last_scanned_at": first.get("last_scanned_at"),
            "scan_status": first.get("scan_status"),
            "scan_error": first.get("scan_error"),
            "added_at": first.get("added_at"),
            "owner_name": first.get("owner_name", ""),
            "owner_email": first.get("owner_email", ""),
            "owner_slack": first.get("owner_slack", ""),
            "renewal_status": first.get("renewal_status", "pending"),
            "renewal_method": first.get("renewal_method", ""),
            "runbook_url": first.get("runbook_url", ""),
        })

    # Step 4: Load ungrouped entries (uploaded + pending) and merge.
    with _connect(db_path) as conn2:
        all_certs = conn2.execute("SELECT * FROM certificates ORDER BY created_at").fetchall()
    full_dash = _build_dashboard_rows(list(all_certs), anchor_rows)
    all_unified = _build_unified_from_dash(full_dash, host_rows, scan_rows)
    grouped_fps = {r["fingerprint_sha256"] for r in rows}

    ungrouped: list[dict] = []
    for e in all_unified:
        fp = e.get("fingerprint_sha256") if e.get("kind") == "scanned" else None
        if fp and fp in grouped_fps:
            continue
        ungrouped.append(e)

    all_entries = grouped_entries + ungrouped
    all_entries = _filter_unified(all_entries, q=q, urgency=urgency, source=source)
    all_entries = _sort_unified(all_entries, sort_by=sort_by, sort_order=sort_order)

    total = len(all_entries)
    if per_page > 0:
        start = max(0, (page - 1) * per_page)
        all_entries = all_entries[start : start + per_page]
    return all_entries, total


def get_cert_detail(db_path: str | Path, cert_id: str) -> dict | None:
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


def _build_unified_from_dash(
    dash: list[dict],
    host_rows: list,
    scan_rows: list,
    *,
    include_uploaded: bool = True,
) -> list[dict]:
    """Build unified entries from dashboard rows, host rows, and scan rows."""
    latest_scan: dict[tuple[str, int], dict] = {
        (r["hostname"], r["port"]): dict(r) for r in scan_rows
    }

    scanned_map: dict[str, dict] = {}
    uploaded: list[dict] = []
    for c in dash:
        if c["source"] == "scanned":
            scanned_map[c["host"]] = c
        else:
            uploaded.append(c)

    host_id_map: dict[tuple[str, int], str] = {
        (h["hostname"], h["port"]): h["id"] for h in host_rows
    }

    entries: list[dict] = []
    for h in host_rows:
        host_key = f"{h['hostname']}:{h['port']}"
        scan = latest_scan.get((h["hostname"], h["port"]))
        owner_info = {
            "owner_name": dict(h).get("owner_name", ""),
            "owner_email": dict(h).get("owner_email", ""),
            "owner_slack": dict(h).get("owner_slack", ""),
            "renewal_status": dict(h).get("renewal_status", "pending"),
            "renewal_method": dict(h).get("renewal_method", ""),
            "runbook_url": dict(h).get("runbook_url", ""),
        }
        if host_key in scanned_map:
            row = scanned_map[host_key]
            row["kind"] = "scanned"
            row["host_id"] = host_id_map.get((h["hostname"], h["port"]))
            row["last_scanned_at"] = scan["scanned_at"] if scan else None
            row["scan_status"] = scan["status"] if scan else None
            row["scan_error"] = scan.get("error_message") if scan else None
            row["added_at"] = h["added_at"]
            row.update(owner_info)
            entries.append(row)
        else:
            entries.append(
                {
                    "id": h["id"],
                    "host_id": h["id"],
                    "kind": "pending",
                    "name": host_key,
                    "host": host_key,
                    "source": "scanned",
                    "subject": None,
                    "issuer": None,
                    "not_before": None,
                    "not_after": None,
                    "days_remaining": None,
                    "urgency": "gray",
                    "leaf_urgency": "gray",
                    "chain": [],
                    "chain_valid": None,
                    "chain_status": None,
                    "replaces_cert_id": None,
                    "notes": "",
                    "fingerprint_sha256": None,
                    "san_dns_names": [],
                    "last_scanned_at": scan["scanned_at"] if scan else None,
                    "scan_status": scan["status"] if scan else None,
                    "scan_error": scan.get("error_message") if scan else None,
                    "added_at": h["added_at"],
                    **owner_info,
                }
            )

    if include_uploaded:
        for u in uploaded:
            u["kind"] = "uploaded"
            u["name"] = u["subject"]
            u["last_scanned_at"] = None
            u["scan_status"] = None
            u["scan_error"] = None
            u["added_at"] = None
            entries.append(u)

    return entries


def _list_unified_entries_raw(db_path: str | Path) -> list[dict]:
    init_schema(db_path)
    with _connect(db_path) as conn:
        cert_rows = conn.execute(
            "SELECT * FROM certificates ORDER BY created_at"
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()
        host_rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()
        # Only fetch the latest scan per host directly in SQL (BC-028)
        scan_rows = conn.execute(
            """
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            """
        ).fetchall()

    dash = _build_dashboard_rows(cert_rows, anchor_rows)
    return _build_unified_from_dash(dash, host_rows, scan_rows)


def _load_unified_filtered(
    db_path: str | Path,
    *,
    host_where: str | None = None,
    host_params: tuple = (),
) -> list[dict]:
    """Load unified entries for scanned/pending hosts, optionally filtered.

    Uses SQL-level filtering via an EXISTS subquery on the *hosts* table so
    only matching rows are materialised.  Uploaded certificates are excluded.

    SECURITY: ``host_where`` is interpolated into SQL via f-string.  It MUST
    be a hardcoded string from internal call sites only — never derived from
    user input.  The callers in ``get_pivot_group_entries()`` construct it
    from whitelisted column names.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        if host_where:
            host_rows = conn.execute(
                f"SELECT * FROM hosts WHERE {host_where} ORDER BY added_at",
                host_params,
            ).fetchall()
        else:
            host_rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()

        if host_where:
            exists_clause = (
                f"EXISTS (SELECT 1 FROM hosts h WHERE h.hostname = c.hostname "
                f"AND h.port = c.port AND {host_where})"
            )
        else:
            exists_clause = "c.hostname IS NOT NULL"

        cert_rows = conn.execute(
            f"SELECT * FROM certificates c WHERE c.is_leaf = 1 "
            f"AND {exists_clause} ORDER BY created_at",
            host_params,
        ).fetchall()
        leaf_ids = [r["id"] for r in cert_rows]
        if leaf_ids:
            ph = ",".join("?" * len(leaf_ids))
            chain_rows = conn.execute(
                f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})",
                leaf_ids,
            ).fetchall()
        else:
            chain_rows = []

        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        if host_where:
            scan_exists = (
                f"EXISTS (SELECT 1 FROM hosts h WHERE h.hostname = sh1.hostname "
                f"AND h.port = sh1.port AND {host_where})"
            )
        else:
            scan_exists = "1=1"
        scan_rows = conn.execute(
            f"""
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            AND {scan_exists}
            """,
            host_params,
        ).fetchall()

    dash = _build_dashboard_rows(list(cert_rows) + list(chain_rows), anchor_rows)
    return _build_unified_from_dash(dash, host_rows, scan_rows, include_uploaded=False)


_URGENCY_ORDER = ("expired", "critical", "warning", "healthy", "gray")


def list_fleet_pivot(
    db_path: str | Path,
    pivot: str,
) -> list[dict]:
    """Return fleet pivot groups using SQL-level aggregation.

    Each group has ``key``, ``count``, ``worst_urgency``, ``earliest_expiry``.
    The ``entries`` field is ``None`` — use :func:`get_pivot_group_entries`
    to fetch entries for a specific group on demand (BC-048).
    """
    from cert_watch.filters import friendly_issuer

    init_schema(db_path)

    _METHOD_LABELS = {
        "acme": "ACME",
        "cert-manager": "cert-manager",
        "manual": "Manual",
    }

    # Determine the grouping column for scanned leaf certs
    if pivot == "issuer":
        group_col = "c.issuer"
    elif pivot == "owner":
        group_col = "COALESCE(h.owner_name, '')"
    elif pivot == "renewal_method":
        group_col = "COALESCE(h.renewal_method, '')"
    else:
        group_col = "'unknown'"

    with _connect(db_path) as conn:
        # Scanned hosts: aggregate per group from leaf certificates
        rows = conn.execute(
            f"""
            SELECT {group_col} AS grp,
                   CAST(MIN(CASE
                        WHEN c.not_after < datetime('now') THEN 0
                        ELSE CAST(
                            (julianday(c.not_after) - julianday('now'))
                            AS INTEGER
                        )
                   END) AS INTEGER) AS min_days,
                   COUNT(*) AS cnt
            FROM certificates c
            JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
            WHERE c.is_leaf = 1
            GROUP BY grp
            """
        ).fetchall()

        # Pending hosts: hosts with no leaf certificate
        # For issuer pivot, pending hosts have no cert so group by "Unknown"
        pending_group_col = "''" if pivot == "issuer" else group_col
        pending_rows = conn.execute(
            f"""
            SELECT {pending_group_col} AS grp,
                   COUNT(*) AS cnt
            FROM hosts h
            WHERE NOT EXISTS (
                SELECT 1 FROM certificates c
                WHERE c.hostname = h.hostname AND c.port = h.port AND c.is_leaf = 1
            )
            GROUP BY grp
            """
        ).fetchall()

    result: list[dict] = []

    for r in rows:
        d = dict(r)
        raw_key = d["grp"] or ""
        min_days = d["min_days"]

        if min_days is not None and min_days < 0:
            urgency = "expired"
        elif min_days is not None and min_days < 7:
            urgency = "critical"
        elif min_days is not None and min_days < 30:
            urgency = "warning"
        else:
            urgency = "healthy"

        result.append({
            "key": raw_key,
            "count": d["cnt"],
            "worst_urgency": urgency,
            "earliest_expiry": min_days,
            "entries": None,
        })

    for r in pending_rows:
        d = dict(r)
        raw_key = d["grp"] or ""
        existing = next((g for g in result if g["key"] == raw_key), None)
        if existing:
            existing["count"] += d["cnt"]
            if existing["worst_urgency"] == "healthy":
                existing["worst_urgency"] = "gray"
        else:
            result.append({
                "key": raw_key,
                "count": d["cnt"],
                "worst_urgency": "gray",
                "earliest_expiry": None,
                "entries": None,
            })

    # Apply friendly labels to group keys
    for g in result:
        raw = g["key"] or ""
        if pivot == "issuer":
            g["key"] = friendly_issuer(raw) if raw else "Unknown"
        elif pivot == "owner":
            g["key"] = raw or "Unassigned"
        elif pivot == "renewal_method":
            g["key"] = _METHOD_LABELS.get(raw, raw) if raw else "Unknown"

    result.sort(key=lambda g: g["count"], reverse=True)
    return result


def get_pivot_group_entries(
    db_path: str | Path,
    pivot: str,
    group_key: str,
) -> list[dict]:
    """Return unified entries for a single pivot group.

    Used to lazily load entries when a pivot group is expanded (BC-048).
    ``group_key`` is the *friendly* key as displayed in the pivot table
    (e.g. "Let's Encrypt", "alice", "ACME").

    Uses SQL-level filtering so only matching hosts and their certs are
    materialised at fleet scale.
    """
    from cert_watch.filters import friendly_issuer

    _METHOD_LABELS = {
        "acme": "ACME",
        "cert-manager": "cert-manager",
        "manual": "Manual",
    }

    # Map the friendly group_key back to raw DB values for SQL filtering
    if pivot == "issuer":
        entries = _load_unified_filtered(db_path)
    elif pivot == "owner":
        if group_key == "Unassigned":
            host_where = "COALESCE(h.owner_name, '') = ? OR h.owner_name IS NULL"
            host_params = ("",)
        else:
            host_where = "h.owner_name = ?"
            host_params = (group_key,)
        entries = _load_unified_filtered(db_path, host_where=host_where, host_params=host_params)
    elif pivot == "renewal_method":
        if group_key == "Unknown":
            host_where = "COALESCE(h.renewal_method, '') = ? OR h.renewal_method IS NULL"
            host_params = ("",)
        else:
            # Reverse-label lookup: accept any raw value that maps to the friendly label
            raw_methods = [k for k, v in _METHOD_LABELS.items() if v == group_key]
            if raw_methods:
                ph = ",".join("?" * len(raw_methods))
                host_where = f"h.renewal_method IN ({ph})"
                host_params = tuple(raw_methods)
            else:
                host_where = "h.renewal_method = ?"
                host_params = (group_key,)
        entries = _load_unified_filtered(db_path, host_where=host_where, host_params=host_params)
    else:
        entries = _load_unified_filtered(db_path)

    for e in entries:
        if pivot == "issuer":
            raw = e.get("issuer") or ""
            key = friendly_issuer(raw) if raw else "Unknown"
        elif pivot == "owner":
            key = e.get("owner_name") or "Unassigned"
        elif pivot == "renewal_method":
            raw = e.get("renewal_method") or ""
            key = _METHOD_LABELS.get(raw, raw) if raw else "Unknown"
        else:
            key = "Unknown"
        e["_pivot_key"] = key

    return [e for e in entries if e.get("_pivot_key") == group_key]


def group_entries_by_fingerprint(entries: list[dict]) -> list[dict]:
    """Group scanned entries sharing the same leaf fingerprint into single rows.

    Entries with ``kind != "scanned"`` or no fingerprint pass through unchanged.
    Groups of size 1 also pass through.  Only scanned entries with a matching
    fingerprint and 2+ hosts are collapsed into a ``kind == "grouped"`` entry.
    """
    fp_groups: dict[str, list[dict]] = {}
    first_seen: dict[str, int] = {}

    for idx, e in enumerate(entries):
        fp = e.get("fingerprint_sha256") if e.get("kind") == "scanned" else None
        if fp:
            fp_groups.setdefault(fp, []).append(e)
            first_seen.setdefault(fp, idx)

    result: list[dict] = []
    emitted_fps: set[str] = set()
    group_idx = 0

    for e in entries:
        fp = e.get("fingerprint_sha256") if e.get("kind") == "scanned" else None

        if not fp or len(fp_groups.get(fp, [])) <= 1:
            result.append(e)
            continue

        if fp in emitted_fps:
            continue
        emitted_fps.add(fp)

        group = fp_groups[fp]
        group_idx += 1
        first = group[0]

        urgency_counts: dict[str, int] = {}
        for h in group:
            u = h["urgency"]
            urgency_counts[u] = urgency_counts.get(u, 0) + 1

        group_urgency = "healthy"
        for u in _URGENCY_ORDER:
            if urgency_counts.get(u, 0) > 0:
                group_urgency = u
                break

        result.append({
            "id": first["id"],
            "fingerprint_sha256": fp,
            "group_id": group_idx,
            "kind": "grouped",
            "source": "scanned",
            "subject": first["subject"],
            "issuer": first["issuer"],
            "not_before": first["not_before"],
            "not_after": first["not_after"],
            "days_remaining": first["days_remaining"],
            "urgency": group_urgency,
            "leaf_urgency": first["leaf_urgency"],
            "chain": first["chain"],
            "chain_valid": first["chain_valid"],
            "chain_status": first["chain_status"],
            "san_dns_names": first.get("san_dns_names", []),
            "replaces_cert_id": first.get("replaces_cert_id"),
            "notes": first.get("notes", ""),
            "name": first["subject"] or first["host"],
            "host": first["host"],
            "host_id": first.get("host_id"),
            "host_count": len(group),
            "healthy_count": sum(1 for h in group if h["urgency"] == "healthy"),
            "urgency_summary": urgency_counts,
            "hosts": group,
            "last_scanned_at": first.get("last_scanned_at"),
            "scan_status": first.get("scan_status"),
            "scan_error": first.get("scan_error"),
            "added_at": first.get("added_at"),
            "owner_name": first.get("owner_name", ""),
            "owner_email": first.get("owner_email", ""),
            "owner_slack": first.get("owner_slack", ""),
            "renewal_status": first.get("renewal_status", "pending"),
            "renewal_method": first.get("renewal_method", ""),
            "runbook_url": first.get("runbook_url", ""),
        })

    return result


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


def store_scan_posture(
    db_path: str | Path,
    cert_id: str,
    hostname: str | None,
    port: int | None,
    grade: str,
    findings: list[dict],
    protocol_version: str = "",
    ocsp_stapling: bool | None = None,
    hsts: bool | None = None,
    must_staple: bool = False,
    tls_verified: bool | None = None,
    scanned_at: str | None = None,
) -> str:
    """Store a posture evaluation result in the scan_posture table.

    Returns the posture entry id.
    """
    from cert_watch.posture import Finding

    init_schema(db_path)
    posture_id = str(uuid.uuid4())
    if scanned_at is None:
        scanned_at = _iso(datetime.now(UTC))

    findings_json = json.dumps([
        {"check": f.check, "status": f.status, "message": f.message}
        if isinstance(f, Finding) else f
        for f in findings
    ])

    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO scan_posture
            (id, cert_id, hostname, port, grade, protocol_version,
             ocsp_stapling, hsts, must_staple, tls_verified, findings, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                posture_id,
                cert_id,
                hostname,
                port,
                grade,
                protocol_version,
                1 if ocsp_stapling is True else (0 if ocsp_stapling is False else None),
                1 if hsts is True else (0 if hsts is False else None),
                1 if must_staple else 0,
                1 if tls_verified is True else (0 if tls_verified is False else None),
                findings_json,
                scanned_at,
            ),
        )
        conn.commit()
    return posture_id


def get_posture_for_cert(db_path: str | Path, cert_id: str) -> dict | None:
    """Get the most recent posture evaluation for a certificate.

    Returns a dict with grade, findings, protocol_version, etc. or None.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scan_posture WHERE cert_id = ? "
            "ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (cert_id,),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["findings"] = (
            json.loads(d["findings"])
            if isinstance(d["findings"], str)
            else d["findings"]
        )
    except (json.JSONDecodeError, TypeError):
        d["findings"] = []
    return d


def get_posture_grades_for_certs(
    db_path: str | Path, cert_ids: list[str]
) -> dict[str, str]:
    """Get the latest posture grade for each cert_id.

    Returns {cert_id: grade} for certs that have posture data.
    """
    if not cert_ids:
        return {}
    init_schema(db_path)
    with _connect(db_path) as conn:
        ph = ",".join("?" * len(cert_ids))
        # Pick exactly one row per cert_id — the latest by (scanned_at, id).
        # The id tiebreaker makes the result deterministic when two scans
        # share an identical scanned_at timestamp.
        rows = conn.execute(
            f"""SELECT sp.cert_id, sp.grade FROM scan_posture sp
            WHERE sp.cert_id IN ({ph})
              AND sp.id = (
                SELECT sp2.id FROM scan_posture sp2
                WHERE sp2.cert_id = sp.cert_id
                ORDER BY sp2.scanned_at DESC, sp2.id DESC
                LIMIT 1
              )""",
            cert_ids,
        ).fetchall()
    return {r["cert_id"]: r["grade"] for r in rows}


# ---------- kv_store helpers ----------


def kv_get(db_path: str | Path, key: str, encryption_key: str | None = None) -> str | None:
    """Get a value from the kv_store table. Returns None if key not found.

    When *encryption_key* is set and the stored value has the ``enc:v1:``
    prefix, the value is transparently decrypted (BC-082).
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    val = row["value"]
    if encryption_key and val.startswith(_ENCRYPTED_PREFIX):
        val = fernet_decrypt(val, encryption_key)
    return val


def kv_set(db_path: str | Path, key: str, value: str) -> None:
    """Set a value in the kv_store table (upsert)."""
    init_schema(db_path)
    now = _iso(datetime.now(UTC))
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now),
        )
        conn.commit()


def kv_set_secret(db_path: str | Path, key: str, value: str, encryption_key: str) -> None:
    """Encrypt and store a sensitive value in kv_store (BC-082)."""
    kv_set(db_path, key, fernet_encrypt(value, encryption_key))


def kv_all(db_path: str | Path) -> dict[str, str]:
    """Return all key-value pairs from the kv_store table."""
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
    return {r["key"]: r["value"] for r in rows}


# ---------- cert_history (Plan 016) ----------


def _extract_key_algo(raw_der: bytes) -> str:
    """Extract key algorithm string from DER-encoded certificate."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        cert = x509.load_der_x509_certificate(raw_der)
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return f"RSA-{key.key_size}"
        if isinstance(key, ec.EllipticCurvePublicKey):
            return f"EC-{key.curve.name}"
        return type(key).__name__
    except Exception:
        return ""


def _extract_sig_algo(raw_der: bytes) -> str:
    """Extract signature algorithm string from DER-encoded certificate."""
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(raw_der)
        oid = cert.signature_algorithm_oid
        return oid._name if hasattr(oid, "_name") else oid.dotted_string
    except Exception:
        return ""


def record_cert_history(
    db_path: str | Path,
    hostname: str,
    port: int,
    leaf: Certificate,
    posture_grade: str = "",
    protocol_version: str = "",
    scanned_at: str | None = None,
) -> str:
    """Append a per-scan snapshot row to cert_history.

    Called after every successful leaf scan. Returns the new row id.
    """
    init_schema(db_path)
    row_id = str(uuid.uuid4())
    if scanned_at is None:
        scanned_at = _iso(datetime.now(UTC))

    key_algo = _extract_key_algo(leaf.raw_der) if leaf.raw_der else ""
    sig_algo = _extract_sig_algo(leaf.raw_der) if leaf.raw_der else ""

    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO cert_history
            (id, hostname, port, fingerprint_sha256, issuer, not_after,
             key_algo, sig_algo, posture_grade, protocol_version, san_count, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
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
            ),
        )
        conn.commit()
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
    except Exception:
        import logging
        logging.getLogger("cert_watch.database").warning("cert_history purge failed", exc_info=True)
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


# ---------- Calendar (Plan 016 Slice 4) ----------


def list_calendar(
    db_path: str | Path,
    from_date: str | None = None,
    to_date: str | None = None,
    bucket: str = "month",
) -> list[dict]:
    """Return certificate expiry buckets for the calendar view.

    Buckets: ``day``, ``week``, ``month``.  Each result has
    ``bucket_start``, ``count``, and ``cert_ids`` (JSON array).
    Only leaf certificates are included.
    """
    init_schema(db_path)
    if bucket not in ("day", "week", "month"):
        bucket = "month"

    # SQLite date formatting for bucketing
    if bucket == "day":
        group_expr = "DATE(not_after)"
    elif bucket == "week":
        # Start of ISO week (Monday)
        group_expr = "DATE(not_after, 'weekday 0', '-6 days')"
    else:  # month
        group_expr = "DATE(not_after, 'start of month')"

    conditions = ["is_leaf = 1"]
    params: list[str] = []
    if from_date:
        conditions.append("not_after >= ?")
        params.append(from_date)
    if to_date:
        conditions.append("not_after <= ?")
        params.append(to_date)

    where = " AND ".join(conditions)

    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT {group_expr} AS bucket_start,
                       COUNT(*) AS count,
                       GROUP_CONCAT(id) AS cert_ids_csv
                FROM certificates
                WHERE {where}
                GROUP BY {group_expr}
                ORDER BY bucket_start""",
            params,
        ).fetchall()

    result = []
    for r in rows:
        ids = r["cert_ids_csv"].split(",") if r["cert_ids_csv"] else []
        result.append({
            "bucket_start": r["bucket_start"],
            "count": r["count"],
            "cert_ids": ids,
        })
    return result


# ---------- Alert retention (Plan 002 WI-1) ----------


def purge_old_alerts(db_path: str | Path, retention_days: int) -> int:
    """Delete alerts rows older than *retention_days*. Returns count deleted.

    A non-positive ``retention_days`` disables purging (returns 0).
    """
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    try:
        init_schema(db_path)
        with _connect(db_path) as conn:
            cur = conn.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff,))
            deleted = cur.rowcount
            conn.commit()
        if deleted:
            import logging
            logging.getLogger("cert_watch.database").info(
                "purged %d alert rows older than %d days", deleted, retention_days
            )
        return deleted
    except Exception:
        import logging
        logging.getLogger("cert_watch.database").warning("alert purge failed", exc_info=True)
        return 0


# ---------- Session version helpers (BC-081) ----------


def get_session_version(db_path: str | Path, username: str) -> int:
    """Return the current session version for *username*, defaulting to 0.

    A version of 0 means no row exists yet — sessions without a version
    record are accepted (backward compat for tokens issued before this
    feature was added).
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT version FROM session_versions WHERE username = ?", (username,)
        ).fetchone()
    return row["version"] if row else 0


def bump_session_version(db_path: str | Path, username: str) -> int:
    """Increment and return the session version for *username*.

    Creates the row (starting at version 1) if it doesn't exist. Returns the
    new version, so callers can use it directly.
    """
    init_schema(db_path)
    now = _iso(datetime.now(UTC))
    with _connect(db_path) as conn:
        # Try to increment first
        cur = conn.execute(
            "UPDATE session_versions SET version = version + 1, updated_at = ?"
            " WHERE username = ?",
            (now, username),
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO session_versions (username, version, updated_at)"
                " VALUES (?, 1, ?)",
                (username, now),
            )
            version = 1
        else:
            row = conn.execute(
                "SELECT version FROM session_versions WHERE username = ?", (username,)
            ).fetchone()
            version = row["version"]
        conn.commit()
    return version
