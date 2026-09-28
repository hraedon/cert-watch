"""Migration 0047 — move legacy renewal progress into leased attempts (#118 S3)."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

MIGRATION_ID = "0047"
DESCRIPTION = "backfill leased renewal attempts and allow manual cancellation"


def _lease_hours(conn: sqlite3.Connection) -> int:
    raw = os.environ.get("CERT_WATCH_RENEWAL_REPORT_LEASE_HOURS", "").strip()
    if not raw:
        has_kv = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='kv_store'"
        ).fetchone()
        row = (
            conn.execute(
                "SELECT value FROM kv_store WHERE key='renewal_report_lease_hours'"
            ).fetchone()
            if has_kv is not None
            else None
        )
        raw = str(row[0]).strip() if row is not None else ""
    try:
        hours = int(raw) if raw else 24
    except ValueError:
        return 24
    return hours if 1 <= hours <= 168 else 24


def _allow_cancelled_reports(conn: sqlite3.Connection) -> None:
    sql = str(
        conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='renewal_reports'"
        ).fetchone()[0]
    )
    if "'cancelled'" in sql:
        return
    conn.execute("ALTER TABLE renewal_reports RENAME TO renewal_reports_old_0047")
    conn.execute(
        """CREATE TABLE renewal_reports (
               seq INTEGER PRIMARY KEY AUTOINCREMENT,
               report_id TEXT NOT NULL UNIQUE,
               host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
               hostname_snapshot TEXT NOT NULL,
               port_snapshot INTEGER NOT NULL,
               outcome TEXT NOT NULL CHECK (
                   outcome IN ('started','succeeded','failed','cancelled')
               ),
               message TEXT,
               tool TEXT,
               correlation_id TEXT,
               new_fingerprint TEXT,
               occurred_at TEXT,
               received_at TEXT NOT NULL,
               source TEXT NOT NULL,
               effect TEXT NOT NULL CHECK (
                   effect IN ('applied','ignored_late','duplicate','no_change')
               ),
               attempt_id TEXT NOT NULL
           )"""
    )
    conn.execute(
        """INSERT INTO renewal_reports
           (seq,report_id,host_id,hostname_snapshot,port_snapshot,outcome,message,tool,
            correlation_id,new_fingerprint,occurred_at,received_at,source,effect,attempt_id)
           SELECT seq,report_id,host_id,hostname_snapshot,port_snapshot,outcome,message,tool,
                  correlation_id,new_fingerprint,occurred_at,received_at,source,effect,attempt_id
           FROM renewal_reports_old_0047"""
    )
    conn.execute("DROP TABLE renewal_reports_old_0047")
    conn.execute(
        "CREATE INDEX idx_renewal_reports_host_seq ON renewal_reports(host_id, seq DESC)"
    )
    conn.execute(
        "CREATE INDEX idx_renewal_reports_source_seq ON renewal_reports(source, seq DESC)"
    )


def upgrade(conn: sqlite3.Connection) -> None:
    _allow_cancelled_reports(conn)
    now = datetime.now(UTC)
    received_at = now.isoformat()
    lease_expires_at = (now + timedelta(hours=_lease_hours(conn))).isoformat()
    rows = conn.execute(
        """SELECT h.id,h.hostname,h.port,c.fingerprint_sha256,c.not_after
           FROM hosts h
           LEFT JOIN certificates c ON c.rowid=(
               SELECT leaf.rowid FROM certificates leaf
               WHERE leaf.hostname=h.hostname AND leaf.port=h.port
                 AND leaf.is_leaf=1 AND leaf.source='scanned'
               ORDER BY leaf.created_at DESC,leaf.rowid DESC LIMIT 1
           )
           WHERE h.renewal_status='in_progress'
           ORDER BY h.id"""
    ).fetchall()
    for row in rows:
        host_id, hostname, port, fingerprint, not_after = row
        existing = conn.execute(
            """SELECT 1 FROM renewal_reports
               WHERE host_id=? AND source='migration:0047' LIMIT 1""",
            (host_id,),
        ).fetchone()
        if existing is not None:
            continue
        conn.execute(
            "UPDATE renewal_attempts SET is_current=0 WHERE host_id=? AND is_current=1",
            (host_id,),
        )
        attempt_id = uuid.uuid4().hex
        report_id = uuid.uuid4().hex
        cursor = conn.execute(
            """INSERT INTO renewal_reports
               (report_id,host_id,hostname_snapshot,port_snapshot,outcome,message,tool,
                correlation_id,new_fingerprint,occurred_at,received_at,source,effect,attempt_id)
               VALUES (?,?,?,?, 'started',NULL,NULL,NULL,NULL,NULL,?,
                       'migration:0047','applied',?)""",
            (report_id, host_id, hostname, port, received_at, attempt_id),
        )
        assert cursor.lastrowid is not None
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,baseline_fingerprint,
                baseline_not_after,new_fingerprint,lease_expires_at,suppresses_stalled,
                received_at,next_check_at,closed_reason)
               VALUES (?,?,1,'migration:0047','open',?,?,?,NULL,?,1,?,NULL,NULL)""",
            (
                attempt_id,
                host_id,
                int(cursor.lastrowid),
                str(fingerprint).lower() if fingerprint else None,
                not_after,
                lease_expires_at,
                received_at,
            ),
        )
        detail = json.dumps(
            {
                "attempt_id": attempt_id,
                "lease_expires_at": lease_expires_at,
                "previous_renewal_status": "in_progress",
                "reason": "migration 0047 converted renewal progress to a leased attempt",
            }
        )
        conn.execute(
            """INSERT INTO audit_log
               (id,ts,actor,action,target_type,target_id,detail,source_ip)
               VALUES (?,?,'migration:0047','renewal_report.create','host',?,?,NULL)""",
            (str(uuid.uuid4()), received_at, host_id, detail),
        )
