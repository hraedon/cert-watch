"""Migration 0037 — alert dedupe keys, condition closure, and routing snapshots."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime

MIGRATION_ID = "0037"
DESCRIPTION = "add alert dedupe keys, closure timestamps, and routing snapshots"

_POLICY_RULE = re.compile(r"\[([^\]]+)\]")


def _routing_snapshot(raw_recipients: object) -> str:
    try:
        recipients = (
            json.loads(raw_recipients)
            if isinstance(raw_recipients, (str, bytes, bytearray)) and raw_recipients
            else []
        )
    except (json.JSONDecodeError, TypeError):
        recipients = []
    if not isinstance(recipients, list):
        recipients = []
    return json.dumps(
        {"version": 1, "recipients": recipients, "groups": []},
        separators=(",", ":"),
        sort_keys=True,
    )


def _backfill_key(row: sqlite3.Row) -> str | None:
    fingerprint = row["fingerprint_sha256"]
    alert_type = row["alert_type"]
    if not fingerprint:
        return None
    if alert_type in {"expiry_warning", "expired"} and row["threshold_days"] is not None:
        return f"expiry:{fingerprint}:{alert_type}:{row['threshold_days']}"
    if alert_type == "renewal_stalled":
        return f"renewal:{fingerprint}"
    if alert_type == "policy_violation":
        match = _POLICY_RULE.search(row["message"] or "")
        if match:
            return f"policy:{fingerprint}:{match.group(1)}"
    return None


def upgrade(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    for name, definition in {
        "dedupe_key": "TEXT",
        "closed_at": "TEXT",
        "routing": "TEXT",
    }.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")

    conn.execute(
        """CREATE TABLE IF NOT EXISTS rule_firings (
            dedupe_key TEXT PRIMARY KEY,
            first_fired_at TEXT NOT NULL,
            last_fired_at TEXT NOT NULL,
            fire_count INTEGER NOT NULL
        )"""
    )

    tables = {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    if "event_log" in tables:
        for event in conn.execute(
            """SELECT payload, created_at FROM event_log
               WHERE event_type = 'renewal_overdue' ORDER BY created_at"""
        ).fetchall():
            try:
                payload = json.loads(event["payload"])
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(payload, dict):
                continue
            hostname = payload.get("hostname")
            fingerprint = payload.get("cert_fingerprint")
            port = payload.get("port")
            if not isinstance(hostname, str) or not isinstance(fingerprint, str):
                continue
            if port is None:
                port_key = "*"
            elif type(port) is int and 1 <= port <= 65535:
                port_key = str(port)
            else:
                continue
            key = f"overdue:{hostname}:{port_key}:{fingerprint}"
            conn.execute(
                """INSERT INTO rule_firings
                       (dedupe_key, first_fired_at, last_fired_at, fire_count)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(dedupe_key) DO UPDATE SET
                       last_fired_at = MAX(last_fired_at, excluded.last_fired_at),
                       fire_count = fire_count + 1""",
                (key, event["created_at"], event["created_at"]),
            )

    alert_columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    recipients_expr = (
        "a.extra_recipients" if "extra_recipients" in alert_columns else "'[]'"
    )
    threshold_expr = (
        "a.threshold_days" if "threshold_days" in alert_columns else "NULL"
    )
    rows = conn.execute(
        f"""SELECT a.id, a.alert_type, a.message, {threshold_expr} AS threshold_days,
                  {recipients_expr} AS extra_recipients, c.fingerprint_sha256
           FROM alerts AS a
           LEFT JOIN certificates AS c ON c.id = a.cert_id
           WHERE a.dedupe_key IS NULL OR a.routing IS NULL"""
    ).fetchall()
    for row in rows:
        dedupe_key = _backfill_key(row)
        conn.execute(
            """UPDATE alerts
               SET dedupe_key = COALESCE(dedupe_key, ?),
                   routing = COALESCE(routing, ?)
               WHERE id = ?""",
            (dedupe_key, _routing_snapshot(row["extra_recipients"]), row["id"]),
        )

    # Pre-lifecycle versions could have several deliverable rows for one
    # condition. Keep the oldest as pending and retain the others as cancelled
    # history before installing the queue-level uniqueness guard.
    now = datetime.now(UTC).isoformat()
    duplicate_keys = conn.execute(
        """SELECT dedupe_key FROM alerts
           WHERE dedupe_key IS NOT NULL AND status IN ('pending', 'sending')
           GROUP BY dedupe_key HAVING COUNT(*) > 1"""
    ).fetchall()
    for duplicate in duplicate_keys:
        key = duplicate["dedupe_key"]
        open_rows = conn.execute(
            """SELECT id FROM alerts
               WHERE dedupe_key = ? AND status IN ('pending', 'sending')
               ORDER BY created_at, id""",
            (key,),
        ).fetchall()
        keeper = open_rows[0]["id"]
        conn.execute(
            """UPDATE alerts SET status = 'pending', lease_owner = NULL,
                      lease_expires_at = NULL, next_attempt_at = NULL
               WHERE id = ?""",
            (keeper,),
        )
        conn.executemany(
            """UPDATE alerts SET status = 'cancelled', closed_at = ?,
                      lease_owner = NULL, lease_expires_at = NULL,
                      next_attempt_at = NULL, deferred_since = NULL
               WHERE id = ?""",
            ((now, row["id"]) for row in open_rows[1:]),
        )

    conn.execute(
        """CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_open_dedupe
           ON alerts(dedupe_key)
           WHERE dedupe_key IS NOT NULL
             AND status IN ('pending', 'sending')"""
    )
