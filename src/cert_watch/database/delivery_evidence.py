"""Append-only per-alert delivery observations, retained with their parent alert."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DELIVERY_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS alert_delivery_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id TEXT NOT NULL,
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    occurred_at TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('started', 'completed')),
    channel TEXT NOT NULL,
    details TEXT NOT NULL,
    UNIQUE (attempt_id, event_kind)
);
CREATE INDEX IF NOT EXISTS idx_alert_delivery_events_alert
    ON alert_delivery_events(alert_id, id DESC);
CREATE TRIGGER IF NOT EXISTS alert_delivery_events_no_update
BEFORE UPDATE ON alert_delivery_events BEGIN
    SELECT RAISE(ABORT, 'delivery observations cannot be edited');
END;
"""


def begin_attempt(db_path: str | Path, alert_id: str, channel: str, details: dict[str, Any]) -> str:
    from cert_watch.database.connection import _connect, get_write_lock

    attempt_id = str(uuid.uuid4())
    with get_write_lock(), _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO alert_delivery_events "
            "(attempt_id, alert_id, occurred_at, event_kind, channel, details) "
            "VALUES (?, ?, ?, 'started', ?, ?)",
            (attempt_id, alert_id, datetime.now(UTC).isoformat(), channel, json.dumps(details)),
        )
        conn.commit()
    return attempt_id


def complete_attempt(db_path: str | Path, attempt_id: str, details: dict[str, Any]) -> None:
    from cert_watch.database.connection import _connect, get_write_lock

    with get_write_lock(), _connect(db_path) as conn:
        start = conn.execute(
            "SELECT alert_id, channel FROM alert_delivery_events "
            "WHERE attempt_id = ? AND event_kind = 'started'", (attempt_id,),
        ).fetchone()
        if start is None:
            raise ValueError("Delivery attempt start is unavailable")
        conn.execute(
            "INSERT INTO alert_delivery_events "
            "(attempt_id, alert_id, occurred_at, event_kind, channel, details) "
            "VALUES (?, ?, ?, 'completed', ?, ?)",
            (attempt_id, start["alert_id"], datetime.now(UTC).isoformat(),
             start["channel"], json.dumps(details)),
        )
        conn.commit()


def list_attempts(
    db_path: str | Path, alert_ids: list[str], *, limit: int = 20,
) -> dict[str, list[dict[str, Any]]]:
    """Load bounded history only for alert IDs already authorized by the caller."""
    if not alert_ids:
        return {}
    from cert_watch.database.connection import _connect

    placeholders = ",".join("?" for _ in alert_ids)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""WITH starts AS (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY alert_id ORDER BY id DESC) AS n
                FROM alert_delivery_events
                WHERE alert_id IN ({placeholders}) AND event_kind = 'started'
            )
            SELECT s.alert_id, s.attempt_id, s.channel, s.occurred_at AS started_at,
                   s.details AS routing, c.occurred_at AS completed_at, c.details AS result
            FROM starts s LEFT JOIN alert_delivery_events c
                ON c.attempt_id = s.attempt_id AND c.event_kind = 'completed'
            WHERE s.n <= ? ORDER BY s.id DESC""",
            (*alert_ids, limit),
        ).fetchall()
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        attempt = dict(row)
        attempt["routing"] = json.loads(row["routing"])
        attempt["result"] = json.loads(row["result"]) if row["result"] else None
        result.setdefault(row["alert_id"], []).append(attempt)
    return result


def latest_outcomes(db_path: str | Path, alert_ids: list[str]) -> dict[str, str]:
    """Return only fixed outcome labels, never recipient/routing details."""
    if not alert_ids:
        return {}
    from cert_watch.database.connection import _connect

    placeholders = ",".join("?" for _ in alert_ids)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT s.alert_id, json_extract(c.details, '$.outcome') AS outcome
            FROM alert_delivery_events s LEFT JOIN alert_delivery_events c
                ON c.attempt_id = s.attempt_id AND c.event_kind = 'completed'
            WHERE s.id IN (
                SELECT MAX(id) FROM alert_delivery_events
                WHERE event_kind = 'started' AND alert_id IN ({placeholders}) GROUP BY alert_id
            )""", alert_ids,
        ).fetchall()
    return {row["alert_id"]: row["outcome"] if row["outcome"] in {"accepted", "partial", "failed"}
            else "unknown" for row in rows}
