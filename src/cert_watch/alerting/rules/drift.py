"""Posture-drift edge alerts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.alerting.routing import resolve_routing
from cert_watch.database import Alert, AlertStore, DriftEvent
from cert_watch.database.drift import _drift_summary


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
    """Queue a high-severity drift edge with an immediately closed key."""
    high = [event for event in events if event.severity == "high"]
    if not high:
        return None
    if conn is not None:
        row = conn.execute(
            "SELECT subject, fingerprint_sha256 FROM certificates WHERE id = ?",
            (cert_id,),
        ).fetchone()
    else:
        from cert_watch.database.connection import _connect
        with _connect(db_path) as lookup:
            row = lookup.execute(
                "SELECT subject, fingerprint_sha256 FROM certificates WHERE id = ?",
                (cert_id,),
            ).fetchone()
    subject = (row["subject"] or "") if row else ""
    fingerprint = (row["fingerprint_sha256"] or cert_id) if row else cert_id
    serialized = json.dumps(
        [
            {
                "field": event.field,
                "old": event.old,
                "new": event.new,
                "severity": event.severity,
            }
            for event in events
        ],
        separators=(",", ":"),
        sort_keys=True,
    )
    event_hash = hashlib.sha256(serialized.encode()).hexdigest()
    routing = resolve_routing(db_path, (cert_id,), conn=conn)[cert_id]
    recipients = list(routing["recipients"])
    for address in extra_recipients or []:
        if address not in recipients:
            recipients.append(address)
    routing["recipients"] = recipients
    created_at = datetime.now(UTC)
    alert = Alert(
        cert_id=cert_id,
        alert_type="drift",
        status="pending",
        message=f"{hostname}:{port} — {_drift_summary(events)}",
        extra_recipients=recipients,
        hostname=hostname,
        subject=subject,
        dedupe_key=f"drift:{hostname}:{port}:{fingerprint}:{event_hash}",
        closed_at=created_at,
        created_at=created_at,
        routing=routing,
    )
    return AlertStore(db_path, initialize=conn is None).enqueue(alert, conn=conn)
