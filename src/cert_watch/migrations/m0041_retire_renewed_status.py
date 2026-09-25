"""Migration 0041 — retire the operator-reported ``renewed`` status.

A claim that renewal completed must never suppress certificate expiry alerts.
Existing claims are reset to ``pending`` so every stored host uses one of the
remaining operator-report states.  Each reset is audited for visibility.

Migration ids 0039 and 0040 are reserved by the work in pull request #114.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime

MIGRATION_ID = "0041"
DESCRIPTION = "retire renewed host status and reset existing claims to pending"


def upgrade(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        "SELECT id FROM hosts WHERE renewal_status = 'renewed' ORDER BY id"
    ).fetchall()
    now = datetime.now(UTC).isoformat()
    detail = json.dumps(
        {
            "renewal_status": "pending",
            "previous_renewal_status": "renewed",
            "reason": "migration 0041 retired the renewed status",
        }
    )
    for row in rows:
        host_id = row[0]
        conn.execute(
            "UPDATE hosts SET renewal_status = 'pending' "
            "WHERE id = ? AND renewal_status = 'renewed'",
            (host_id,),
        )
        conn.execute(
            "INSERT INTO audit_log "
            "(id, ts, actor, action, target_type, target_id, detail, source_ip) "
            "VALUES (?, ?, 'migration:0041', 'host.update_settings', "
            "'host', ?, ?, NULL)",
            (str(uuid.uuid4()), now, host_id, detail),
        )
