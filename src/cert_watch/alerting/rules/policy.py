"""Policy-violation rule."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from cert_watch.database import Alert

if TYPE_CHECKING:
    from cert_watch.policy import PolicyViolation


def evaluate_policy_alerts(
    cert_id: str,
    hostname: str,
    violations: list[PolicyViolation],
    db_path: str | Path,
    *,
    subject: str = "",
    conn: sqlite3.Connection | None = None,
    fingerprint: str | None = None,
    closed_sent: list[Alert] | None = None,
) -> list[Alert]:
    """Queue current warning/critical rules and close rules no longer present."""
    from cert_watch.alerting.routing import resolve_routing
    from cert_watch.database import AlertStore
    from cert_watch.database.connection import _connect

    if conn is not None:
        cert_row = conn.execute(
            "SELECT fingerprint_sha256 FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
    else:
        with _connect(db_path) as lookup:
            cert_row = lookup.execute(
                "SELECT fingerprint_sha256 FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
    cert_fingerprint = fingerprint or (
        cert_row["fingerprint_sha256"] if cert_row else None
    )
    routing = resolve_routing(db_path, (cert_id,), conn=conn)[cert_id]
    active_rule_ids = {
        violation.rule_id
        for violation in violations
        if violation.severity in ("critical", "warning")
    }
    store = AlertStore(db_path, initialize=conn is None)
    if cert_fingerprint:
        query = """SELECT dedupe_key FROM alerts
                   WHERE alert_type = 'policy_violation' AND closed_at IS NULL
                     AND dedupe_key LIKE ?"""
        if conn is not None:
            open_rows = conn.execute(
                query, (f"policy:{cert_fingerprint}:%",)
            ).fetchall()
        else:
            with _connect(db_path) as lookup:
                open_rows = lookup.execute(
                    query, (f"policy:{cert_fingerprint}:%",)
                ).fetchall()
        active_keys = {
            f"policy:{cert_fingerprint}:{rule_id}" for rule_id in active_rule_ids
        }
        stale_keys = {row["dedupe_key"] for row in open_rows} - active_keys
        closed = store.close_keys(stale_keys, conn=conn)
        if closed_sent is not None:
            closed_sent.extend(closed)

    created: list[Alert] = []
    for violation in violations:
        if violation.severity not in ("critical", "warning"):
            continue
        alert = Alert(
            cert_id=cert_id,
            alert_type="policy_violation",
            status="pending",
            message=(
                f"Policy violation ({violation.severity}) [{violation.rule_id}]: "
                f"{violation.message} Remediation: {violation.remediation}"
            ),
            hostname=hostname,
            subject=subject,
            dedupe_key=(
                f"policy:{cert_fingerprint}:{violation.rule_id}"
                if cert_fingerprint else None
            ),
            routing=routing,
            extra_recipients=list(routing["recipients"]),
        )
        alert_id = store.enqueue(alert, conn=conn)
        if alert_id is None:
            continue
        alert.id = alert_id
        created.append(alert)
    return created
