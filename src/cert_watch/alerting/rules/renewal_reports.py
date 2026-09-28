"""Alerts derived from durable renewal-report attempt state."""

from __future__ import annotations

from pathlib import Path

from cert_watch.alerting.keys import certificate_alert_key
from cert_watch.alerting.routing import resolve_routing
from cert_watch.database import Alert, AlertRepository, AlertStore
from cert_watch.database.connection import _connect


def evaluate_renewal_report_alerts(
    db_path: str | Path,
    alert_repo: AlertRepository,
    *,
    base_url: str = "",
    closed_sent: list[Alert] | None = None,
) -> list[Alert]:
    """Open/close ``renewal_not_deployed`` from current attempt state."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT a.attempt_id,a.received_at,a.verification_reason,h.hostname,h.port,
                      c.id AS cert_id,c.subject,c.fingerprint_sha256
               FROM renewal_attempts a
               JOIN hosts h ON h.id=a.host_id
               JOIN certificates c ON c.rowid=(
                   SELECT leaf.rowid FROM certificates leaf
                   WHERE leaf.hostname=h.hostname AND leaf.port=h.port
                     AND leaf.is_leaf=1 AND leaf.source='scanned'
                   ORDER BY leaf.created_at DESC,leaf.rowid DESC LIMIT 1
               )
               WHERE a.is_current=1 AND a.state='not_deployed'
               ORDER BY a.opened_seq"""
        ).fetchall()
        open_keys = {
            str(row["dedupe_key"])
            for row in conn.execute(
                """SELECT dedupe_key FROM alerts
                   WHERE alert_type='renewal_not_deployed' AND closed_at IS NULL
                     AND dedupe_key IS NOT NULL"""
            )
        }
    active_keys = {
        certificate_alert_key(
            "renewal_not_deployed",
            cert_id=str(row["cert_id"]),
            fingerprint=row["fingerprint_sha256"],
            hostname=row["hostname"],
            port=row["port"],
            suffix=(str(row["attempt_id"]),),
        )
        for row in rows
    }
    closed = AlertStore(db_path).close_keys(open_keys - active_keys)
    if closed_sent is not None:
        closed_sent.extend(closed)
    routing = resolve_routing(db_path, tuple(str(row["cert_id"]) for row in rows))
    created: list[Alert] = []
    for row in rows:
        cert_id = str(row["cert_id"])
        key = certificate_alert_key(
            "renewal_not_deployed",
            cert_id=cert_id,
            fingerprint=row["fingerprint_sha256"],
            hostname=row["hostname"],
            port=row["port"],
            suffix=(str(row["attempt_id"]),),
        )
        link = (
            f"{base_url.rstrip('/')}/certificates/{cert_id}"
            if base_url
            else f"/certificates/{cert_id}"
        )
        route = routing[cert_id]
        condition = (
            "serves a certificate different from the reported fingerprint"
            if row["verification_reason"] == "mismatch"
            else "still serves the previous certificate"
        )
        alert = Alert(
            cert_id=cert_id,
            trigger_cert_id=cert_id,
            alert_type="renewal_not_deployed",
            status="pending",
            message=(
                f"Renewal of {row['hostname']}:{row['port']} was reported successful at "
                f"{row['received_at']} but the endpoint {condition}. "
                f"Details: {link}"
            ),
            threshold_days=None,
            hostname=str(row["hostname"]),
            subject=str(row["subject"] or ""),
            dedupe_key=key,
            routing=route,
            extra_recipients=list(route["recipients"]),
        )
        alert_id = alert_repo.enqueue(alert, lifetime=False)
        if alert_id is not None:
            alert.id = alert_id
            created.append(alert)
    return created
