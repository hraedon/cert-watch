"""Alerts derived from durable renewal-report attempt state."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from cert_watch.alerting.keys import certificate_alert_key
from cert_watch.alerting.routing import resolve_routing
from cert_watch.database import Alert, AlertRepository, AlertStore, get_write_lock
from cert_watch.database.connection import _connect, begin_immediate


@dataclass(frozen=True)
class _Condition:
    alert_type: str
    at: str


def _conditions(row: sqlite3.Row) -> tuple[_Condition, ...]:
    conditions: list[_Condition] = []
    if row["failure_reported_at"] and not row["failure_cleared_at"]:
        conditions.append(_Condition("renewal_failed", str(row["failure_reported_at"])))
    if row["state"] == "not_deployed":
        conditions.append(_Condition("renewal_not_deployed", str(row["received_at"])))
    return tuple(conditions)


def _key(row: sqlite3.Row, alert_type: str) -> str:
    if alert_type == "renewal_failed":
        failure_attempt_id = row["failure_attempt_id"] or row["attempt_id"]
        return f"renewal_failed:{failure_attempt_id}"
    return certificate_alert_key(
        alert_type,
        cert_id=str(row["cert_id"]),
        fingerprint=row["fingerprint_sha256"],
        hostname=row["hostname"],
        port=row["port"],
        suffix=(str(row["attempt_id"]),),
    )


def _message(row: sqlite3.Row, condition: _Condition, link: str) -> str:
    endpoint = f"{row['hostname']}:{row['port']}"
    if condition.alert_type == "renewal_failed":
        return (
            f"Renewal automation reported a failure for {endpoint} at {condition.at}. "
            f"Details: {link}"
        )
    deployment = (
        "serves a certificate different from the reported fingerprint"
        if row["verification_reason"] == "mismatch"
        else "still serves the previous certificate"
    )
    return (
        f"Renewal of {endpoint} was reported successful at {condition.at} but the "
        f"endpoint {deployment}. Details: {link}"
    )


def evaluate_renewal_report_alerts(
    db_path: str | Path,
    alert_repo: AlertRepository,
    *,
    base_url: str = "",
    closed_sent: list[Alert] | None = None,
) -> list[Alert]:
    """Open and close attempt-scoped renewal failure/deployment alerts."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT a.attempt_id,a.state,a.received_at,a.failure_attempt_id,
                      a.failure_reported_at,a.failure_cleared_at,
                      a.verification_reason,h.hostname,h.port,
                      c.id AS cert_id,c.subject,c.fingerprint_sha256
               FROM renewal_attempts a
               JOIN hosts h ON h.id=a.host_id
               JOIN certificates c ON c.rowid=(
                   SELECT leaf.rowid FROM certificates leaf
                   WHERE leaf.hostname=h.hostname AND leaf.port=h.port
                     AND leaf.is_leaf=1 AND leaf.source='scanned'
                   ORDER BY leaf.created_at DESC,leaf.rowid DESC LIMIT 1
               )
               WHERE (a.is_current=1 AND a.state='not_deployed') OR (
                     a.failure_reported_at IS NOT NULL
                     AND a.failure_cleared_at IS NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM renewal_attempts later
                         WHERE later.host_id=a.host_id
                           AND later.failure_attempt_id=
                               COALESCE(a.failure_attempt_id,a.attempt_id)
                           AND later.opened_seq>a.opened_seq
                     )
                 )
               ORDER BY a.opened_seq"""
        ).fetchall()
        wake_rows = conn.execute(
            """SELECT attempt_id,rule_due_at FROM renewal_attempts
               WHERE rule_due_at IS NOT NULL"""
        ).fetchall()
        open_keys = {
            str(row["dedupe_key"])
            for row in conn.execute(
                """SELECT dedupe_key FROM alerts
                   WHERE alert_type IN ('renewal_failed','renewal_not_deployed')
                     AND closed_at IS NULL AND dedupe_key IS NOT NULL"""
            )
        }
    active_keys = {
        _key(row, condition.alert_type)
        for row in rows
        for condition in _conditions(row)
    }
    closed = AlertStore(db_path).close_keys(open_keys - active_keys)
    if closed_sent is not None:
        closed_sent.extend(closed)
    routing = resolve_routing(db_path, tuple(str(row["cert_id"]) for row in rows))
    created: list[Alert] = []
    for row in rows:
        cert_id = str(row["cert_id"])
        link = (
            f"{base_url.rstrip('/')}/certificates/{cert_id}"
            if base_url
            else f"/certificates/{cert_id}"
        )
        route = routing[cert_id]
        for condition in _conditions(row):
            alert = Alert(
                cert_id=cert_id,
                trigger_cert_id=cert_id,
                alert_type=condition.alert_type,
                status="pending",
                message=_message(row, condition, link),
                threshold_days=None,
                hostname=str(row["hostname"]),
                subject=str(row["subject"] or ""),
                dedupe_key=_key(row, condition.alert_type),
                routing=route,
                extra_recipients=list(route["recipients"]),
            )
            alert_id = alert_repo.enqueue(alert, lifetime=False)
            if alert_id is not None:
                alert.id = alert_id
                created.append(alert)
    # Consume only the durable wake values observed by this pass.  A report
    # racing enqueue changes rule_due_at, so its compare-and-set fails and the
    # scheduler immediately runs another pass that can see the new condition.
    with get_write_lock():
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            for wake in wake_rows:
                conn.execute(
                    """UPDATE renewal_attempts SET rule_due_at=NULL
                       WHERE attempt_id=? AND rule_due_at=?""",
                    (wake["attempt_id"], wake["rule_due_at"]),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return created
