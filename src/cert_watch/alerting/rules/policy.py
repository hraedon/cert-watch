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
) -> list[Alert]:
    """Create pending alerts for critical or warning policy violations.

    Info-level violations are recorded but do not generate alerts.
    Returns the list of created Alert objects.

    Deduplication: before creating a new alert for a (cert_id, rule_id)
    pair, check whether a pending ``policy_violation`` alert already exists
    for the same cert and rule_id. Only create a new alert if no matching
    pending alert is found (mirrors the cooldown logic in
    ``evaluate_thresholds``). When *conn* is provided it is used directly
    and the caller owns commit/rollback.
    """
    from cert_watch.database import SqliteAlertRepository

    alert_repo = SqliteAlertRepository(db_path)
    existing = alert_repo.list_for_cert(cert_id, conn=conn)
    existing_rule_ids: set[str] = set()
    for a in existing:
        if a.alert_type == "policy_violation" and a.status == "pending":
            for v in violations:
                marker = f"[{v.rule_id}]"
                if marker in a.message:
                    existing_rule_ids.add(v.rule_id)
                    break
    created: list[Alert] = []
    for v in violations:
        if v.severity not in ("critical", "warning"):
            continue
        if v.rule_id in existing_rule_ids:
            continue
        alert = Alert(
            cert_id=cert_id,
            alert_type="policy_violation",
            status="pending",
            message=(
                f"Policy violation ({v.severity}) [{v.rule_id}]: {v.message} "
                f"Remediation: {v.remediation}"
            ),
            hostname=hostname,
            subject=subject,
        )
        alert.id = alert_repo.create(alert, conn=conn)
        created.append(alert)
    return created
