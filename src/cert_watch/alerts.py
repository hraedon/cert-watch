"""Email alerts. See spec wi_fr04_alerts.md."""

from __future__ import annotations

import smtplib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage

from cert_watch.certificate_model import Certificate
from cert_watch.database import Alert, AlertRepository

LEAF_THRESHOLDS = (14, 7, 3, 1)
CHAIN_THRESHOLDS = (30, 14, 7)


@dataclass
class AlertConfig:
    """SMTP configuration. See AC-01."""

    smtp_host: str
    smtp_user: str
    smtp_password: str
    from_addr: str
    recipients: list[str] = field(default_factory=list)
    smtp_port: int = 587


def evaluate_thresholds(
    cert: Certificate,
    alert_repo: AlertRepository,
    *,
    cert_id: str | None = None,
) -> list[Alert]:
    """
    Create pending alerts for thresholds the cert has now crossed, skipping any
    threshold that already has an alert recorded for this cert. See AC-02.

    The spec talks about cert_id as the link to existing alerts; we accept it as
    a kwarg so callers that persisted the cert can pass the row id. If omitted we
    use fingerprint_sha256 as a stable handle.
    """
    days = cert.days_until_expiry()
    thresholds = LEAF_THRESHOLDS if cert.is_leaf else CHAIN_THRESHOLDS
    cid = cert_id or cert.fingerprint_sha256

    # Find existing alerts for this cert and their thresholds (via threshold_days col).
    existing_thresholds: set[int] = set()
    if hasattr(alert_repo, "list_for_cert"):
        for a in alert_repo.list_for_cert(cid):
            if a.threshold_days is not None:
                existing_thresholds.add(a.threshold_days)
    else:
        # Fallback: list pending only.
        for a in alert_repo.list_pending():
            if a.cert_id == cid and a.threshold_days is not None:
                existing_thresholds.add(a.threshold_days)

    created: list[Alert] = []
    for t in thresholds:
        if days <= t and t not in existing_thresholds:
            alert = Alert(
                cert_id=cid,
                alert_type="expired" if days < 0 else "expiry_warning",
                status="pending",
                message=_format_message(cert, days, t),
                threshold_days=t,
            )
            alert_id = alert_repo.create(alert)
            alert.id = alert_id
            created.append(alert)
            existing_thresholds.add(t)
    return created


def _format_message(cert: Certificate, days: int, threshold: int) -> str:
    """See AC-05."""
    action = (
        "Renew this certificate immediately."
        if days <= 7
        else "Plan a renewal soon."
    )
    return (
        f"Certificate '{cert.display_name}' "
        f"(subject: {cert.subject}) "
        f"expires on {cert.not_after.isoformat()} "
        f"({days} days remaining; threshold: <={threshold}d). "
        f"Recommended action: {action}"
    )


def send_alert(alert: Alert, config: AlertConfig | None) -> bool:
    """Send via SMTP. See AC-03/AC-06."""
    if config is None:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[cert-watch] {alert.alert_type}: {alert.message[:60]}"
    msg["From"] = config.from_addr
    msg["To"] = ", ".join(config.recipients)
    msg.set_content(alert.message)
    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15) as s:
            s.starttls()
            if config.smtp_user:
                s.login(config.smtp_user, config.smtp_password)
            s.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 — AC-06 says do not raise
        alert.error_message = str(exc)
        return False


def process_pending(
    alert_repo: AlertRepository, config: AlertConfig | None
) -> dict[str, int]:
    """See AC-04. No-ops when config is None (per scaffold convention)."""
    if config is None:
        return {"sent": 0, "failed": 0}
    sent = 0
    failed = 0
    for alert in alert_repo.list_pending():
        if send_alert(alert, config):
            alert.sent_at = datetime.now(UTC)
            alert_repo.mark_sent(alert.id)
            sent += 1
        else:
            alert_repo.mark_failed(alert.id, alert.error_message or "unknown")
            failed += 1
    return {"sent": sent, "failed": failed}
