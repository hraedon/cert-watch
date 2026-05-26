"""Email and webhook alerts. See spec wi_fr04_alerts.md."""

from __future__ import annotations

import json
import smtplib
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path

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


@dataclass
class WebhookConfig:
    """Webhook/Slack alert configuration."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 15


def evaluate_thresholds(
    cert: Certificate,
    alert_repo: AlertRepository,
    *,
    cert_id: str | None = None,
    custom_thresholds: tuple[int, ...] | None = None,
) -> list[Alert]:
    """
    Create pending alerts for thresholds the cert has now crossed, skipping any
    threshold that already has an alert recorded for this cert. See AC-02.

    The spec talks about cert_id as the link to existing alerts; we accept it as
    a kwarg so callers that persisted the cert can pass the row id. If omitted we
    use fingerprint_sha256 as a stable handle.

    If custom_thresholds is provided, those are used instead of the defaults.
    """
    days = cert.days_until_expiry()
    if custom_thresholds is not None:
        thresholds = custom_thresholds
    else:
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


def evaluate_all_certs(
    db_path: str | Path, alert_repo: AlertRepository
) -> list[Alert]:
    """Evaluate thresholds for all leaf certificates in the database.

    Looks up per-host custom thresholds from the hosts table and passes them
    through to evaluate_thresholds.
    """
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import _connect, _parse_iso

    with _connect(db_path) as conn:
        host_thresholds: dict[tuple[str, int], int | None] = {}
        for row in conn.execute("SELECT hostname, port, threshold_days FROM hosts").fetchall():
            host_thresholds[(row["hostname"], row["port"])] = row["threshold_days"]

        leaves = conn.execute(
            "SELECT * FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    all_alerts: list[Alert] = []
    for leaf_row in leaves:
        cert = Certificate(
            subject=leaf_row["subject"],
            issuer=leaf_row["issuer"],
            not_before=_parse_iso(leaf_row["not_before"]),
            not_after=_parse_iso(leaf_row["not_after"]),
            san_dns_names=json.loads(leaf_row["san_dns_names"]),
            fingerprint_sha256=leaf_row["fingerprint_sha256"],
            raw_der=bytes(leaf_row["raw_der"]),
            is_leaf=True,
        )
        custom = None
        hostname = leaf_row["hostname"]
        port = leaf_row["port"]
        if hostname and port:
            host_td = host_thresholds.get((hostname, port))
            if host_td is not None:
                custom = (host_td, max(host_td // 2, 1), max(host_td // 4, 1))
        alerts = evaluate_thresholds(
            cert, alert_repo, cert_id=leaf_row["id"], custom_thresholds=custom
        )
        all_alerts.extend(alerts)
    return all_alerts


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


def _sanitize_smtp_error(msg: str, config: AlertConfig | None) -> str:
    """Strip SMTP credentials from error messages to avoid logging secrets.

    Only replaces passwords >= 4 chars to avoid false positives (e.g. 'p' in 'nope').
    """
    if config and config.smtp_password and len(config.smtp_password) >= 4:
        msg = msg.replace(config.smtp_password, "***")
    if config and config.smtp_user and len(config.smtp_user) >= 4:
        msg = msg.replace(config.smtp_user, "***")
    return msg


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
        alert.error_message = _sanitize_smtp_error(str(exc), config)
        return False


def send_webhook(alert: Alert, config: WebhookConfig | None) -> bool:
    """Send alert as JSON POST to a webhook URL. Returns True on success."""
    if config is None:
        return False
    payload = json.dumps({
        "alert_type": alert.alert_type,
        "cert_id": alert.cert_id,
        "message": alert.message,
        "threshold_days": alert.threshold_days,
        "status": alert.status,
    }).encode("utf-8")
    req = urllib.request.Request(
        config.url,
        data=payload,
        headers={"Content-Type": "application/json", **config.headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:  # noqa: BLE001
        alert.error_message = str(exc)
        return False


def process_pending(
    alert_repo: AlertRepository,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
) -> dict[str, int]:
    """See AC-04. No-ops when both configs are None. Tries webhook if SMTP fails or is absent."""
    if config is None and webhook_config is None:
        return {"sent": 0, "failed": 0}
    sent = 0
    failed = 0
    for alert in alert_repo.list_pending():
        delivered = False
        if config is not None:
            delivered = send_alert(alert, config)
        if not delivered and webhook_config is not None:
            delivered = send_webhook(alert, webhook_config)
        if delivered:
            alert.sent_at = datetime.now(UTC)
            alert_repo.mark_sent(alert.id)
            sent += 1
        else:
            alert_repo.mark_failed(alert.id, alert.error_message or "unknown")
            failed += 1
    return {"sent": sent, "failed": failed}
