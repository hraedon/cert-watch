"""Email and webhook alerts. See spec wi_fr04_alerts.md."""

from __future__ import annotations

import json
import logging
import smtplib
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database import Alert, AlertRepository

logger = logging.getLogger("cert_watch.alerts")

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
    template: str = ""  # Jinja-style template; empty = default JSON


def evaluate_thresholds(
    cert: Certificate,
    alert_repo: AlertRepository,
    *,
    cert_id: str | None = None,
    custom_thresholds: tuple[int, ...] | None = None,
    cooldown_hours: int = 24,
    owner_info: dict | None = None,
) -> list[Alert]:
    """
    Create pending alerts for thresholds the cert has now crossed, skipping any
    threshold that already has an alert recorded for this cert. See AC-02.

    Escalation: if the most recent alert for a threshold is older than
    cooldown_hours and the cert still crosses that threshold, a new alert
    is created. This ensures persistent expiry issues get re-alerted while
    avoiding noise from repeated alerts within the cooldown window.

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
    now = datetime.now(UTC)

    # Find existing alerts for this cert and their thresholds.
    # Track the most recent alert time per threshold for cooldown logic.
    existing_thresholds: set[int] = set()
    latest_alert_by_threshold: dict[int, datetime] = {}
    cert_alerts = (
        alert_repo.list_for_cert(cid)
        if hasattr(alert_repo, "list_for_cert")
        else [a for a in alert_repo.list_pending() if a.cert_id == cid]
    )
    for a in cert_alerts:
        if a.threshold_days is not None:
            existing_thresholds.add(a.threshold_days)
            prev_latest = latest_alert_by_threshold.get(
                a.threshold_days, datetime.min.replace(tzinfo=UTC)
            )
            if a.created_at > prev_latest:
                latest_alert_by_threshold[a.threshold_days] = a.created_at

    created: list[Alert] = []
    for t in thresholds:
        # Suppress alerts when renewal is complete — certs renewed don't need
        # re-alerting until the next threshold window opens.
        if owner_info and owner_info.get("renewal_status") == "renewed":
            continue
        # Floor semantics: days_until_expiry() returns floor(delta), so a
        # cert with 1d23h remaining shows days=1 and crosses the t=1 threshold.
        # This means a threshold can fire up to ~23h before the nominal expiry
        # day; acceptable because thresholds are calendar-day aligned.
        if days <= t:
            # Check cooldown: skip if a recent alert exists for this threshold
            if t in existing_thresholds:
                last_alert_time = latest_alert_by_threshold.get(t)
                cooldown_secs = cooldown_hours * 3600
                if (
                    last_alert_time
                    and (now - last_alert_time).total_seconds() < cooldown_secs
                ):
                    continue
            alert = Alert(
                cert_id=cid,
                alert_type="expired" if days < 0 else "expiry_warning",
                status="pending",
                message=_format_message(cert, days, t, owner_info=owner_info),
                threshold_days=t,
                extra_recipients=(
                    [owner_info["owner_email"]]
                    if owner_info and owner_info.get("owner_email")
                    else []
                ),
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

    Looks up per-host custom thresholds and owner/contact info from the hosts
    table and passes them through to evaluate_thresholds.
    """
    from cert_watch.database import _connect, _parse_iso

    with _connect(db_path) as conn:
        host_thresholds: dict[tuple[str, int], int | None] = {}
        host_owners: dict[tuple[str, int], dict] = {}
        for row in conn.execute("SELECT * FROM hosts").fetchall():
            key = (row["hostname"], row["port"])
            host_thresholds[key] = row["threshold_days"]
            host_owners[key] = {
                "owner_name": dict(row).get("owner_name", ""),
                "owner_email": dict(row).get("owner_email", ""),
                "owner_slack": dict(row).get("owner_slack", ""),
                "renewal_status": dict(row).get("renewal_status", "pending"),
            }

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
        owner_info: dict | None = None
        if hostname and port:
            host_td = host_thresholds.get((hostname, port))
            if host_td is not None:
                custom = (host_td, max(host_td // 2, 1), max(host_td // 4, 1))
            owner_info = host_owners.get((hostname, port))
        alerts = evaluate_thresholds(
            cert, alert_repo, cert_id=leaf_row["id"], custom_thresholds=custom,
            owner_info=owner_info,
        )
        all_alerts.extend(alerts)
    return all_alerts


def _format_message(
    cert: Certificate, days: int, threshold: int, *, owner_info: dict | None = None
) -> str:
    """See AC-05."""
    action = (
        "Renew this certificate immediately."
        if days <= 7
        else "Plan a renewal soon."
    )
    msg = (
        f"Certificate '{cert.display_name}' "
        f"(subject: {cert.subject}) "
        f"expires on {cert.not_after.isoformat()} "
        f"({days} days remaining; threshold: <={threshold}d). "
        f"Recommended action: {action}"
    )
    if owner_info:
        parts = []
        if owner_info.get("owner_name"):
            parts.append(f"Owner: {owner_info['owner_name']}")
        if owner_info.get("owner_email"):
            parts.append(f"Contact: {owner_info['owner_email']}")
        if owner_info.get("owner_slack"):
            parts.append(f"Slack: {owner_info['owner_slack']}")
        if parts:
            msg += " " + "; ".join(parts)
    if owner_info and owner_info.get("renewal_status") == "in_progress":
        msg += " (renewal in progress)"
    return msg


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
    all_recipients = list(config.recipients) + [
        r for r in alert.extra_recipients if r not in config.recipients
    ]
    msg["To"] = ", ".join(all_recipients)
    msg.set_content(alert.message)
    try:
        if config.smtp_port == 465:
            s = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=15)
        else:
            s = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15)
        with s:
            if config.smtp_port != 465:
                try:
                    s.starttls()
                except smtplib.SMTPNotSupportedError:
                    alert.error_message = (
                        "STARTTLS not supported by SMTP server; "
                        "refusing to send credentials in cleartext"
                    )
                    return False
            if config.smtp_user:
                s.login(config.smtp_user, config.smtp_password)
            s.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 — AC-06 says do not raise
        alert.error_message = _sanitize_smtp_error(str(exc), config)
        return False


def send_webhook(alert: Alert, config: WebhookConfig | None) -> bool:
    """Send alert as JSON POST to a webhook URL. Returns True on success.

    If config.template is set, uses it as the payload with {{var}} substitution.
    Available variables: alert_type, cert_id, message, threshold_days, status.
    """
    if config is None:
        return False
    if config.template:
        payload = config.template
        for key in ("alert_type", "cert_id", "message", "threshold_days", "status"):
            value = str(getattr(alert, key, ""))
            payload = payload.replace("{{" + key + "}}", value)
        content_type = "text/plain"
        if payload.lstrip().startswith("{"):
            content_type = "application/json"
    else:
        payload_dict = {
            "alert_type": alert.alert_type,
            "cert_id": alert.cert_id,
            "message": alert.message,
            "threshold_days": alert.threshold_days,
            "status": alert.status,
        }
        if alert.extra_recipients:
            payload_dict["extra_recipients"] = alert.extra_recipients
        payload = json.dumps(payload_dict)
        content_type = "application/json"
    req = urllib.request.Request(
        config.url,
        data=payload.encode("utf-8"),
        headers={"Content-Type": content_type, **config.headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:  # noqa: BLE001
        alert.error_message = str(exc)
        return False


ALERT_MAX_RETRIES = 3
ALERT_RETRY_DELAY = 2  # seconds between retries


def send_expiry_digest(
    db_path: str | Path,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
) -> bool:
    """Send a single digest email summarizing all certificates expiring within 30 days.

    Returns True if the digest was delivered successfully.
    """
    from cert_watch.database import _connect, _parse_iso

    if config is None and webhook_config is None:
        return False

    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM certificates WHERE is_leaf = 1 ORDER BY not_after"
        ).fetchall()

    now = datetime.now(UTC)
    expiring: list[dict] = []
    for r in rows:
        na = _parse_iso(r["not_after"])
        days = (na - now).days
        if days <= 30:
            expiring.append({
                "subject": r["subject"],
                "hostname": r["hostname"] or "",
                "port": r["port"] or 443,
                "not_after": r["not_after"],
                "days_remaining": days,
            })

    if not expiring:
        return True  # nothing to report

    # Build digest message
    lines = [
        f"[cert-watch] Expiry Digest — {len(expiring)} certificate(s) expiring within 30 days",
        "",
    ]
    for cert in expiring:
        host = f"{cert['hostname']}:{cert['port']}" if cert["hostname"] else "(uploaded)"
        status = "EXPIRED" if cert["days_remaining"] < 0 else f"{cert['days_remaining']}d remaining"
        lines.append(f"  - {cert['subject']} ({host}) — {status} — expires {cert['not_after']}")

    message = "\n".join(lines)

    # Send via email
    if config is not None:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[cert-watch] Expiry Digest: {len(expiring)} cert(s) expiring soon"
            msg["From"] = config.from_addr
            msg["To"] = ", ".join(config.recipients)
            msg.set_content(message)
            if config.smtp_port == 465:
                s = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=15)
            else:
                s = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15)
            with s:
                if config.smtp_port != 465:
                    try:
                        s.starttls()
                    except smtplib.SMTPNotSupportedError:
                        logger.warning(
                            "digest email aborted: STARTTLS not supported by %s:%s; "
                            "refusing to send credentials in cleartext",
                            config.smtp_host, config.smtp_port,
                        )
                        return False
                if config.smtp_user:
                    s.login(config.smtp_user, config.smtp_password)
                s.send_message(msg)
            return True
        except Exception as exc:
            logger.warning("digest email failed: %s", _sanitize_smtp_error(str(exc), config))

    # Send via webhook
    if webhook_config is not None:
        import urllib.request as _urlreq

        payload = json.dumps({
            "alert_type": "expiry_digest",
            "cert_count": len(expiring),
            "message": message,
            "certificates": expiring,
        })
        req = _urlreq.Request(
            webhook_config.url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json", **webhook_config.headers},
            method="POST",
        )
        try:
            with _urlreq.urlopen(req, timeout=webhook_config.timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    return False


def process_pending(
    alert_repo: AlertRepository,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
) -> dict[str, int]:
    """See AC-04. No-ops when both configs are None. Tries webhook if SMTP fails or is absent.

    Failed deliveries are retried up to ALERT_MAX_RETRIES times with a short delay.
    """
    if config is None and webhook_config is None:
        return {"sent": 0, "failed": 0}
    sent = 0
    failed = 0
    for alert in alert_repo.list_pending():
        delivered = False
        last_error = ""
        for attempt in range(ALERT_MAX_RETRIES):
            if config is not None:
                delivered = send_alert(alert, config)
            if not delivered and webhook_config is not None:
                delivered = send_webhook(alert, webhook_config)
            if delivered:
                break
            last_error = alert.error_message or "unknown"
            if attempt < ALERT_MAX_RETRIES - 1:
                import time
                time.sleep(ALERT_RETRY_DELAY * (attempt + 1))
        if delivered:
            alert.sent_at = datetime.now(UTC)
            alert_repo.mark_sent(alert.id)
            sent += 1
        else:
            alert_repo.mark_failed(
                alert.id, f"{last_error} (after {ALERT_MAX_RETRIES} attempts)"
            )
            failed += 1
    return {"sent": sent, "failed": failed}
