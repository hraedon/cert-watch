"""Expiry digest: certificates expiring within the cadence window."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from cert_watch.alerting.digest.engine import _send_claimed_digest_smtp
from cert_watch.alerting.model import (
    ALERT_MAX_RETRIES,
    ALERT_RETRY_DELAY,
    AlertConfig,
    OutboundMessage,
    WebhookConfig,
)
from cert_watch.alerting.transports.smtp import (
    _open_smtp_connection,
    _sanitize_smtp_error,
    _validate_email,
)
from cert_watch.alerting.transports.webhook import send_webhook
from cert_watch.retry import backoff_range

logger = logging.getLogger("cert_watch.alerts")


def _build_digest_message(
    certs: list[dict[str, Any]], *, owner_name: str | None = None
) -> tuple[str, str]:
    lines = [
        f"[cert-watch] Expiry Digest — {len(certs)} certificate(s) expiring within 30 days",
        "",
    ]
    if owner_name:
        lines.insert(1, "You are receiving this digest as the owner of the following certificates.")
        lines.insert(2, "")
    for cert in certs:
        host = f"{cert['hostname']}:{cert['port']}" if cert["hostname"] else "(uploaded)"
        status = "EXPIRED" if cert["days_remaining"] < 0 else f"{cert['days_remaining']}d remaining"
        lines.append(f"  - {cert['subject']} ({host}) — {status} — expires {cert['not_after']}")
    message = "\n".join(lines)
    subject = f"[cert-watch] Expiry Digest: {len(certs)} cert(s) expiring soon"
    return message, subject


def _build_digest_email(
    certs: list[dict[str, Any]],
    recipients: list[str],
    from_addr: str,
    *,
    owner_name: str | None = None,
) -> EmailMessage:
    message, subject = _build_digest_message(certs, owner_name=owner_name)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg.set_content(message)
    return msg


def _send_digest_smtp(
    certs: list[dict[str, Any]],
    recipients: list[str],
    config: AlertConfig,
    *,
    owner_name: str | None = None,
    _conn: smtplib.SMTP | smtplib.SMTP_SSL | None = None,
) -> bool:
    msg = _build_digest_email(certs, recipients, config.from_addr, owner_name=owner_name)
    if _conn is not None:
        try:
            refused = _conn.send_message(msg)
            return not refused
        except Exception as exc:  # noqa: BLE001 — SMTP send, external service, AC-06
            logger.warning("digest email failed: %s", _sanitize_smtp_error(str(exc), config))
            return False
    for _ in backoff_range(ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"):
        try:
            conn = _open_smtp_connection(config)
            if conn is None:
                continue
            try:
                refused = conn.send_message(msg)
                if not refused:
                    return True
            finally:
                with contextlib.suppress(Exception):
                    conn.quit()
        except Exception as exc:  # noqa: BLE001 — SMTP retry loop, external service
            logger.warning("digest email failed: %s", _sanitize_smtp_error(str(exc), config))
    return False


def _send_digest_webhook(
    certs: list[dict[str, Any]],
    webhook_config: WebhookConfig,
    *,
    idempotency_key: str,
) -> bool:
    """Dispatch expiry digest through the adapter registry.

    Creates a transport message so every adapter formats the digest correctly.
    """
    message, subject = _build_digest_message(certs)
    msg = OutboundMessage.from_digest(
        subject=subject,
        body=message,
        severity="expiry_digest",
        idempotency_key=idempotency_key,
    )
    return bool(send_webhook(msg, webhook_config))


def send_expiry_digest(
    db_path: str | Path,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
    *,
    cadence_days: int = 30,
) -> bool:
    """Send expiry digest: one per owner (their certs only) + one global (all certs).

    Owners identified via host owner_email. If an owner is also in config.recipients
    they receive only the global digest (no duplicate). Returns True only when all
    deliveries succeeded; False on total or partial failure.
    """
    from cert_watch.database import _connect, _parse_iso
    from cert_watch.database.digest_deliveries import (
        claim_digest_delivery,
        complete_digest_delivery,
        digest_period_key,
        renew_digest_delivery,
    )

    if config is None and webhook_config is None:
        return False

    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT c.id, c.subject, c.hostname, c.port, c.not_after, "
            "h.owner_email, h.owner_name "
            "FROM certificates c "
            "LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port "
            "WHERE c.is_leaf = 1 ORDER BY c.not_after"
        ).fetchall()

    now = datetime.now(UTC)
    digest_key = digest_period_key("expiry", cadence_days, now=now)
    expiring: list[dict[str, Any]] = []
    for r in rows:
        na = _parse_iso(r["not_after"])
        days = (na - now).days
        if days <= cadence_days:
            expiring.append({
                "subject": r["subject"],
                "hostname": r["hostname"] or "",
                "port": r["port"] or 443,
                "not_after": r["not_after"],
                "days_remaining": days,
                "owner_email": dict(r).get("owner_email") or "",
                "owner_name": dict(r).get("owner_name") or "",
            })

    if not expiring:
        return True

    global_recipients_cf: set[str] = set()
    global_recipients_original: list[str] = []
    if config is not None:
        seen: set[str] = set()
        for r in config.recipients:
            if not _validate_email(r):
                continue
            cf = r.casefold()
            if cf not in seen:
                seen.add(cf)
                global_recipients_original.append(r)
        global_recipients_cf = seen

    original_emails: dict[str, str] = {}
    owner_names: dict[str, str] = {}
    for cert in expiring:
        oe = cert["owner_email"]
        if oe:
            if not _validate_email(oe):
                logger.warning("skipping invalid owner_email digest: %r", oe)
                continue
            cf = oe.casefold()
            original_emails.setdefault(cf, oe)
            on = cert.get("owner_name", "")
            if on and cf not in owner_names:
                owner_names[cf] = on

    owner_certs: dict[str, list[dict[str, Any]]] = {}
    for cert in expiring:
        oe = cert["owner_email"]
        cf = oe.casefold() if oe else ""
        if cf and cf in original_emails and cf not in global_recipients_cf:
            owner_certs.setdefault(cf, []).append(cert)

    any_smtp_success = False
    any_smtp_failure = False
    smtp_busy = False

    if config is not None:
        if global_recipients_original:
            outcomes, busy = _send_claimed_digest_smtp(
                db_path,
                digest_key,
                global_recipients_original,
                config,
                lambda recipients: _build_digest_email(
                    expiring, recipients, config.from_addr
                ),
                failure_label="global expiry digest",
            )
            smtp_busy |= busy
            any_smtp_success |= any(outcomes.values())
            any_smtp_failure |= any(not delivered for delivered in outcomes.values())

        for cf_email, certs in owner_certs.items():
            original = original_emails.get(cf_email, cf_email)

            def _build_owner_email(
                recipients: list[str],
                current_certs: list[dict[str, Any]] = certs,
                owner_email: str = cf_email,
            ) -> EmailMessage:
                return _build_digest_email(
                    current_certs,
                    recipients,
                    config.from_addr,
                    owner_name=owner_names.get(owner_email),
                )

            outcomes, busy = _send_claimed_digest_smtp(
                db_path,
                digest_key,
                [original],
                config,
                _build_owner_email,
                failure_label=f"owner expiry digest for {original}",
            )
            smtp_busy |= busy
            any_smtp_success |= any(outcomes.values())
            any_smtp_failure |= any(not delivered for delivered in outcomes.values())

        any_smtp_failure |= smtp_busy

    if any_smtp_success and not any_smtp_failure:
        return True

    if smtp_busy:
        return False

    if webhook_config is not None:
        endpoint = (
            webhook_config.routing_key
            if webhook_config.kind == "pagerduty"
            else webhook_config.url
        )
        endpoint_hash = hashlib.sha256(endpoint.encode()).hexdigest()[:16]
        channel = f"webhook:{webhook_config.kind}:{endpoint_hash}"
        claim = claim_digest_delivery(db_path, digest_key, channel, "global")
        if claim.state == "sent":
            return True
        if not claim.acquired:
            return False
        if not renew_digest_delivery(db_path, claim):
            return False
        delivered = _send_digest_webhook(
            expiring,
            webhook_config,
            idempotency_key=claim.idempotency_key,
        )
        complete_digest_delivery(db_path, claim, succeeded=delivered)
        return delivered

    return False
