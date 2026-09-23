"""Expiry digest target selection and rendering."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from cert_watch.alerting.digest.engine import DigestTarget
from cert_watch.alerting.model import AlertConfig, OutboundMessage
from cert_watch.alerting.transports.smtp import _validate_email
from cert_watch.database import _connect, _parse_iso

logger = logging.getLogger("cert_watch.alerting.digest")


def _build_digest_message(
    certs: list[dict[str, Any]],
    *,
    owner_name: str | None = None,
    cadence_days: int = 30,
) -> tuple[str, str]:
    lines = [
        f"[cert-watch] Expiry Digest — {len(certs)} certificate(s) "
        f"expiring within {cadence_days} days",
        "",
    ]
    if owner_name:
        lines.insert(
            1,
            "You are receiving this digest as the owner of the following certificates.",
        )
        lines.insert(2, "")
    for cert in certs:
        host = (
            f"{cert['hostname']}:{cert['port']}" if cert["hostname"] else "(uploaded)"
        )
        status = (
            "EXPIRED"
            if cert["days_remaining"] < 0
            else f"{cert['days_remaining']}d remaining"
        )
        lines.append(
            f"  - {cert['subject']} ({host}) — {status} — expires {cert['not_after']}"
        )
    message = "\n".join(lines)
    subject = f"[cert-watch] Expiry Digest: {len(certs)} cert(s) expiring soon"
    return message, subject


@dataclass(frozen=True)
class _ExpiryPayload:
    certs: list[dict[str, Any]]
    cadence_days: int
    owner_name: str | None = None


@dataclass(frozen=True)
class ExpiryDigestKind:
    """One global expiry digest plus owner-scoped SMTP copies."""

    alert_config: AlertConfig | None
    name: str = "expiry"
    webhook_fanout: Literal["global"] = "global"

    def targets(
        self,
        db_path: str | Path,
        now: datetime,
        cadence_days: int,
    ) -> list[DigestTarget]:
        with _connect(db_path) as conn:
            rows = conn.execute(
                "SELECT c.id, c.subject, c.hostname, c.port, c.not_after, "
                "h.owner_email, h.owner_name "
                "FROM certificates c "
                "LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port "
                "WHERE c.is_leaf = 1 ORDER BY c.not_after"
            ).fetchall()

        expiring: list[dict[str, Any]] = []
        for row in rows:
            not_after = _parse_iso(row["not_after"])
            days = (not_after - now).days
            if days <= cadence_days:
                expiring.append({
                    "subject": row["subject"],
                    "hostname": row["hostname"] or "",
                    "port": row["port"] or 443,
                    "not_after": row["not_after"],
                    "days_remaining": days,
                    "owner_email": dict(row).get("owner_email") or "",
                    "owner_name": dict(row).get("owner_name") or "",
                })
        if not expiring:
            return []

        global_recipients = _valid_recipients(
            self.alert_config.recipients if self.alert_config is not None else []
        )
        global_recipient_keys = {recipient.casefold() for recipient in global_recipients}
        targets = [
            DigestTarget(
                key="global",
                payload=_ExpiryPayload(expiring, cadence_days),
                smtp_recipients=tuple(global_recipients),
                is_global=True,
            )
        ]

        original_emails: dict[str, str] = {}
        owner_names: dict[str, str] = {}
        owner_certs: dict[str, list[dict[str, Any]]] = {}
        for cert in expiring:
            owner = cert["owner_email"]
            if not owner:
                continue
            if not _validate_email(owner):
                logger.warning("skipping invalid owner_email digest: %r", owner)
                continue
            key = owner.casefold()
            original_emails.setdefault(key, owner)
            if cert["owner_name"]:
                owner_names.setdefault(key, cert["owner_name"])
            if key not in global_recipient_keys:
                owner_certs.setdefault(key, []).append(cert)

        targets.extend(
            DigestTarget(
                key=owner,
                payload=_ExpiryPayload(
                    certs,
                    cadence_days,
                    owner_name=owner_names.get(owner),
                ),
                smtp_recipients=(original_emails[owner],),
                webhook_eligible=False,
            )
            for owner, certs in owner_certs.items()
        )
        return targets

    def render(self, target: DigestTarget) -> OutboundMessage:
        payload = target.payload
        if not isinstance(payload, _ExpiryPayload):
            raise TypeError("expiry target has the wrong payload")
        body, subject = _build_digest_message(
            payload.certs,
            owner_name=payload.owner_name,
            cadence_days=payload.cadence_days,
        )
        return OutboundMessage.from_digest(
            subject=subject,
            body=body,
            severity="expiry_digest",
            idempotency_key="",
            recipients=target.smtp_recipients,
        )


def _valid_recipients(recipients: list[str]) -> list[str]:
    seen: set[str] = set()
    valid: list[str] = []
    for recipient in recipients:
        key = recipient.casefold()
        if _validate_email(recipient) and key not in seen:
            seen.add(key)
            valid.append(recipient)
    return valid
