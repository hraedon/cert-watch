"""Orphan notice: admins learn which certificates route to nobody specific."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

from cert_watch.alerting.digest.engine import _send_claimed_digest_smtp
from cert_watch.alerting.model import AlertConfig
from cert_watch.alerting.routing import find_orphan_certs
from cert_watch.alerting.transports.smtp import _validate_email

logger = logging.getLogger("cert_watch.digest")


def _admin_emails(db_path: str | Path) -> list[str]:
    """Emails of users whose role is permission_tier == 'admin' (deduped, order
    preserved). Empty if local auth / roles are unavailable.
    """
    try:
        from cert_watch.database.users_roles import (
            SqliteRoleRepository,
            SqliteUserRepository,
        )

        admin_role_ids = {
            r.id
            for r in SqliteRoleRepository(db_path).list_all()
            if (r.permission_tier or "viewer") == "admin"
        }
        seen: set[str] = set()
        emails: list[str] = []
        for u in SqliteUserRepository(db_path).list_all():
            if u.role_id in admin_role_ids and u.email and u.email.casefold() not in seen:
                seen.add(u.email.casefold())
                emails.append(u.email)
        return emails
    except (ImportError, sqlite3.Error):  # roles table missing or local-auth extra absent
        logger.warning("admin email lookup unavailable", exc_info=True)
        return []


def _build_orphan_message(orphans: list[dict[str, Any]]) -> str:
    lines = [
        f"[cert-watch] Orphaned certificates — no alert routing ({len(orphans)})",
        "",
        "These certificates match no alert group and have no host owner, so they",
        "route to no specific recipient — they fall back to the global recipient",
        "list and are the ones most likely to be silently missed. Assign a tag /",
        "alert group or a host owner to route them deliberately.",
        "",
    ]
    for o in orphans:
        host = o.get("hostname") or "?"
        port = o.get("port")
        where = f"{host}:{port}" if port else host
        lines.append(f"  - [orphan] {where} — {o.get('subject') or '(no subject)'}")
    return "\n".join(lines)


def send_orphan_notice(db_path: str | Path, alert_config: AlertConfig | None) -> bool | None:
    """Email admin-tier users a flagged list of orphaned certs (no alert routing).

    Part of the weekly digest run (Plan 050, decision pinned 2026-06-20): admins
    get standing visibility into certs that resolve to nobody specific, even in a
    week with no renewal activity. Returns ``None`` when there is nothing to send
    (no orphans, no admin recipients, or no SMTP config), ``True`` on delivery,
    ``False`` on SMTP failure. Successful per-admin deliveries are durably
    recorded so overlapping/repeated weekly runs do not resend them.
    """
    from email.message import EmailMessage

    if not isinstance(alert_config, AlertConfig):
        return None
    orphans = find_orphan_certs(db_path)
    if not orphans:
        return None
    admins = [a for a in _admin_emails(db_path) if _validate_email(a)]
    if not admins:
        return None

    from cert_watch.database.digest_deliveries import digest_period_key

    digest_key = digest_period_key("orphan", 7)

    def _build_message(recipients: list[str]) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = (
            f"[cert-watch] {len(orphans)} orphaned certificate(s) — no alert routing"
        )
        msg["From"] = alert_config.from_addr
        msg["To"] = ", ".join(recipients)
        msg.set_content(_build_orphan_message(orphans))
        return msg

    outcomes, busy = _send_claimed_digest_smtp(
        db_path,
        digest_key,
        admins,
        alert_config,
        _build_message,
        failure_label="orphan notice delivery",
    )
    return bool(outcomes) and all(outcomes.values()) and not busy
