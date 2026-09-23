"""Orphan notice: admins learn which certificates route to nobody specific."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from cert_watch.alerting.digest.engine import DigestTarget
from cert_watch.alerting.model import AlertConfig, OutboundMessage
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


@dataclass(frozen=True)
class OrphanDigestKind:
    """One claimed weekly SMTP notice to every local admin."""

    alert_config: AlertConfig | None
    name: str = "orphan"
    webhook_fanout: Literal["global"] = "global"

    def targets(
        self,
        db_path: str | Path,
        now: datetime,
        cadence_days: int,
    ) -> list[DigestTarget]:
        del now, cadence_days
        if not isinstance(self.alert_config, AlertConfig):
            return []
        orphans = find_orphan_certs(db_path)
        admins = [address for address in _admin_emails(db_path) if _validate_email(address)]
        if not orphans or not admins:
            return []
        return [
            DigestTarget(
                key="global",
                payload=orphans,
                smtp_recipients=tuple(admins),
                is_global=True,
                webhook_eligible=False,
            )
        ]

    def render(self, target: DigestTarget) -> OutboundMessage:
        orphans = target.payload
        if not isinstance(orphans, list):
            raise TypeError("orphan target has the wrong payload")
        return OutboundMessage.from_digest(
            subject=(
                f"[cert-watch] {len(orphans)} orphaned certificate(s) — "
                "no alert routing"
            ),
            body=_build_orphan_message(orphans),
            severity="orphan_digest",
            idempotency_key="",
            recipients=target.smtp_recipients,
        )
