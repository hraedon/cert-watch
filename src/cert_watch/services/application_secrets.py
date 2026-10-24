"""Admin-owned credential metadata mutations with transactional audit."""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.alerting.model import WebhookConfig
from cert_watch.application_secrets import parse_metadata
from cert_watch.audit import export_audit, record_audit
from cert_watch.auth.scope import ScopeDeniedError, require_auth_context
from cert_watch.database.alert_store import AlertStore
from cert_watch.database.connection import _connect, get_write_lock


def require_secret_admin(auth: Any) -> None:
    principal = require_auth_context(auth)
    if not principal.is_admin:
        raise ScopeDeniedError("Application credential inventory requires administrator access.")


def create_application_secret(
    db_path: str | Path, data: Mapping[str, object], *, auth: Any,
    actor: str, source_ip: str | None = None,
) -> str:
    require_secret_admin(auth)
    metadata = parse_metadata(data)
    identifier = uuid.uuid4().hex
    with get_write_lock(), _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        require_secret_admin(auth)
        try:
            conn.execute(
                """INSERT INTO application_secrets
                   (id,application_name,application_id,credential_id,credential_name,
                    tenant_id,expires_at,owner_email,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (identifier, metadata.application_name, metadata.application_id,
                 metadata.credential_id, metadata.credential_name, metadata.tenant_id,
                 metadata.expires_at.isoformat(), metadata.owner_email,
                 datetime.now(UTC).isoformat()),
            )
        except sqlite3.IntegrityError:
            raise ValueError(
                "An active record already exists for this application credential."
            ) from None
        event = record_audit(
            db_path, actor=actor, action="application_secret.create",
            target_type="application_secret", target_id=identifier,
            source_ip=source_ip, conn=conn,
        )
        conn.commit()
    export_audit(event)
    return identifier


def retire_application_secret(
    db_path: str | Path, identifier: str, *, auth: Any,
    actor: str, source_ip: str | None = None, webhook_config: WebhookConfig | None = None,
) -> bool:
    require_secret_admin(auth)
    with get_write_lock(), _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        require_secret_admin(auth)
        changed = conn.execute(
            "UPDATE application_secrets SET retired_at=? WHERE id=? AND retired_at IS NULL",
            (datetime.now(UTC).isoformat(), identifier),
        ).rowcount
        if not changed:
            return False
        # Cancel queued notifications before any manual flush can claim them.
        keys = {str(row[0]) for row in conn.execute(
            "SELECT dedupe_key FROM alerts WHERE cert_id=? AND closed_at IS NULL",
            (f"application-secret:{identifier}",),
        )}
        closed_sent = AlertStore(db_path, initialize=False).close_keys(
            keys, conn=conn, reason="application credential retired",
        )
        event = record_audit(
            db_path, actor=actor, action="application_secret.retire",
            target_type="application_secret", target_id=identifier,
            source_ip=source_ip, conn=conn,
        )
        conn.commit()
    export_audit(event)
    if closed_sent:
        from cert_watch.alerting.resolve import resolve_webhook_for_renewed_cert

        resolve_webhook_for_renewed_cert(
            db_path, "", webhook_config, pending_alerts=closed_sent,
        )
    return True
