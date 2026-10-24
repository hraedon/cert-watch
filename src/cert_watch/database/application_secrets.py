"""Read application credential metadata from the operator inventory."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from cert_watch.application_secrets import ApplicationSecret
from cert_watch.database.connection import _connect


def list_application_secrets(db_path: str | Path) -> list[ApplicationSecret]:
    rows = _connect(db_path).execute(
        """SELECT * FROM application_secrets
           ORDER BY retired_at IS NOT NULL, expires_at, application_name, id"""
    ).fetchall()
    return [
        ApplicationSecret(
            id=row["id"], application_name=row["application_name"],
            application_id=row["application_id"], credential_id=row["credential_id"],
            credential_name=row["credential_name"], tenant_id=row["tenant_id"],
            expires_at=datetime.fromisoformat(row["expires_at"]),
            owner_email=row["owner_email"], created_at=datetime.fromisoformat(row["created_at"]),
            retired_at=datetime.fromisoformat(row["retired_at"]) if row["retired_at"] else None,
        ) for row in rows
    ]
