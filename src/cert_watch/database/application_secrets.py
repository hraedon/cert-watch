"""Read application credential metadata from the operator inventory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cert_watch.application_secrets import ApplicationSecret
from cert_watch.database.connection import _connect


def _stored_instant(value: object) -> datetime | None:
    """Return a stored UTC instant, or None when the value cannot be one.

    The service writes timezone-aware ISO text. Anything else came from a hand
    edit or a restore and must not raise for the whole inventory.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def list_application_secrets(db_path: str | Path) -> list[ApplicationSecret]:
    rows = _connect(db_path).execute(
        """SELECT * FROM application_secrets
           ORDER BY retired_at IS NOT NULL, expires_at, application_name, id"""
    ).fetchall()
    secrets: list[ApplicationSecret] = []
    for row in rows:
        times: dict[str, datetime | None] = {}
        unreadable: list[str] = []
        for name in ("expires_at", "created_at", "retired_at"):
            value = row[name]
            times[name] = None if value is None else _stored_instant(value)
            if value is not None and times[name] is None:
                unreadable.append(name)
        secrets.append(ApplicationSecret(
            id=row["id"], application_name=row["application_name"],
            application_id=row["application_id"], credential_id=row["credential_id"],
            credential_name=row["credential_name"], tenant_id=row["tenant_id"],
            expires_at=times["expires_at"], owner_email=row["owner_email"],
            created_at=times["created_at"], retired_at=times["retired_at"],
            unreadable=tuple(unreadable),
        ))
    return secrets
