"""API key repository (Plan 039 / BC-104).

Scoped bearer tokens for machine-to-machine access to the REST API. The raw
token is returned exactly once at creation; only its SHA-256 hash is stored, so
a database disclosure does not leak usable credentials.

Scopes map onto the Plan 035 RBAC roles:

- ``read``  → viewer  (cert:read)
- ``write`` → operator (cert:read, cert:write)
- ``admin`` → admin    (all permissions, incl. settings:admin)
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import _connect

VALID_SCOPES = ("read", "write", "admin")

# Raw tokens are prefixed so they are recognisable in logs/configs and so a
# bearer token can be told apart from other Authorization schemes at a glance.
_TOKEN_PREFIX = "cwk_"


@dataclass
class ApiKeyEntry:
    """A stored API key, without the raw token or its hash."""

    id: str
    name: str
    scope: str
    created_at: datetime
    last_used_at: datetime | None = None
    revoked: bool = False


@dataclass
class ApiKeyAuth:
    """Result of verifying a presented token."""

    id: str
    name: str
    scope: str


def hash_token(raw_token: str) -> str:
    """Return the hex SHA-256 of a raw token (what we store and look up by)."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    """Generate a new opaque raw token."""
    return _TOKEN_PREFIX + secrets.token_urlsafe(32)


class SqliteApiKeyRepository:
    """SQLite-backed API key store."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = db_path

    def create_key(self, name: str, scope: str) -> tuple[ApiKeyEntry, str]:
        """Create a key. Returns (stored entry, raw token shown once)."""
        if scope not in VALID_SCOPES:
            raise ValueError(f"scope must be one of {VALID_SCOPES}")
        if not name or not name.strip():
            raise ValueError("name is required")
        raw = generate_token()
        key_id = uuid.uuid4().hex
        created = datetime.now(UTC)
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO api_keys (id, key_hash, name, scope, created_at, revoked)"
                " VALUES (?, ?, ?, ?, ?, 0)",
                (key_id, hash_token(raw), name.strip(), scope, created.isoformat()),
            )
            conn.commit()
        entry = ApiKeyEntry(id=key_id, name=name.strip(), scope=scope, created_at=created)
        return entry, raw

    def verify_key(self, raw_token: str) -> ApiKeyAuth | None:
        """Return the auth result for a valid, non-revoked token, else None.

        Updates ``last_used_at`` as a side effect on success.
        """
        if not raw_token:
            return None
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, name, scope, revoked FROM api_keys WHERE key_hash = ?",
                (hash_token(raw_token),),
            ).fetchone()
            if row is None or row["revoked"]:
                return None
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), row["id"]),
            )
            conn.commit()
            return ApiKeyAuth(id=row["id"], name=row["name"], scope=row["scope"])

    def revoke_key(self, key_id: str) -> bool:
        """Mark a key revoked. Returns True if a row changed."""
        with _connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0",
                (key_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    def list_keys(self, *, include_revoked: bool = False) -> list[ApiKeyEntry]:
        """List keys (never exposes the hash or raw token)."""
        sql = (
            "SELECT id, name, scope, created_at, last_used_at, revoked"
            " FROM api_keys"
        )
        if not include_revoked:
            sql += " WHERE revoked = 0"
        sql += " ORDER BY created_at DESC"
        with _connect(self.db_path) as conn:
            rows = conn.execute(sql).fetchall()
        return [
            ApiKeyEntry(
                id=r["id"],
                name=r["name"],
                scope=r["scope"],
                created_at=datetime.fromisoformat(r["created_at"]),
                last_used_at=(
                    datetime.fromisoformat(r["last_used_at"]) if r["last_used_at"] else None
                ),
                revoked=bool(r["revoked"]),
            )
            for r in rows
        ]
