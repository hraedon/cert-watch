"""API key repository (Plan 039 / BC-104).

Scoped bearer tokens for machine-to-machine access to the REST API. The raw
token is returned exactly once at creation; only its hash is stored, so
a database disclosure does not leak usable credentials.

Keys are hashed with HMAC-SHA256 using a server-side pepper (derived from
the app signing key).  This is the appropriate choice for high-entropy
API keys (32 random bytes): the pepper makes a DB-only leak unexploitable
without simultaneous access to the signing key.  Legacy raw SHA-256 hashes
(64-char hex, no prefix) are still verified on lookup and transparently
upgraded to peppered HMAC on next use.

Scopes map onto the Plan 035 RBAC roles:

- ``read``  → viewer  (cert:read)
- ``write`` → operator (cert:read, cert:write)
- ``admin`` → admin    (all permissions, incl. settings:admin)
"""

from __future__ import annotations

import hashlib
import hmac
import os
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

# Prefix for peppered HMAC hashes (new format).
_HMAC_PREFIX = "hmac:"

# Length of legacy SHA-256 hex hashes (64 chars, no prefix).
_LEGACY_HASH_LEN = 64


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


def _get_pepper() -> bytes:
    """Return the pepper for API key hashing.

    Falls back to a static pepper when no signing key is available
    (e.g. during tests without a SecurityContext).
    """
    return os.environ.get(
        "CERT_WATCH_AUTH_SECRET", "cert-watch-default-pepper"
    ).encode()


def hash_token(raw_token: str, *, pepper: bytes | None = None) -> str:
    """Return the peppered HMAC-SHA256 of a raw token (what we store and look up by).

    Uses HMAC-SHA256 with a server-side pepper so a DB-only leak cannot
    be brute-forced without simultaneous access to the signing key.
    The stored format is ``hmac:<hex>``.
    """
    if pepper is None:
        pepper = _get_pepper()
    mac = hmac.new(pepper, raw_token.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{_HMAC_PREFIX}{mac}"


def _hash_token_legacy(raw_token: str) -> str:
    """Legacy SHA-256 hash (for backward compatibility with existing stored keys)."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _verify_token(raw_token: str, stored_hash: str, *, pepper: bytes | None = None) -> bool:
    """Verify a raw token against a stored hash (HMAC or legacy SHA-256)."""
    if stored_hash.startswith(_HMAC_PREFIX):
        expected = stored_hash[len(_HMAC_PREFIX):]
        if pepper is None:
            pepper = _get_pepper()
        computed = hmac.new(
            pepper, raw_token.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(computed, expected)
    if len(stored_hash) == _LEGACY_HASH_LEN and not stored_hash.startswith(_HMAC_PREFIX):
        legacy = _hash_token_legacy(raw_token)
        return hmac.compare_digest(legacy, stored_hash)
    return False


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

        Updates ``last_used_at`` as a side effect on success.  Transparently
        upgrades legacy SHA-256 hashes to peppered HMAC on successful
        verification.
        """
        if not raw_token:
            return None
        new_hash = hash_token(raw_token)
        legacy_hash = _hash_token_legacy(raw_token)
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, name, scope, key_hash, revoked FROM api_keys"
                " WHERE key_hash = ? OR key_hash = ?",
                (new_hash, legacy_hash),
            ).fetchone()
            if row is None or row["revoked"]:
                return None
            if not _verify_token(raw_token, row["key_hash"]):
                return None
            now_iso = datetime.now(UTC).isoformat()
            updates = ["last_used_at = ?"]
            params: list[str] = [now_iso]
            if not row["key_hash"].startswith(_HMAC_PREFIX):
                updates.append("key_hash = ?")
                params.append(new_hash)
            params.append(row["id"])
            conn.execute(
                f"UPDATE api_keys SET {' AND '.join(updates)} WHERE id = ?",
                params,
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
