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
from cert_watch.security import SecurityContext

VALID_SCOPES = ("read", "write", "admin")

# Raw tokens are prefixed so they are recognisable in logs/configs and so a
# bearer token can be told apart from other Authorization schemes at a glance.
_TOKEN_PREFIX = "cwk_"

# Prefix for peppered HMAC hashes (new format).
_HMAC_PREFIX = "hmac:"

# The pepper used by releases before API-key hashing was wired to the
# application SecurityContext. It remains a verification-only fallback so
# existing keys can be upgraded on use.
_LEGACY_DEFAULT_PEPPER = b"cert-watch-default-pepper"


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
    """Return the pre-SecurityContext pepper for compatibility/test use.

    Standalone repository users retain the historical environment/default
    behaviour. Production request paths inject a SecurityContext instead.
    """
    value = os.environ.get("CERT_WATCH_AUTH_SECRET")
    return value.encode() if value is not None else _LEGACY_DEFAULT_PEPPER


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


def generate_token() -> str:
    """Generate a new opaque raw token."""
    return _TOKEN_PREFIX + secrets.token_urlsafe(32)


class SqliteApiKeyRepository:
    """SQLite-backed API key store."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        security: SecurityContext | None = None,
    ) -> None:
        self.db_path = db_path
        # Request paths inject the immutable application signing material.
        # The old resolver remains the standalone/test default.
        self._pepper = (
            security.signing_key.encode("utf-8") if security is not None else _get_pepper()
        )

    def _candidate_hashes(self, raw_token: str) -> list[str]:
        """Return current and legacy hashes, ordered by preference."""
        peppers = (self._pepper, _get_pepper(), _LEGACY_DEFAULT_PEPPER)
        candidates: list[str] = []
        for pepper in peppers:
            candidate = hash_token(raw_token, pepper=pepper)
            if candidate not in candidates:
                candidates.append(candidate)
        candidates.append(_hash_token_legacy(raw_token))
        return candidates

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
                (
                    key_id,
                    hash_token(raw, pepper=self._pepper),
                    name.strip(),
                    scope,
                    created.isoformat(),
                ),
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
        candidates = self._candidate_hashes(raw_token)
        new_hash = candidates[0]
        placeholders = ", ".join("?" for _ in candidates)
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, name, scope, key_hash, revoked FROM api_keys"
                f" WHERE key_hash IN ({placeholders})",
                candidates,
            ).fetchall()
            rows_by_hash = {row["key_hash"]: row for row in rows}
            row = next(
                (rows_by_hash[candidate] for candidate in candidates if candidate in rows_by_hash),
                None,
            )
            if row is None or row["revoked"]:
                return None
            now_iso = datetime.now(UTC).isoformat()
            updates = ["last_used_at = ?"]
            params: list[str] = [now_iso]
            if row["key_hash"] != new_hash:
                updates.append("key_hash = ?")
                params.append(new_hash)
            params.append(row["id"])
            conn.execute(
                f"UPDATE api_keys SET {', '.join(updates)} WHERE id = ?",
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
