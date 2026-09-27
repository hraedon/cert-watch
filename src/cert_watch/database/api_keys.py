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
- ``renewal-report`` → report submission/readback only (no RBAC permissions)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from cert_watch.database.connection import _connect
from cert_watch.security import SecurityContext
from cert_watch.tags import format_tags, parse_tags

logger = logging.getLogger("cert_watch.database.api_keys")

VALID_SCOPES = ("read", "write", "admin", "renewal-report")
VALID_BINDINGS = ("all", "tags")
RENEWAL_REPORT_SCOPE = "renewal-report"

# Raw tokens are prefixed so they are recognisable in logs/configs and so a
# bearer token can be told apart from other Authorization schemes at a glance.
_TOKEN_PREFIX = "cwk_"

# Prefix for peppered HMAC hashes (new format).
_HMAC_PREFIX = "hmac:"

# Deliberately unknown to the 1.1.x verifier. A downgraded binary therefore
# cannot reinterpret a renewal-report key as a more powerful legacy scope.
_RENEWAL_REPORT_HMAC_PREFIX = "rr-hmac:"

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
    binding: str
    bound_tags: tuple[str, ...]
    created_at: datetime
    last_used_at: datetime | None = None
    revoked: bool = False


@dataclass
class ApiKeyAuth:
    """Result of verifying a presented token."""

    id: str
    name: str
    scope: str
    binding: str
    bound_tags: tuple[str, ...]


@lru_cache(maxsize=16)
def _pepper_from_env_source(source: str, raw_source: str) -> bytes:
    """Resolve each stable auth-secret env source once per process."""
    del source, raw_source  # cache key; Settings owns parsing and validation
    from cert_watch.config import Settings

    return Settings.from_env().auth_secret.encode()


def _get_pepper() -> bytes:
    """Return the pre-SecurityContext pepper for compatibility/test use.

    Standalone repository users retain the historical environment/default
    behaviour. Production request paths inject a SecurityContext instead.
    """
    from cert_watch.config import setting_env_source

    source = setting_env_source("auth_secret")
    if source is None:
        return _LEGACY_DEFAULT_PEPPER
    return _pepper_from_env_source(source, os.environ[source])


def hash_token(
    raw_token: str, *, pepper: bytes | None = None, prefix: str = _HMAC_PREFIX
) -> str:
    """Return the peppered HMAC-SHA256 of a raw token (what we store and look up by).

    Uses HMAC-SHA256 with a server-side pepper so a DB-only leak cannot
    be brute-forced without simultaneous access to the signing key.
    The stored format is ``hmac:<hex>``.
    """
    if pepper is None:
        pepper = _get_pepper()
    mac = hmac.new(pepper, raw_token.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{prefix}{mac}"


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
            report_candidate = hash_token(
                raw_token, pepper=pepper, prefix=_RENEWAL_REPORT_HMAC_PREFIX
            )
            if report_candidate not in candidates:
                candidates.append(report_candidate)
        candidates.append(_hash_token_legacy(raw_token))
        return candidates

    def _renewal_report_candidate_hashes(self, raw_token: str) -> list[str]:
        """Return only hashes from the downgrade-safe report-key family."""
        peppers = (self._pepper, _get_pepper(), _LEGACY_DEFAULT_PEPPER)
        candidates: list[str] = []
        for pepper in peppers:
            candidate = hash_token(
                raw_token, pepper=pepper, prefix=_RENEWAL_REPORT_HMAC_PREFIX
            )
            if candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def create_key(
        self,
        name: str,
        scope: str,
        *,
        binding: str | None = None,
        bound_tags: str | None = None,
    ) -> tuple[ApiKeyEntry, str]:
        """Create a key. Returns (stored entry, raw token shown once)."""
        if scope not in VALID_SCOPES:
            raise ValueError(f"scope must be one of {VALID_SCOPES}")
        if not name or not name.strip():
            raise ValueError("name is required")
        tags = parse_tags(bound_tags)
        if scope == RENEWAL_REPORT_SCOPE:
            if binding not in VALID_BINDINGS:
                raise ValueError("renewal-report keys require an explicit binding")
            if binding == "tags" and not tags:
                raise ValueError("tag-bound renewal-report keys require at least one tag")
            if binding == "all" and tags:
                raise ValueError("all-bound renewal-report keys cannot include tags")
        else:
            if binding not in (None, "", "all") or tags:
                raise ValueError(f"{scope} keys must use binding='all'")
            binding = "all"
            tags = []
        normalized_tags = format_tags(tags)
        raw = generate_token()
        key_id = uuid.uuid4().hex
        created = datetime.now(UTC)
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO api_keys "
                "(id, key_hash, name, scope, binding, bound_tags, created_at, revoked)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    key_id,
                    hash_token(
                        raw,
                        pepper=self._pepper,
                        prefix=(
                            _RENEWAL_REPORT_HMAC_PREFIX
                            if scope == RENEWAL_REPORT_SCOPE
                            else _HMAC_PREFIX
                        ),
                    ),
                    name.strip(),
                    scope,
                    binding,
                    normalized_tags,
                    created.isoformat(),
                ),
            )
            conn.commit()
        entry = ApiKeyEntry(
            id=key_id,
            name=name.strip(),
            scope=scope,
            binding=binding,
            bound_tags=tuple(tags),
            created_at=created,
        )
        return entry, raw

    def verify_key(
        self, raw_token: str, *, renewal_report_only: bool = False
    ) -> ApiKeyAuth | None:
        """Return the auth result for a valid, non-revoked token, else None.

        Updates ``last_used_at`` as a side effect on success.  Transparently
        upgrades legacy SHA-256 hashes to peppered HMAC on successful
        verification.
        """
        if not raw_token:
            return None
        candidates = (
            self._renewal_report_candidate_hashes(raw_token)
            if renewal_report_only
            else self._candidate_hashes(raw_token)
        )
        new_hash = hash_token(raw_token, pepper=self._pepper)
        new_report_hash = hash_token(
            raw_token,
            pepper=self._pepper,
            prefix=_RENEWAL_REPORT_HMAC_PREFIX,
        )
        placeholders = ", ".join("?" for _ in candidates)
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, name, scope, binding, bound_tags, key_hash, revoked FROM api_keys"
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
            if renewal_report_only and row["scope"] != RENEWAL_REPORT_SCOPE:
                return None
            tags = tuple(parse_tags(row["bound_tags"]))
            auth = ApiKeyAuth(
                id=row["id"], name=row["name"], scope=row["scope"],
                binding=row["binding"], bound_tags=tags,
            )
            # A corrupt scope is still returned so the authentication boundary
            # can log and reject the specific key, but it must not look used or
            # receive a hash upgrade for a request that authorization refuses.
            if row["scope"] not in VALID_SCOPES:
                return auth
            if row["scope"] == RENEWAL_REPORT_SCOPE:
                if not row["key_hash"].startswith(_RENEWAL_REPORT_HMAC_PREFIX):
                    return None
                if row["binding"] not in VALID_BINDINGS:
                    return None
                if row["binding"] == "tags" and not tags:
                    return None
                if row["binding"] == "all" and tags:
                    return None
            elif (
                row["key_hash"].startswith(_RENEWAL_REPORT_HMAC_PREFIX)
                or row["binding"] != "all"
                or tags
            ):
                return None
            now_iso = datetime.now(UTC).isoformat()
            updates = ["last_used_at = ?"]
            params: list[str] = [now_iso]
            desired_hash = (
                new_report_hash
                if row["scope"] == RENEWAL_REPORT_SCOPE
                else new_hash
            )
            if row["key_hash"] != desired_hash:
                # Verified under a non-current hash: either an earlier pepper or
                # the pre-pepper unkeyed SHA-256. Surface it so an operator can
                # see which keys still trail the current signing material — the
                # legacy candidates offer no DB-leak protection, so a straggler
                # here is worth rotating.
                legacy_kind = (
                    "an earlier pepper"
                    if row["key_hash"].startswith(
                        (_HMAC_PREFIX, _RENEWAL_REPORT_HMAC_PREFIX)
                    )
                    else "an unkeyed SHA-256 hash"
                )
                logger.warning(
                    "API key %s (scope=%s) verified under %s; upgrading to the "
                    "current signing pepper. Rotate the key if the earlier "
                    "material is considered exposed.",
                    row["id"],
                    row["scope"],
                    legacy_kind,
                )
                updates.append("key_hash = ?")
                params.append(desired_hash)
            params.append(row["id"])
            conn.execute(
                f"UPDATE api_keys SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            conn.commit()
            return auth

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
            "SELECT id, name, scope, binding, bound_tags, created_at, last_used_at, revoked"
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
                binding=r["binding"],
                bound_tags=tuple(parse_tags(r["bound_tags"])),
                created_at=datetime.fromisoformat(r["created_at"]),
                last_used_at=(
                    datetime.fromisoformat(r["last_used_at"]) if r["last_used_at"] else None
                ),
                revoked=bool(r["revoked"]),
            )
            for r in rows
        ]
