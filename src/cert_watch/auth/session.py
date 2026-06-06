"""Session signing/verification and OAuth state signing.

HMAC-signed session tokens and OAuth state tokens, plus the module-level
signing key (set during lifespan startup). The most security-critical and
most-referenced slice of the auth surface.

BC-081: sessions now include a version field. On validation, the stored
session version is checked — if it exceeds the token's version, the session
is revoked (logout/credential change bumps the version in the DB).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time

from cert_watch.config import read_secret
from cert_watch.security import SecurityContext

logger = logging.getLogger("cert_watch.auth")


def _key(security: SecurityContext | None) -> str:
    """Resolve the signing key: the injected SecurityContext, else the
    module-level import-time fallback (Plan 018 B1)."""
    val = security.signing_key if security is not None else _signing_key
    assert val is not None
    return val

# Session cookie config
SESSION_COOKIE = "cw_auth"
SESSION_TTL = 8 * 3600  # 8 hours, matches CSRF token TTL
_signing_key = read_secret("CERT_WATCH_AUTH_SECRET") or None
if not _signing_key:
    # Import-time fallback only. The lifespan replaces this via set_signing_key()
    # with a key from config.resolve_or_persist_secret(), which persists to
    # data_dir/.auth_secret (0600) so sessions survive restarts even without the
    # env var. The authoritative warning (if persistence actually fails) is
    # emitted there; keep this at debug to avoid a misleading "sessions die on
    # restart" message that the persistence path contradicts.
    _signing_key = secrets.token_hex(32)
    logger.debug(
        "CERT_WATCH_AUTH_SECRET not set at import; using a temporary key until "
        "lifespan resolves a persisted signing key."
    )


def set_signing_key(value: str) -> None:
    """Replace the module-level signing key (used during lifespan startup)."""
    global _signing_key
    _signing_key = value


def _sign_state(
    state: str, security: SecurityContext | None = None, nonce: str | None = None
) -> str:
    payload = f"{state}:{nonce}" if nonce else state
    sig = hmac.new(_key(security).encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}:{sig}"


def _verify_state(
    token: str, security: SecurityContext | None = None
) -> tuple[str, str | None] | None:
    """Verify a signed OAuth state token.

    Returns ``(state, nonce)`` on success, ``None`` on failure.
    Handles both the new ``state:nonce:sig`` format and the legacy
    ``state:sig`` format (nonce returned as ``None``).
    """
    if not token or ":" not in token:
        return None
    # Try new format first: state:nonce:sig (3+ colon-separated parts)
    parts = token.split(":")
    if len(parts) >= 3:
        sig = parts[-1]
        nonce = parts[-2]
        state = ":".join(parts[:-2])
        expected = hmac.new(
            _key(security).encode(), f"{state}:{nonce}".encode(), hashlib.sha256
        ).hexdigest()[:32]
        if hmac.compare_digest(sig, expected):
            return state, nonce
    # Fallback: legacy format state:sig
    last_colon = token.rfind(":")
    state = token[:last_colon]
    sig = token[last_colon + 1:]
    expected = hmac.new(
        _key(security).encode(), state.encode(), hashlib.sha256
    ).hexdigest()[:32]
    if hmac.compare_digest(sig, expected):
        return state, None
    return None


def _sign_session(data: str, security: SecurityContext | None = None) -> str:
    sig = hmac.new(_key(security).encode(), data.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{data}:{sig}"


def create_session(
    username: str,
    security: SecurityContext | None = None,
    *,
    version: int = 0,
) -> str:
    """Create a signed session token for the given username.

    The *version* parameter embeds the current session version from the
    ``session_versions`` table. On validation, if the stored version exceeds
    the token's embedded version, the session is considered revoked.
    """
    payload = f"{username}:{version}:{int(time.time())}:{secrets.token_hex(8)}"
    return _sign_session(payload, security)


def validate_session(
    token: str,
    security: SecurityContext | None = None,
    *,
    db_path: str | None = None,
) -> str | None:
    """Validate a session token and return the username, or None if invalid.

    When *db_path* is provided, the stored session version for the user is
    checked. If the stored version exceeds the version embedded in the token,
    the session is considered revoked (BC-081).
    """
    if not token or ":" not in token:
        return None
    # Split last ':' to get the signature
    last_colon = token.rfind(":")
    if last_colon < 0:
        return None
    payload = token[:last_colon]
    sig = token[last_colon + 1 :]
    expected = hmac.new(_key(security).encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None
    parts = payload.split(":")
    if len(parts) < 3:
        return None

    # BC-081: tokens with version field have 4+ parts (username:version:ts:nonce)
    # Old-format tokens have 3 parts (username:ts:nonce) — version defaults to 0.
    if len(parts) >= 4:
        username = parts[0]
        try:
            version = int(parts[1])
        except ValueError:
            # Not a version field — treat as old-format (username:ts:nonce)
            username = parts[0]
            version = 0
            ts = _parse_ts(parts, start=1)
        else:
            ts = _parse_ts(parts, start=2)
    else:
        username = parts[0]
        version = 0
        ts = _parse_ts(parts, start=1)

    # Read SESSION_TTL from the cert_watch.auth package namespace so tests that
    # monkeypatch the re-exported `cert_watch.auth.SESSION_TTL` take effect here.
    # Env var CERT_WATCH_SESSION_TTL wins (project convention).
    import cert_watch.auth as _auth_pkg

    env_ttl = int(os.environ.get("CERT_WATCH_SESSION_TTL", "0"))
    ttl = env_ttl or getattr(_auth_pkg, "SESSION_TTL", SESSION_TTL)
    if (time.time() - ts) > ttl:
        return None

    # BC-081: check session version against the database
    if db_path is not None:
        from cert_watch.database.queries import get_session_version
        stored_version = get_session_version(db_path, username)
        if stored_version > version:
            return None

    return username


def _parse_ts(parts: list[str], start: int) -> float:
    """Extract the timestamp from the parts list starting at *start*.

    The timestamp is always an integer (epoch seconds). If parsing fails,
    return 0 which will cause the TTL check to fail.
    """
    try:
        return int(parts[start])
    except (ValueError, IndexError):
        return 0.0
