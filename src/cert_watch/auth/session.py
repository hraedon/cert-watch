"""Session signing/verification and OAuth state signing.

HMAC-signed session tokens and OAuth state tokens, plus the module-level
signing key (set during lifespan startup). The most security-critical and
most-referenced slice of the auth surface.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time

from cert_watch.config import read_secret
from cert_watch.security import SecurityContext

logger = logging.getLogger("cert_watch.auth")


def _key(security: SecurityContext | None) -> str:
    """Resolve the signing key: the injected SecurityContext, else the
    module-level import-time fallback (Plan 018 B1)."""
    return security.signing_key if security is not None else _signing_key

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


def _sign_state(state: str, security: SecurityContext | None = None) -> str:
    sig = hmac.new(_key(security).encode(), state.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{state}:{sig}"


def _verify_state(token: str, security: SecurityContext | None = None) -> str | None:
    if not token or ":" not in token:
        return None
    last_colon = token.rfind(":")
    state = token[:last_colon]
    sig = token[last_colon + 1 :]
    expected = hmac.new(_key(security).encode(), state.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None
    return state


def _sign_session(data: str, security: SecurityContext | None = None) -> str:
    sig = hmac.new(_key(security).encode(), data.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{data}:{sig}"


def create_session(username: str, security: SecurityContext | None = None) -> str:
    """Create a signed session token for the given username."""
    payload = f"{username}:{int(time.time())}:{secrets.token_hex(8)}"
    return _sign_session(payload, security)


def validate_session(token: str, security: SecurityContext | None = None) -> str | None:
    """Validate a session token and return the username, or None if invalid."""
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
    if len(parts) < 2:
        return None
    username = parts[0]
    try:
        ts = int(parts[1])
    except ValueError:
        return None
    # Read SESSION_TTL from the cert_watch.auth package namespace so tests that
    # monkeypatch the re-exported `cert_watch.auth.SESSION_TTL` take effect here.
    import cert_watch.auth as _auth_pkg

    ttl = getattr(_auth_pkg, "SESSION_TTL", SESSION_TTL)
    if (time.time() - ts) > ttl:
        return None
    return username
