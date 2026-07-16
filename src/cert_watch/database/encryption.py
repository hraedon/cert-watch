"""At-rest encryption utilities for sensitive kv_store values (BC-082)."""
from __future__ import annotations

import base64
import hashlib
import logging
from pathlib import Path

from cert_watch.database.connection import _connect
from cert_watch.database.schema import init_schema

_logger = logging.getLogger("cert_watch.database.encryption")

_ENCRYPTED_PREFIX = "enc:v1:"
_ENCRYPTED_PREFIX_V2 = "enc:v2:"

_KDF_INFO = b"cert-watch-kv-encryption-v2"


def derive_encryption_key(signing_key: str) -> str:
    """Derive a Fernet-compatible key from the app signing key.

    Uses HKDF-SHA256 with a context string for key separation so the same
    signing key produces different keys for session cookies, CSRF tokens,
    and kv_store encryption.  Backward-compatible: values encrypted with
    the legacy SHA-256 derivation are decryptable via
    :func:`derive_encryption_key_legacy`.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_KDF_INFO,
    )
    raw = hkdf.derive(signing_key.encode())
    return base64.urlsafe_b64encode(raw).decode()


def derive_encryption_key_legacy(signing_key: str) -> str:
    """Legacy key derivation (raw SHA-256, no context separation).

    Used only for decrypting ``enc:v1:`` values that were encrypted before
    the HKDF migration.  New encryptions use ``enc:v2:`` with
    :func:`derive_encryption_key`.
    """
    raw = hashlib.sha256(signing_key.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode()


def fernet_encrypt(plaintext: str, key: str) -> str:
    """Encrypt a value; return ``enc:v2:<token>``."""
    from cryptography.fernet import Fernet

    return _ENCRYPTED_PREFIX_V2 + Fernet(key.encode()).encrypt(plaintext.encode()).decode()


def fernet_decrypt(value: str, key: str) -> str | None:
    """Decrypt an ``enc:v1:`` or ``enc:v2:`` value; pass through plaintext unchanged.

    Attempts decryption with the provided *key*. For ``enc:v1:`` values that
    fail, the caller is responsible for retrying with a legacy-derived key
    (see :func:`derive_encryption_key_legacy`).

    Returns ``None`` when decryption fails (wrong key or corrupted data)
    instead of silently returning the raw ciphertext.
    """
    if not value.startswith(_ENCRYPTED_PREFIX) and not value.startswith(_ENCRYPTED_PREFIX_V2):
        return value
    from cryptography.fernet import Fernet, InvalidToken

    is_v2 = value.startswith(_ENCRYPTED_PREFIX_V2)
    token = value[len(_ENCRYPTED_PREFIX_V2 if is_v2 else _ENCRYPTED_PREFIX):]

    # Try the provided key first
    try:
        return Fernet(key.encode()).decrypt(token.encode()).decode()
    except (InvalidToken, Exception):
        pass

    if not is_v2:
        _logger.warning("kv: failed to decrypt v1 value with provided key")
        return None

    _logger.warning("kv: failed to decrypt value (wrong key or corrupted)")
    return None


def check_encrypted_values(db_path: str | Path, encryption_key: str) -> list[str]:
    """Return list of kv_store keys whose encrypted values fail to decrypt.

    Used at startup to warn if the signing key changed (e.g. .auth_secret
    was deleted/regenerated) and encrypted values are now unreadable.
    Handles both ``enc:v1:`` (legacy SHA-256) and ``enc:v2:`` (HKDF) values.
    """
    init_schema(db_path)
    undecryptable: list[str] = []
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
    for row in rows:
        val = row["value"]
        if val and (val.startswith(_ENCRYPTED_PREFIX) or val.startswith(_ENCRYPTED_PREFIX_V2)):
            from cryptography.fernet import Fernet, InvalidToken
            if val.startswith(_ENCRYPTED_PREFIX_V2):
                token = val[len(_ENCRYPTED_PREFIX_V2):]
            else:
                token = val[len(_ENCRYPTED_PREFIX):]
            try:
                Fernet(encryption_key.encode()).decrypt(token.encode())
            except (InvalidToken, Exception):
                undecryptable.append(row["key"])
    return undecryptable


def re_encrypt_kv_store(db_path: str | Path, old_key: str, new_key: str) -> int:
    """Re-encrypt all encrypted kv_store values from *old_key* to *new_key*.

    Handles both ``enc:v1:`` and ``enc:v2:`` prefixes. Returns the number of
    values re-encrypted. Values that cannot be decrypted with *old_key* are
    skipped (logged as warnings).
    """
    init_schema(db_path)
    count = 0
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
        for row in rows:
            val = row["value"]
            if not val or not (
                val.startswith(_ENCRYPTED_PREFIX)
                or val.startswith(_ENCRYPTED_PREFIX_V2)
            ):
                continue
            plaintext = fernet_decrypt(val, old_key)
            if plaintext is None or plaintext.startswith(_ENCRYPTED_PREFIX):
                _logger.warning(
                    "re_encrypt: skipping key %s — cannot decrypt with old key",
                    row["key"],
                )
                continue
            new_val = fernet_encrypt(plaintext, new_key)
            conn.execute(
                "UPDATE kv_store SET value = ? WHERE key = ?", (new_val, row["key"])
            )
            count += 1
        conn.commit()
    return count
