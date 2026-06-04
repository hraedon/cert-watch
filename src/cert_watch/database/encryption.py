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


def derive_encryption_key(signing_key: str) -> str:
    """Derive a Fernet-compatible key from the app signing key."""
    raw = hashlib.sha256(signing_key.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode()


def fernet_encrypt(plaintext: str, key: str) -> str:
    """Encrypt a value; return ``enc:v1:<token>``."""
    from cryptography.fernet import Fernet

    return _ENCRYPTED_PREFIX + Fernet(key.encode()).encrypt(plaintext.encode()).decode()


def fernet_decrypt(value: str, key: str) -> str | None:
    """Decrypt an ``enc:v1:`` value; pass through plaintext unchanged.

    Returns ``None`` when decryption fails (wrong key or corrupted data)
    instead of silently returning the raw ciphertext.
    """
    if not value.startswith(_ENCRYPTED_PREFIX):
        return value
    from cryptography.fernet import Fernet, InvalidToken

    try:
        return Fernet(key.encode()).decrypt(value[len(_ENCRYPTED_PREFIX) :].encode()).decode()
    except (InvalidToken, Exception):
        _logger.warning("kv: failed to decrypt value (wrong key or corrupted)")
        return None


def check_encrypted_values(db_path: str | Path, encryption_key: str) -> list[str]:
    """Return list of kv_store keys whose enc:v1: values fail to decrypt.

    Used at startup to warn if the signing key changed (e.g. .auth_secret
    was deleted/regenerated) and encrypted values are now unreadable.
    """
    init_schema(db_path)
    undecryptable: list[str] = []
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
    for row in rows:
        val = row["value"]
        if val and val.startswith(_ENCRYPTED_PREFIX):
            from cryptography.fernet import Fernet, InvalidToken
            try:
                Fernet(encryption_key.encode()).decrypt(
                    val[len(_ENCRYPTED_PREFIX) :].encode()
                )
            except (InvalidToken, Exception):
                undecryptable.append(row["key"])
    return undecryptable


def re_encrypt_kv_store(db_path: str | Path, old_key: str, new_key: str) -> int:
    """Re-encrypt all enc:v1: kv_store values from *old_key* to *new_key*.

    Returns the number of values re-encrypted. Values that cannot be decrypted
    with *old_key* are skipped (logged as warnings).
    """
    init_schema(db_path)
    count = 0
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
    for row in rows:
        val = row["value"]
        if not val or not val.startswith(_ENCRYPTED_PREFIX):
            continue
        plaintext = fernet_decrypt(val, old_key)
        if plaintext is None or plaintext.startswith(_ENCRYPTED_PREFIX):
            _logger.warning("re_encrypt: skipping key %s — cannot decrypt with old key", row["key"])
            continue
        new_val = fernet_encrypt(plaintext, new_key)
        with _connect(db_path) as conn2:
            conn2.execute(
                "UPDATE kv_store SET value = ? WHERE key = ?", (new_val, row["key"])
            )
            conn2.commit()
        count += 1
    return count
