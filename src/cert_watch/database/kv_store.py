"""kv_store key-value helpers."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from cert_watch.database.connection import _connect, _iso
from cert_watch.database.encryption import (
    _ENCRYPTED_PREFIX,
    _ENCRYPTED_PREFIX_V2,
    fernet_decrypt,
    fernet_encrypt,
)
from cert_watch.database.schema import init_schema


def kv_get(db_path: str | Path, key: str, encryption_key: str | None = None) -> str | None:
    """Get a value from the kv_store table. Returns None if key not found.

    When *encryption_key* is set and the stored value has an ``enc:``
    prefix (v1 or v2), the value is transparently decrypted (BC-082).
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    val = row["value"]
    if encryption_key and (
        val.startswith(_ENCRYPTED_PREFIX) or val.startswith(_ENCRYPTED_PREFIX_V2)
    ):
        val = fernet_decrypt(val, encryption_key)
    return cast("str | None", val)


def kv_set(db_path: str | Path, key: str, value: str) -> None:
    """Set a value in the kv_store table (upsert)."""
    init_schema(db_path)
    now = _iso(datetime.now(UTC))
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now),
        )
        conn.commit()


def kv_set_multi(db_path: str | Path, pairs: dict[str, str]) -> None:
    """Set multiple key-value pairs atomically in a single transaction."""
    init_schema(db_path)
    now = _iso(datetime.now(UTC))
    with _connect(db_path) as conn:
        for key, value in pairs.items():
            conn.execute(
                "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, now),
            )
        conn.commit()


def kv_set_secret(db_path: str | Path, key: str, value: str, encryption_key: str) -> None:
    """Encrypt and store a sensitive value in kv_store (BC-082)."""
    kv_set(db_path, key, fernet_encrypt(value, encryption_key))


def kv_all(db_path: str | Path) -> dict[str, str]:
    """Return all key-value pairs from the kv_store table."""
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()
    return {r["key"]: r["value"] for r in rows}
