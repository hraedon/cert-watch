"""kv_store key-value helpers."""
from __future__ import annotations

import re
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


_ISO_WEEK_RE = re.compile(r"^(\d{4})-W(0[1-9]|[1-4]\d|5[0-3])$")


def kv_set_max_iso_week(
    db_path: str | Path, key: str, week: tuple[int, int]
) -> tuple[bool, tuple[int, int]]:
    """Persist *week* without allowing an older ISO week to overwrite it.

    The comparison and write happen inside ``BEGIN IMMEDIATE`` so delayed
    async callbacks from different scheduler contexts cannot regress the
    durable digest ledger after a newer week has completed.

    Returns ``(accepted, stored_week)``.  An equal week is accepted as an
    idempotent success; an older candidate returns ``False`` and the newer
    stored week.
    """
    year, week_number = week
    if year < 1 or not 1 <= week_number <= 53:
        raise ValueError(f"invalid ISO week: {week!r}")
    candidate = f"{year:04d}-W{week_number:02d}"

    init_schema(db_path)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = ?", (key,)
            ).fetchone()
            current = (0, 0)
            if row is not None:
                match = _ISO_WEEK_RE.fullmatch(str(row["value"]))
                if match:
                    parsed = (int(match.group(1)), int(match.group(2)))
                    if parsed[0] >= 1:
                        current = parsed
            if current > week:
                conn.rollback()
                return False, current
            if current == week:
                conn.rollback()
                return True, current
            now = _iso(datetime.now(UTC))
            conn.execute(
                "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
                (key, candidate, now),
            )
            conn.commit()
            return True, week
        except Exception:
            conn.rollback()
            raise


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
