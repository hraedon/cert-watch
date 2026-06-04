"""Session version helpers for token revocation (BC-081)."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import _connect, _iso
from cert_watch.database.schema import init_schema


def get_session_version(db_path: str | Path, username: str) -> int:
    """Return the current session version for *username*, defaulting to 0.

    A version of 0 means no row exists yet — sessions without a version
    record are accepted (backward compat for tokens issued before this
    feature was added).
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT version FROM session_versions WHERE username = ?", (username,)
        ).fetchone()
    return row["version"] if row else 0


def bump_session_version(db_path: str | Path, username: str) -> int:
    """Increment and return the session version for *username*.

    Creates the row (starting at version 1) if it doesn't exist. Returns the
    new version, so callers can use it directly.

    Uses INSERT … ON CONFLICT … DO UPDATE … RETURNING (SQLite 3.35+) to
    eliminate the TOCTOU window between UPDATE and SELECT.
    """
    init_schema(db_path)
    now = _iso(datetime.now(UTC))
    with _connect(db_path) as conn:
        row = conn.execute(
            "INSERT INTO session_versions (username, version, updated_at)"
            " VALUES (?, 1, ?)"
            " ON CONFLICT(username) DO UPDATE SET"
            " version = version + 1, updated_at = excluded.updated_at"
            " RETURNING version",
            (username, now),
        ).fetchone()
        version = row["version"] if row else 1
        conn.commit()
    return version
