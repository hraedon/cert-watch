"""Durable, cross-process claims for individual digest deliveries."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.database.schema import init_schema

DEFAULT_LEASE_SECONDS = 15 * 60


@dataclass(frozen=True)
class DigestDeliveryClaim:
    state: Literal["acquired", "busy", "sent"]
    digest_key: str
    channel: str
    target: str
    idempotency_key: str
    lease_owner: str | None = None

    @property
    def acquired(self) -> bool:
        return self.state == "acquired"


def digest_period_key(kind: str, cadence_days: int, *, now: datetime | None = None) -> str:
    """Return a stable identity for one weekly digest period."""
    current = now or datetime.now(UTC)
    iso = current.isocalendar()
    return f"{kind}:{iso.year:04d}-W{iso.week:02d}:cadence={cadence_days}"


def _idempotency_key(digest_key: str, channel: str, target: str) -> str:
    raw = f"{digest_key}\0{channel}\0{target}".encode()
    return hashlib.sha256(raw).hexdigest()


def claim_digest_delivery(
    db_path: str | Path,
    digest_key: str,
    channel: str,
    target: str,
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    now: datetime | None = None,
) -> DigestDeliveryClaim:
    """Atomically claim a delivery unless it is sent or has a live lease."""
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    owner = uuid.uuid4().hex
    expires = current + timedelta(seconds=lease_seconds)
    idempotency_key = _idempotency_key(digest_key, channel, target)

    init_schema(db_path)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT status, lease_expires_at, idempotency_key "
                "FROM digest_deliveries "
                "WHERE digest_key = ? AND channel = ? AND target = ?",
                (digest_key, channel, target),
            ).fetchone()
            if row is not None and row["status"] == "sent":
                conn.rollback()
                return DigestDeliveryClaim(
                    "sent", digest_key, channel, target, row["idempotency_key"]
                )
            if row is not None and row["status"] == "claimed":
                lease_raw = row["lease_expires_at"]
                if lease_raw and _parse_iso(lease_raw) > current:
                    conn.rollback()
                    return DigestDeliveryClaim(
                        "busy", digest_key, channel, target, row["idempotency_key"]
                    )

            timestamp = current.isoformat()
            conn.execute(
                """INSERT INTO digest_deliveries
                   (digest_key, channel, target, status, lease_owner,
                    lease_expires_at, idempotency_key, created_at, updated_at)
                   VALUES (?, ?, ?, 'claimed', ?, ?, ?, ?, ?)
                   ON CONFLICT(digest_key, channel, target) DO UPDATE SET
                       status = 'claimed', lease_owner = excluded.lease_owner,
                       lease_expires_at = excluded.lease_expires_at,
                       updated_at = excluded.updated_at""",
                (
                    digest_key,
                    channel,
                    target,
                    owner,
                    expires.isoformat(),
                    idempotency_key,
                    timestamp,
                    timestamp,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return DigestDeliveryClaim(
        "acquired", digest_key, channel, target, idempotency_key, owner
    )


def complete_digest_delivery(
    db_path: str | Path,
    claim: DigestDeliveryClaim,
    *,
    succeeded: bool,
    now: datetime | None = None,
) -> bool:
    """Complete an acquired claim; stale owners cannot alter a newer claim."""
    if not claim.acquired or claim.lease_owner is None:
        return False
    current = now or datetime.now(UTC)
    timestamp = current.isoformat()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """UPDATE digest_deliveries
               SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
                   updated_at = ?, sent_at = ?
               WHERE digest_key = ? AND channel = ? AND target = ?
                 AND status = 'claimed' AND lease_owner = ?""",
            (
                "sent" if succeeded else "failed",
                timestamp,
                timestamp if succeeded else None,
                claim.digest_key,
                claim.channel,
                claim.target,
                claim.lease_owner,
            ),
        )
        conn.commit()
    return cursor.rowcount == 1


def renew_digest_delivery(
    db_path: str | Path,
    claim: DigestDeliveryClaim,
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    now: datetime | None = None,
) -> bool:
    """Extend an acquired claim if this caller still owns its live row."""
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    if not claim.acquired or claim.lease_owner is None:
        return False
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """UPDATE digest_deliveries
               SET lease_expires_at = ?, updated_at = ?
               WHERE digest_key = ? AND channel = ? AND target = ?
                 AND status = 'claimed' AND lease_owner = ?""",
            (
                (current + timedelta(seconds=lease_seconds)).isoformat(),
                current.isoformat(),
                claim.digest_key,
                claim.channel,
                claim.target,
                claim.lease_owner,
            ),
        )
        conn.commit()
    return cursor.rowcount == 1
