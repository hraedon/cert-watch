from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from cert_watch.database.digest_deliveries import (
    claim_digest_delivery,
    complete_digest_delivery,
    digest_period_key,
    renew_digest_delivery,
)


def test_only_one_process_can_claim_same_delivery(tmp_path):
    db = tmp_path / "claims.sqlite3"
    barrier = threading.Barrier(3)
    states: list[str] = []

    def claim() -> None:
        barrier.wait()
        states.append(
            claim_digest_delivery(db, "renewal:2026-W34", "smtp", "a@example.com").state
        )

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert sorted(states) == ["acquired", "busy"]


def test_expired_lease_can_be_reclaimed_and_stale_owner_cannot_complete(tmp_path):
    db = tmp_path / "claims.sqlite3"
    start = datetime(2026, 8, 23, tzinfo=UTC)
    first = claim_digest_delivery(
        db, "expiry:2026-W34", "smtp", "a@example.com", lease_seconds=10, now=start
    )
    second = claim_digest_delivery(
        db,
        "expiry:2026-W34",
        "smtp",
        "a@example.com",
        lease_seconds=10,
        now=start + timedelta(seconds=11),
    )

    assert first.acquired and second.acquired
    assert first.lease_owner != second.lease_owner
    assert not complete_digest_delivery(db, first, succeeded=True, now=start)
    assert complete_digest_delivery(db, second, succeeded=True, now=start)
    assert claim_digest_delivery(
        db, "expiry:2026-W34", "smtp", "a@example.com", now=start
    ).state == "sent"


def test_failed_claim_is_immediately_retryable_with_same_idempotency_key(tmp_path):
    db = tmp_path / "claims.sqlite3"
    first = claim_digest_delivery(db, "renewal:2026-W34", "webhook:x", "global")
    assert complete_digest_delivery(db, first, succeeded=False)

    retry = claim_digest_delivery(db, "renewal:2026-W34", "webhook:x", "global")
    assert retry.acquired
    assert retry.idempotency_key == first.idempotency_key


def test_renewed_lease_blocks_takeover_past_original_expiry(tmp_path):
    db = tmp_path / "claims.sqlite3"
    start = datetime(2026, 8, 23, tzinfo=UTC)
    first = claim_digest_delivery(
        db, "renewal:2026-W34", "webhook:x", "owner", lease_seconds=10, now=start
    )
    assert renew_digest_delivery(
        db, first, lease_seconds=10, now=start + timedelta(seconds=9)
    )

    contender = claim_digest_delivery(
        db,
        "renewal:2026-W34",
        "webhook:x",
        "owner",
        lease_seconds=10,
        now=start + timedelta(seconds=11),
    )
    assert contender.state == "busy"
    assert claim_digest_delivery(
        db,
        "renewal:2026-W34",
        "webhook:x",
        "owner",
        lease_seconds=10,
        now=start + timedelta(seconds=20),
    ).state == "acquired"


def test_digest_period_key_rolls_over_at_iso_week_boundary():
    sunday = datetime(2026, 8, 23, 23, 59, tzinfo=UTC)
    monday = sunday + timedelta(minutes=2)
    assert digest_period_key("renewal", 7, now=sunday) != digest_period_key(
        "renewal", 7, now=monday
    )


def test_digest_claim_idempotency_key_format_is_upgrade_stable(tmp_path):
    claim = claim_digest_delivery(
        tmp_path / "claims.sqlite3",
        "renewal:2026-W34:cadence=7",
        "webhook:slack:0123456789abcdef",
        "owner@example.com",
    )
    assert claim.idempotency_key == (
        "4252e96e6c501d804f332b45fb98dc70ede1453c9a5dd4c68170d7e9f0ebb078"
    )
