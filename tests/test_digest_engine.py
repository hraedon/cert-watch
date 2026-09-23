"""DigestEngine claim, retry and fallback contracts (plan 058 PR 5)."""

from __future__ import annotations

from dataclasses import dataclass
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest

from cert_watch.alerting import OutboundMessage, SendResult
from cert_watch.alerting.digest.engine import DigestEngine, DigestTarget
from cert_watch.database.digest_deliveries import (
    claim_digest_delivery,
    complete_digest_delivery,
    digest_period_key,
)

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


@dataclass(frozen=True)
class StaticKind:
    name: str
    webhook_fanout: Literal["global", "per_target"]
    digest_targets: tuple[DigestTarget, ...]

    def targets(
        self,
        db_path: str | Path,
        now: datetime,
        cadence_days: int,
    ) -> list[DigestTarget]:
        del db_path, now, cadence_days
        return list(self.digest_targets)

    def render(self, target: DigestTarget) -> OutboundMessage:
        return OutboundMessage.from_digest(
            subject=f"{self.name} digest",
            body=str(target.payload),
            severity=f"{self.name}_digest",
            idempotency_key="",
            recipients=target.smtp_recipients,
        )


def _kind(
    name: str = "expiry",
    *,
    recipients: tuple[str, ...] = ("Accepted@Test", "Refused@Test"),
) -> StaticKind:
    fanout: Literal["global", "per_target"] = (
        "global" if name == "expiry" else "per_target"
    )
    return StaticKind(
        name,
        fanout,
        (
            DigestTarget(
                key="global" if fanout == "global" else "owner@test",
                payload="body",
                smtp_recipients=recipients,
                is_global=fanout == "global",
            ),
        ),
    )


def _period(name: str = "expiry") -> str:
    return digest_period_key(name, 7, now=NOW)


def test_partial_smtp_refusal_retries_only_refused_recipient(
    tmp_path, fake_transport, monkeypatch
) -> None:
    monkeypatch.setattr("cert_watch.retry.time.sleep", lambda _seconds: None)
    smtp = fake_transport(
        SendResult(
            "partial",
            "recipients_refused",
            accepted=("Accepted@Test",),
            refused=("Refused@Test",),
        ),
        SendResult("accepted", accepted=("Refused@Test",)),
        channel="smtp",
    )

    result = DigestEngine(tmp_path / "digest.sqlite3", [smtp], clock=lambda: NOW).run(
        _kind(), _period()
    )

    assert result.sent == 2
    assert result.failed == result.busy == 0
    assert [message.recipients for message in smtp.messages] == [
        ("Accepted@Test", "Refused@Test"),
        ("Refused@Test",),
    ]


def test_busy_smtp_lease_blocks_send_and_webhook_fallback(
    tmp_path, fake_transport
) -> None:
    db = tmp_path / "digest.sqlite3"
    claim_digest_delivery(db, _period(), "smtp", "accepted@test", now=NOW)
    smtp = fake_transport(channel="smtp")
    webhook = fake_transport(channel="webhook:generic")

    result = DigestEngine(db, [smtp, webhook], clock=lambda: NOW).run(
        _kind(recipients=("Accepted@Test",)), _period()
    )

    assert result.busy == 1
    assert smtp.messages == []
    assert webhook.messages == []


def test_webhook_is_fallback_after_smtp_retries_fail(
    tmp_path, fake_transport, monkeypatch
) -> None:
    monkeypatch.setattr("cert_watch.retry.time.sleep", lambda _seconds: None)
    smtp = fake_transport(SendResult("failed", "transport"), channel="smtp")
    webhook = fake_transport(channel="webhook:generic")

    engine = DigestEngine(
        tmp_path / "digest.sqlite3", [smtp, webhook], clock=lambda: NOW
    )
    result = engine.run(_kind(recipients=("ops@test",)), _period())
    repeated = engine.run(_kind(recipients=("ops@test",)), _period())

    assert len(smtp.messages) == 3
    assert len(webhook.messages) == 1
    assert result.failed == result.busy == 0
    assert repeated.sent == 0
    assert repeated.skipped == 1


@pytest.mark.parametrize("name", ["expiry", "renewal"])
def test_retry_policy_is_identical_for_both_digest_kinds(
    name, tmp_path, fake_transport, monkeypatch
) -> None:
    monkeypatch.setattr("cert_watch.retry.time.sleep", lambda _seconds: None)
    webhook = fake_transport(
        SendResult("failed", "transport"),
        SendResult("failed", "transport"),
        SendResult("accepted"),
        channel="webhook:generic",
    )

    result = DigestEngine(
        tmp_path / f"{name}.sqlite3", [webhook], clock=lambda: NOW
    ).run(_kind(name, recipients=()), _period(name))

    assert result.succeeded
    assert len(webhook.messages) == 3


def test_same_period_second_run_sends_nothing(tmp_path, fake_transport) -> None:
    smtp = fake_transport(channel="smtp")
    engine = DigestEngine(tmp_path / "digest.sqlite3", [smtp], clock=lambda: NOW)

    first = engine.run(_kind(recipients=("ops@test",)), _period())
    second = engine.run(_kind(recipients=("ops@test",)), _period())

    assert first.sent == 1
    assert second.sent == 0
    assert second.skipped == 1
    assert len(smtp.messages) == 1


def test_pre_engine_sent_claim_suppresses_upgrade_week_resend(
    tmp_path, fake_transport
) -> None:
    db = tmp_path / "digest.sqlite3"
    claim = claim_digest_delivery(db, _period(), "smtp", "ops@test", now=NOW)
    assert complete_digest_delivery(db, claim, succeeded=True, now=NOW)
    smtp = fake_transport(channel="smtp")

    result = DigestEngine(db, [smtp], clock=lambda: NOW).run(
        _kind(recipients=("ops@test",)), _period()
    )

    assert result.sent == 0
    assert result.skipped == 1
    assert smtp.messages == []


@pytest.mark.parametrize(
    ("first_cadence", "second_cadence"),
    [(7, 14), (14, 7), (30, 7)],
    ids=["cadence-increases", "cadence-decreases", "first-group-created"],
)
def test_cadence_change_does_not_resend_within_the_same_iso_week(
    first_cadence, second_cadence, tmp_path, fake_transport
) -> None:
    db = tmp_path / "digest.sqlite3"
    smtp = fake_transport(channel="smtp")
    engine = DigestEngine(db, [smtp], clock=lambda: NOW)

    first = engine.run(
        _kind(recipients=("ops@test",)),
        digest_period_key("expiry", first_cadence, now=NOW),
    )
    repeated = engine.run(
        _kind(recipients=("ops@test",)),
        digest_period_key("expiry", second_cadence, now=NOW),
    )

    assert first.sent == 1
    assert repeated.sent == 0
    assert repeated.skipped == 1
    assert len(smtp.messages) == 1


def test_cadence_change_still_sends_in_a_new_iso_week(
    tmp_path, fake_transport
) -> None:
    db = tmp_path / "digest.sqlite3"
    smtp = fake_transport(channel="smtp")
    engine = DigestEngine(db, [smtp], clock=lambda: NOW)

    first = engine.run(
        _kind(recipients=("ops@test",)),
        digest_period_key("expiry", 7, now=NOW),
    )
    next_week = engine.run(
        _kind(recipients=("ops@test",)),
        digest_period_key("expiry", 14, now=NOW + timedelta(days=7)),
    )

    assert first.sent == next_week.sent == 1
    assert len(smtp.messages) == 2


def test_stop_after_claim_abandons_lease_for_later_recovery(
    tmp_path, fake_transport, monkeypatch
) -> None:
    import cert_watch.alerting.digest.engine as engine_module

    db = tmp_path / "digest.sqlite3"
    stopped = threading.Event()
    smtp = fake_transport(channel="smtp")
    real_renew = engine_module.renew_digest_delivery

    def renew_then_stop(*args, **kwargs):
        renewed = real_renew(*args, **kwargs)
        stopped.set()
        return renewed

    monkeypatch.setattr(engine_module, "renew_digest_delivery", renew_then_stop)
    result = DigestEngine(
        db, [smtp], clock=lambda: NOW, stop_event=stopped
    ).run(_kind(recipients=("ops@test",)), _period())

    assert result.cancelled
    assert smtp.messages == []

    reclaimed = claim_digest_delivery(
        db,
        _period(),
        "smtp",
        "ops@test",
        now=datetime.now(UTC) + timedelta(minutes=16),
    )
    assert reclaimed.acquired
    assert complete_digest_delivery(db, reclaimed, succeeded=False)

    monkeypatch.setattr(engine_module, "renew_digest_delivery", real_renew)
    stopped.clear()
    recovered = DigestEngine(
        db, [smtp], clock=lambda: NOW, stop_event=stopped
    ).run(_kind(recipients=("ops@test",)), _period())

    assert recovered.sent == 1
    assert len(smtp.messages) == 1
