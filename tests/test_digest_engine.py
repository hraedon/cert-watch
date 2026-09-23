"""DigestEngine claim, retry and fallback contracts (plan 058 PR 5)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
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
