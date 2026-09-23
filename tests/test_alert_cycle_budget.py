"""The alert phase must not block the cycle in proportion to the queue (#43).

A note on the sleep patching below: ``cert_watch.retry`` does ``import time``,
so ``monkeypatch.setattr("cert_watch.retry.time.sleep", ...)`` rebinds the
attribute on the ``time`` MODULE and disables sleeping process-wide for the
duration. That is fine where a test only wants the backoff skipped, but a test
that needs real elapsed time must not combine the two -- the budget tests here
therefore patch nothing and trip inside the first wave.

`_run_cycle` calls the alert phase synchronously, so whatever it costs, scanning
waits for it — and it costs most precisely when delivery is failing, which is
when an operator least wants scanning to stop. Two separate mechanisms hold that
down, and they are tested separately because neither is sufficient alone:

* waves share the backoff sleeps across the queue instead of paying them per
  alert;
* a wall-clock budget bounds everything the sleeps do not, above all a relay
  that hangs to its socket timeout rather than refusing.
"""

from __future__ import annotations

import smtplib
from time import monotonic
from unittest.mock import Mock

import pytest

from cert_watch.alerting import (
    ALERT_MAX_RETRIES,
    ALERT_RETRY_DELAY,
    AlertConfig,
    process_pending,
)
from cert_watch.database import Alert, SqliteAlertRepository, init_schema


def _queue(tmp_path, n):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    for i in range(n):
        repo.create(Alert(
            cert_id=f"cert-{i}", alert_type="expiry_warning", status="pending",
            message="Certificate expires within seven days", threshold_days=7,
            subject=f"CN=h{i}.example.invalid",
        ))
    return db, repo


def _config():
    return AlertConfig(
        smtp_host="relay.example.invalid", smtp_user="u", smtp_password="p",
        from_addr="watch@example.invalid", recipients=["ops@example.invalid"],
    )


def _hanging_relay(seconds):
    """A relay that burns wall clock and yields no connection.

    Busy-waits on `monotonic` rather than sleeping. Sibling tests here patch
    `cert_watch.retry.time.sleep`, which rebinds the attribute on the `time`
    MODULE and so disables sleeping process-wide while it is in effect — a stub
    built on `time.sleep` silently became instant depending on test order, and
    the budget never tripped. The property under test is elapsed time, so the
    stub must consume elapsed time by a means nothing else can switch off.

    A hanging relay does not refuse; it burns the socket timeout and yields no
    connection, which `_open_smtp_connection` reports by returning None.
    """
    def relay(*_a, **_kw):
        deadline = monotonic() + seconds
        while monotonic() < deadline:
            pass
        return None

    return relay


def _failing_smtp(monkeypatch):
    connection = Mock()
    connection.send_message.side_effect = smtplib.SMTPException("relay refused")
    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection", lambda *a, **kw: connection
    )
    return connection


def test_backoff_sleeps_are_shared_by_the_queue_not_paid_per_alert(tmp_path, monkeypatch):
    """The bug: ten failing alerts slept ten times over.

    Counted rather than timed — a wall-clock assertion here would be pinned to
    how loaded the machine is, and would redden CI on a schedule rather than on
    a regression.
    """
    _, repo = _queue(tmp_path, 10)
    _failing_smtp(monkeypatch)
    slept: list[float] = []
    monkeypatch.setattr("cert_watch.retry.time.sleep", slept.append)

    process_pending(repo, _config())

    assert len(slept) == ALERT_MAX_RETRIES - 1, (
        "one sleep between waves, regardless of how many alerts are in the queue"
    )
    assert sum(slept) <= ALERT_RETRY_DELAY * ALERT_MAX_RETRIES * 1.5  # jitter headroom


def test_every_alert_is_tried_once_before_any_is_tried_twice(tmp_path, monkeypatch):
    """Breadth before depth — the reason waves and the budget belong together.

    Spending a budget down the per-alert loop would give the first few alerts
    three attempts each and the rest none. Under an outage, having tried
    everything once is worth more than having tried three things thrice.
    """
    _, repo = _queue(tmp_path, 4)
    _failing_smtp(monkeypatch)
    monkeypatch.setattr("cert_watch.retry.time.sleep", lambda _s: None)
    order: list[str] = []
    from cert_watch.alerting.transports.smtp import SmtpTransport

    real = SmtpTransport.send

    def recording(transport, msg):
        order.append(msg.cert_id)
        return real(transport, msg)

    monkeypatch.setattr(SmtpTransport, "send", recording)

    process_pending(repo, _config())

    first_wave = order[:4]
    assert sorted(first_wave) == [f"cert-{i}" for i in range(4)], (
        f"the first four attempts must cover all four alerts, got {first_wave}"
    )
    assert len(order) == 4 * ALERT_MAX_RETRIES, "each alert still gets its full run"


def test_each_alert_still_gets_its_full_run_of_attempts(tmp_path, monkeypatch):
    """Waves give every alert a full round before persisted backoff."""
    _, repo = _queue(tmp_path, 3)
    connection = _failing_smtp(monkeypatch)
    monkeypatch.setattr("cert_watch.retry.time.sleep", lambda _s: None)

    result = process_pending(repo, _config())

    assert result == {"sent": 0, "failed": 0, "deferred": 3}
    assert connection.send_message.call_count == 3 * ALERT_MAX_RETRIES
    stored = repo.list_for_cert("cert-0")[0]
    assert stored.status == "pending"
    assert stored.attempt_count == ALERT_MAX_RETRIES
    assert stored.next_attempt_at is not None
    assert f"after {ALERT_MAX_RETRIES} attempts" in stored.error_message


def test_a_spent_budget_leaves_alerts_pending_rather_than_failed(tmp_path, monkeypatch):
    """An alert the cycle never finished trying is not an alert that failed.

    Marking it failed would spend its whole retry budget on the clock running
    out, which is a property of the queue, not of the destination.
    """
    _, repo = _queue(tmp_path, 5)

    slow_and_failing = _hanging_relay(0.05)

    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection", slow_and_failing
    )

    result = process_pending(repo, _config(), budget_seconds=0.06)

    assert result["failed"] == 0, "the clock ran out; nothing was refused by a destination"
    assert result["deferred"] == 5
    assert all(a.status == "pending" for i in range(5) for a in repo.list_for_cert(f"cert-{i}"))


def test_budget_deferred_alerts_remain_deliverable(tmp_path, monkeypatch):
    """Attempted rows back off; unattempted rows remain immediately eligible."""
    _, repo = _queue(tmp_path, 2)

    slow_and_failing = _hanging_relay(0.05)

    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection", slow_and_failing
    )
    assert process_pending(repo, _config(), budget_seconds=0.01)["deferred"] == 2

    connection = Mock()
    connection.send_message.return_value = {}
    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection", lambda *a, **kw: connection
    )

    assert process_pending(repo, _config()) == {"sent": 1, "failed": 0, "deferred": 0}
    assert process_pending(repo, _config(), ignore_backoff=True) == {
        "sent": 1,
        "failed": 0,
        "deferred": 0,
    }
    assert connection.send_message.call_count == 2


def test_a_healthy_queue_never_sleeps_and_never_defers(tmp_path, monkeypatch):
    """The budget must be invisible when nothing is wrong."""
    _, repo = _queue(tmp_path, 25)
    connection = Mock()
    connection.send_message.return_value = {}
    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection", lambda *a, **kw: connection
    )
    slept: list[float] = []
    monkeypatch.setattr("cert_watch.retry.time.sleep", slept.append)

    result = process_pending(repo, _config())

    assert result == {"sent": 25, "failed": 0, "deferred": 0}
    assert slept == [], "a delivered alert has nothing to back off from"


def test_a_partially_attempted_alert_does_not_report_attempts_it_never_made(
    tmp_path, monkeypatch,
):
    """The count must describe what happened, not what was planned."""
    _, repo = _queue(tmp_path, 1)
    connection = _failing_smtp(monkeypatch)
    monkeypatch.setattr("cert_watch.retry.time.sleep", lambda _s: None)

    process_pending(repo, _config())

    stored = repo.list_for_cert("cert-0")[0]
    assert f"after {connection.send_message.call_count} attempts" in stored.error_message


@pytest.mark.parametrize("queue_size", [1, 5, 20])
def test_the_sleep_cost_does_not_grow_with_the_queue(queue_size, tmp_path, monkeypatch):
    """Stated as the scaling property, which is the thing that actually regressed."""
    _, repo = _queue(tmp_path, queue_size)
    _failing_smtp(monkeypatch)
    slept: list[float] = []
    monkeypatch.setattr("cert_watch.retry.time.sleep", slept.append)

    process_pending(repo, _config())

    assert len(slept) == ALERT_MAX_RETRIES - 1
