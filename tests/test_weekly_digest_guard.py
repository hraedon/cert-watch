"""Scheduler digest orchestration after claim-ledger cadence replaced week gates."""

from __future__ import annotations

from unittest.mock import MagicMock

from cert_watch.alerting.digest.engine import DigestRunResult
from cert_watch.scheduler_context import SchedulerContext


def _context(db_path, *, digest_only: bool = False) -> SchedulerContext:
    settings = MagicMock(
        db_path=db_path,
        alert_digest_only=digest_only,
        renewal_window_days=30,
    )
    return SchedulerContext(settings=settings, alert_cfg=None, webhook_cfg=None)


def test_weekly_digest_runs_renewal_and_orphan_synchronously(monkeypatch, tmp_path):
    context = _context(tmp_path / "digest.sqlite3")
    run = MagicMock(
        side_effect=[
            DigestRunResult(sent=2),
            DigestRunResult(sent=1),
        ]
    )
    monkeypatch.setattr(context, "_run_digest", run)

    assert context.maybe_run_weekly_digest() == {
        "sent": 3,
        "failed": 0,
        "deferred": 0,
    }
    assert [call.args[1].name for call in run.call_args_list] == ["renewal", "orphan"]
    assert [call.args[2] for call in run.call_args_list] == [7, 7]


def test_weekly_digest_aggregates_failures_and_busy_claims(monkeypatch, tmp_path):
    context = _context(tmp_path / "digest.sqlite3")
    monkeypatch.setattr(
        context,
        "_run_digest",
        MagicMock(
            side_effect=[
                DigestRunResult(failed=1, busy=2),
                DigestRunResult(failed=3, busy=4),
            ]
        ),
    )

    assert context.maybe_run_weekly_digest() == {
        "sent": 0,
        "failed": 4,
        "deferred": 6,
    }


def test_scheduler_never_reads_or_writes_legacy_week_keys(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("legacy scheduler digest week key was accessed")

    monkeypatch.setattr("cert_watch.database.kv_store.kv_get", forbidden)
    monkeypatch.setattr("cert_watch.database.kv_store.kv_set_max_iso_week", forbidden)
    context = _context(tmp_path / "digest.sqlite3")
    monkeypatch.setattr(
        context,
        "_run_digest",
        MagicMock(return_value=DigestRunResult()),
    )

    context.maybe_run_weekly_digest()


def test_expiry_digest_runs_each_alert_cycle_and_lets_claims_dedupe(
    monkeypatch, tmp_path
):
    context = _context(tmp_path / "digest.sqlite3", digest_only=True)
    monkeypatch.setattr("cert_watch.alerting.rules.expiry.evaluate_all_certs", MagicMock())
    monkeypatch.setattr(
        "cert_watch.alerting.rules.renewal.evaluate_renewal_window", MagicMock()
    )
    monkeypatch.setattr(
        "cert_watch.alerting.dispatch.process_pending",
        MagicMock(
            side_effect=lambda *args, **kwargs: {
                "sent": 0,
                "failed": 0,
                "deferred": 0,
            }
        ),
    )
    run = MagicMock(
        side_effect=[DigestRunResult(sent=1), DigestRunResult(skipped=1)]
    )
    monkeypatch.setattr(context, "_run_digest", run)

    assert context.run_alerts()["sent"] == 1
    assert context.run_alerts()["sent"] == 0
    assert run.call_count == 2
