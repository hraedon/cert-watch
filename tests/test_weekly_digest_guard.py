"""Production-code tests for durable, success-only digest cadence guards."""

from __future__ import annotations

import datetime as dt
from unittest.mock import MagicMock

import cert_watch.scheduler_context as scheduler_context
from cert_watch.database.kv_store import kv_get, kv_set_max_iso_week
from cert_watch.scheduler_context import SchedulerContext


class _FrozenDateTime(dt.datetime):
    current = dt.datetime(2026, 8, 17, 6, tzinfo=dt.UTC)

    @classmethod
    def now(cls, tz=None):
        value = cls.current
        return value if tz is None else value.astimezone(tz)


def _context(monkeypatch, db_path, *, now=None) -> tuple[SchedulerContext, MagicMock]:
    _FrozenDateTime.current = now or dt.datetime(2026, 8, 17, 6, tzinfo=dt.UTC)
    monkeypatch.setattr(scheduler_context._dt, "datetime", _FrozenDateTime)
    settings = MagicMock(db_path=db_path)
    context = SchedulerContext(settings=settings, alert_cfg=None, webhook_cfg=None)
    digest = MagicMock(return_value=True)
    monkeypatch.setattr(context, "_weekly_digest", digest)
    return context, digest


def test_renewal_digest_records_success_and_runs_once_per_iso_week(monkeypatch, tmp_path):
    db = tmp_path / "digest.sqlite3"
    context, digest = _context(monkeypatch, db)

    assert context.maybe_run_weekly_digest() == {"sent": 1, "failed": 0}
    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 0}

    assert digest.call_count == 1
    assert kv_get(db, "_scheduler.renewal_digest_iso_week") == "2026-W34"


def test_renewal_digest_failure_does_not_advance_and_retries(monkeypatch, tmp_path):
    context, digest = _context(monkeypatch, tmp_path / "digest.sqlite3")
    digest.return_value = False

    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 1}
    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 1}

    assert digest.call_count == 2
    assert context._renewal_digest_week == (0, 0)


def test_renewal_digest_success_survives_restart(monkeypatch, tmp_path):
    db = tmp_path / "digest.sqlite3"
    first, first_digest = _context(monkeypatch, db)
    first.maybe_run_weekly_digest()

    restarted, restarted_digest = _context(monkeypatch, db)
    restarted.maybe_run_weekly_digest()

    assert first_digest.call_count == 1
    restarted_digest.assert_not_called()


def test_renewal_digest_advances_in_next_iso_week(monkeypatch, tmp_path):
    context, digest = _context(monkeypatch, tmp_path / "digest.sqlite3")
    context.maybe_run_weekly_digest()

    _FrozenDateTime.current += dt.timedelta(days=7)
    context.maybe_run_weekly_digest()

    assert digest.call_count == 2


def test_renewal_digest_uses_iso_year_at_year_boundary(monkeypatch, tmp_path):
    context, digest = _context(
        monkeypatch,
        tmp_path / "digest.sqlite3",
        now=dt.datetime(2026, 12, 31, 6, tzinfo=dt.UTC),
    )
    context.maybe_run_weekly_digest()

    _FrozenDateTime.current = dt.datetime(2027, 1, 1, 6, tzinfo=dt.UTC)
    context.maybe_run_weekly_digest()

    assert digest.call_count == 1


def test_async_renewal_digest_advances_only_from_success_callback(monkeypatch, tmp_path):
    db = tmp_path / "digest.sqlite3"
    context, digest = _context(monkeypatch, db)
    digest.return_value = None

    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 0}
    assert kv_get(db, "_scheduler.renewal_digest_iso_week") is None

    success_callback = digest.call_args.args[0]
    success_callback(True)

    assert kv_get(db, "_scheduler.renewal_digest_iso_week") == "2026-W34"
    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 0}
    assert digest.call_count == 1


def test_async_renewal_digest_does_not_queue_same_week_twice(monkeypatch, tmp_path):
    context, digest = _context(monkeypatch, tmp_path / "digest.sqlite3")
    digest.return_value = None

    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 0}
    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 0}

    assert digest.call_count == 1


def test_late_previous_week_callback_cannot_regress_newer_week(monkeypatch, tmp_path):
    db = tmp_path / "digest.sqlite3"
    context, digest = _context(monkeypatch, db)
    digest.return_value = None

    assert context.maybe_run_weekly_digest() == {"sent": 0, "failed": 0}
    previous_week_callback = digest.call_args.args[0]

    _FrozenDateTime.current = dt.datetime(2027, 1, 4, 6, tzinfo=dt.UTC)
    digest.return_value = True
    assert context.maybe_run_weekly_digest() == {"sent": 1, "failed": 0}
    assert kv_get(db, "_scheduler.renewal_digest_iso_week") == "2027-W01"

    previous_week_callback(True)

    assert kv_get(db, "_scheduler.renewal_digest_iso_week") == "2027-W01"
    assert context._renewal_digest_week == (2027, 1)


def test_inline_success_callback_records_ledger_once(monkeypatch, tmp_path):
    context, digest = _context(monkeypatch, tmp_path / "digest.sqlite3")

    def deliver_inline(callback):
        callback(True)
        return True

    digest.side_effect = deliver_inline
    record = MagicMock(wraps=context._record_digest_week)
    monkeypatch.setattr(context, "_record_digest_week", record)

    assert context.maybe_run_weekly_digest() == {"sent": 1, "failed": 0}

    record.assert_called_once()


def test_async_failure_allows_same_week_retry_then_success(monkeypatch, tmp_path):
    db = tmp_path / "digest.sqlite3"
    context, digest = _context(monkeypatch, db)
    digest.return_value = None

    context.maybe_run_weekly_digest()
    failed_completion = digest.call_args.args[0]
    failed_completion(False)

    assert context._renewal_digest_inflight_week is None
    assert kv_get(db, "_scheduler.renewal_digest_iso_week") is None

    context.maybe_run_weekly_digest()
    successful_completion = digest.call_args.args[0]
    successful_completion(True)

    assert digest.call_count == 2
    assert kv_get(db, "_scheduler.renewal_digest_iso_week") == "2026-W34"


def test_async_duplicate_completion_callbacks_are_idempotent(monkeypatch, tmp_path):
    context, digest = _context(monkeypatch, tmp_path / "digest.sqlite3")
    digest.return_value = None
    record = MagicMock(wraps=context._record_digest_week)
    monkeypatch.setattr(context, "_record_digest_week", record)

    context.maybe_run_weekly_digest()
    completion = digest.call_args.args[0]
    completion(True)
    completion(True)
    completion(False)

    record.assert_called_once()
    assert context._renewal_digest_week == (2026, 34)


def test_stale_failure_cannot_clear_new_week_inflight(monkeypatch, tmp_path):
    context, digest = _context(monkeypatch, tmp_path / "digest.sqlite3")
    digest.return_value = None

    context.maybe_run_weekly_digest()
    old_completion = digest.call_args.args[0]
    _FrozenDateTime.current += dt.timedelta(days=7)
    context.maybe_run_weekly_digest()
    new_completion = digest.call_args.args[0]

    old_completion(False)
    assert context._renewal_digest_inflight_week == (2026, 35)

    new_completion(True)
    assert context._renewal_digest_week == (2026, 35)


def test_digest_ledger_update_is_monotonic(tmp_path):
    db = tmp_path / "digest.sqlite3"
    key = "_scheduler.renewal_digest_iso_week"

    assert kv_set_max_iso_week(db, key, (2027, 1)) == (True, (2027, 1))
    assert kv_set_max_iso_week(db, key, (2027, 1)) == (True, (2027, 1))
    assert kv_set_max_iso_week(db, key, (2026, 53)) == (False, (2027, 1))
    assert kv_get(db, key) == "2027-W01"


def test_expiry_digest_guard_persists_only_after_success(monkeypatch, tmp_path):
    _FrozenDateTime.current = dt.datetime(2026, 8, 17, 6, tzinfo=dt.UTC)
    db = tmp_path / "digest.sqlite3"
    settings = MagicMock(
        db_path=db,
        alert_digest_only=True,
        renewal_window_days=30,
    )
    monkeypatch.setattr(scheduler_context._dt, "datetime", _FrozenDateTime)
    monkeypatch.setattr("cert_watch.alerts.evaluate_all_certs", MagicMock())
    monkeypatch.setattr("cert_watch.alerts.evaluate_renewal_window", MagicMock())
    monkeypatch.setattr(
        "cert_watch.alerts.process_pending",
        MagicMock(side_effect=lambda *args, **kwargs: {"sent": 0, "failed": 0}),
    )
    delivery = MagicMock(side_effect=[False, True])
    monkeypatch.setattr("cert_watch.alerts.send_expiry_digest", delivery)
    context = SchedulerContext(settings=settings, alert_cfg=None, webhook_cfg=None)

    assert context.run_alerts() == {"sent": 0, "failed": 1}
    assert kv_get(db, "_scheduler.expiry_digest_iso_week") is None
    assert context.run_alerts() == {"sent": 1, "failed": 0}
    assert kv_get(db, "_scheduler.expiry_digest_iso_week") == "2026-W34"
    context.run_alerts()

    assert delivery.call_count == 2


def test_expiry_digest_success_survives_restart(monkeypatch, tmp_path):
    _FrozenDateTime.current = dt.datetime(2026, 8, 17, 6, tzinfo=dt.UTC)
    db = tmp_path / "digest.sqlite3"
    settings = MagicMock(
        db_path=db,
        alert_digest_only=True,
        renewal_window_days=30,
    )
    monkeypatch.setattr(scheduler_context._dt, "datetime", _FrozenDateTime)
    monkeypatch.setattr("cert_watch.alerts.evaluate_all_certs", MagicMock())
    monkeypatch.setattr("cert_watch.alerts.evaluate_renewal_window", MagicMock())
    monkeypatch.setattr(
        "cert_watch.alerts.process_pending",
        MagicMock(side_effect=lambda *args, **kwargs: {"sent": 0, "failed": 0}),
    )
    delivery = MagicMock(return_value=True)
    monkeypatch.setattr("cert_watch.alerts.send_expiry_digest", delivery)

    SchedulerContext(settings=settings, alert_cfg=None, webhook_cfg=None).run_alerts()
    SchedulerContext(settings=settings, alert_cfg=None, webhook_cfg=None).run_alerts()

    delivery.assert_called_once()
