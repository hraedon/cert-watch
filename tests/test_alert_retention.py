"""Tests for alert retention purge (Plan 002 WI-1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.database import Alert, SqliteAlertRepository, init_schema, purge_old_alerts
from cert_watch.database.pagination import UNDELIVERED_RETENTION_MULTIPLIER


def _make_alert(
    repo: SqliteAlertRepository,
    *,
    created_at: datetime | None = None,
    alert_type: str = "expiry_warning",
    status: str = "sent",
    cert_id: str = "cert-1",
    sent_at: datetime | None = None,
) -> str:
    alert = Alert(
        cert_id=cert_id,
        alert_type=alert_type,
        status=status,
        message="test alert",
        created_at=created_at or datetime.now(UTC),
        sent_at=sent_at,
    )
    return repo.create(alert)


def _days_ago(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


# ---------- purge_old_alerts ----------


def test_purge_old_alerts_deletes_old_retains_recent(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    old_ts = datetime.now(UTC) - timedelta(days=200)
    recent_ts = datetime.now(UTC) - timedelta(days=10)

    _make_alert(repo, created_at=old_ts, cert_id="old-cert")
    _make_alert(repo, created_at=recent_ts, cert_id="recent-cert")

    deleted = purge_old_alerts(db, retention_days=90)
    assert deleted == 1

    remaining = repo.list_all()
    assert len(remaining) == 1
    assert remaining[0].cert_id == "recent-cert"


def test_purge_old_alerts_boundary(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    inside_ts = datetime.now(UTC) - timedelta(days=89)
    outside_ts = datetime.now(UTC) - timedelta(days=91)

    _make_alert(repo, created_at=inside_ts, cert_id="inside")
    _make_alert(repo, created_at=outside_ts, cert_id="outside")

    deleted = purge_old_alerts(db, retention_days=90)
    assert deleted == 1

    remaining = repo.list_all()
    assert len(remaining) == 1
    assert remaining[0].cert_id == "inside"


def test_purge_old_alerts_zero_disables(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    old_ts = datetime.now(UTC) - timedelta(days=999)
    _make_alert(repo, created_at=old_ts)

    assert purge_old_alerts(db, retention_days=0) == 0
    assert len(repo.list_all()) == 1


def test_purge_old_alerts_negative_disables(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    old_ts = datetime.now(UTC) - timedelta(days=999)
    _make_alert(repo, created_at=old_ts)

    assert purge_old_alerts(db, retention_days=-5) == 0
    assert len(repo.list_all()) == 1


def test_purge_old_alerts_never_raises(tmp_path: Path) -> None:
    assert purge_old_alerts("/nonexistent/dir/db.sqlite3", retention_days=90) == 0


def test_purge_old_alerts_empty_table(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    assert purge_old_alerts(db, retention_days=90) == 0


def test_purge_old_alerts_all_old(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    old_ts = datetime.now(UTC) - timedelta(days=200)
    _make_alert(repo, created_at=old_ts, cert_id="a")
    _make_alert(repo, created_at=old_ts, cert_id="b")

    deleted = purge_old_alerts(db, retention_days=90)
    assert deleted == 2
    assert len(repo.list_all()) == 0


def test_purge_old_alerts_all_recent(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    recent_ts = datetime.now(UTC) - timedelta(days=10)
    _make_alert(repo, created_at=recent_ts, cert_id="a")
    _make_alert(repo, created_at=recent_ts, cert_id="b")

    deleted = purge_old_alerts(db, retention_days=90)
    assert deleted == 0
    assert len(repo.list_all()) == 2


def test_purge_old_alerts_mixed_types(tmp_path: Path) -> None:
    """Purge works regardless of alert_type."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    old_ts = datetime.now(UTC) - timedelta(days=200)
    recent_ts = datetime.now(UTC) - timedelta(days=10)

    _make_alert(repo, created_at=old_ts, alert_type="expiry_warning", cert_id="a")
    _make_alert(repo, created_at=old_ts, alert_type="drift", cert_id="b")
    _make_alert(repo, created_at=recent_ts, alert_type="expired", cert_id="c")
    _make_alert(repo, created_at=recent_ts, alert_type="drift", cert_id="d")

    deleted = purge_old_alerts(db, retention_days=90)
    assert deleted == 2

    remaining = repo.list_all()
    assert len(remaining) == 2
    assert {r.cert_id for r in remaining} == {"c", "d"}


# ---------- undelivered alerts outlive the delivered window (#39) ----------


def test_undelivered_alerts_survive_the_delivered_retention_window(tmp_path: Path) -> None:
    """A pending or failed alert reached nobody; it is the only record of that.

    Scenario from #39: SMTP credentials are wrong, alerts exhaust retries into
    ``failed``, and 90 days later the evidence that nothing was delivered used
    to disappear along with the alerts that *were*.
    """
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    _make_alert(repo, created_at=_days_ago(200), status="sent", cert_id="delivered")
    _make_alert(repo, created_at=_days_ago(200), status="pending", cert_id="never-tried")
    _make_alert(repo, created_at=_days_ago(200), status="failed", cert_id="never-reached")

    assert purge_old_alerts(db, retention_days=90) == 1
    assert {a.cert_id for a in repo.list_all()} == {"never-tried", "never-reached"}


def test_undelivered_alerts_are_still_bounded_by_the_longer_horizon(tmp_path: Path) -> None:
    """An install with no transport keeps every alert pending forever; the table
    must still have a bound, just a much longer one than for delivered rows.
    """
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    horizon = 90 * UNDELIVERED_RETENTION_MULTIPLIER

    _make_alert(repo, created_at=_days_ago(horizon - 1), status="pending", cert_id="inside")
    _make_alert(repo, created_at=_days_ago(horizon + 1), status="pending", cert_id="outside")
    _make_alert(repo, created_at=_days_ago(horizon + 1), status="failed", cert_id="outside-failed")

    assert purge_old_alerts(db, retention_days=90) == 2
    assert [a.cert_id for a in repo.list_all()] == ["inside"]


def test_a_recorded_sent_at_counts_as_delivered_whatever_the_status(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    _make_alert(
        repo, created_at=_days_ago(200), status="failed", sent_at=_days_ago(199), cert_id="odd",
    )

    assert purge_old_alerts(db, retention_days=90) == 1
    assert repo.list_all() == []


def test_zero_retention_disables_the_undelivered_horizon_too(tmp_path: Path) -> None:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)

    _make_alert(repo, created_at=_days_ago(5000), status="pending")

    assert purge_old_alerts(db, retention_days=0) == 0
    assert len(repo.list_all()) == 1
