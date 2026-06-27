"""Tests for alert retention purge (Plan 002 WI-1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.database import Alert, SqliteAlertRepository, init_schema, purge_old_alerts


def _make_alert(
    repo: SqliteAlertRepository,
    *,
    created_at: datetime | None = None,
    alert_type: str = "expiry_warning",
    status: str = "sent",
    cert_id: str = "cert-1",
) -> str:
    alert = Alert(
        cert_id=cert_id,
        alert_type=alert_type,
        status=status,
        message="test alert",
        created_at=created_at or datetime.now(UTC),
    )
    return repo.create(alert)


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
    """Purge works regardless of alert_type or status."""
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
