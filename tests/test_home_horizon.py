"""Home's horizon is twelve calendar weeks, not twelve non-empty buckets."""
from datetime import UTC, datetime, timedelta
from importlib import import_module

from fastapi.testclient import TestClient

from tests.test_attention import _seed


def test_home_horizon_excludes_expiries_beyond_twelve_weeks(reload_app, tmp_path, monkeypatch):
    monday = datetime(2026, 9, 7, 12, tzinfo=UTC)

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return monday

    module = import_module("cert_watch.routes.dashboard")
    monkeypatch.setattr(module, "datetime", FrozenDateTime)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    # Set stored dates explicitly to exercise the real calendar query.
    from cert_watch.database.connection import _connect

    with TestClient(app_mod.app) as client:
        for seed, offset in (("near", 3), ("last", 83), ("outside", 84), ("far", 200)):
            cert_id = _seed(db, seed, 20)
            with _connect(db) as conn:
                conn.execute(
                    "UPDATE certificates SET not_after = ? WHERE id = ?",
                    ((monday + timedelta(days=offset)).isoformat(), cert_id),
                )
                conn.commit()
        response = client.get("/")
    assert response.status_code == 200
    assert [bucket["bucket_start"] for bucket in response.context["horizon"]] == [
        "2026-09-07", "2026-11-23",
    ]
