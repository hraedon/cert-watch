"""Tests for Plan 016 Slice 4 — calendar / expiry timeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteCertificateRepository, init_schema
from cert_watch.database.queries import list_calendar


def _make_leaf(
    days_valid: int = 90,
    sans: list[str] | None = None,
    fingerprint: str = "abc123",
) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject="CN=test.example.com",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=days_valid),
        san_dns_names=sans or ["test.example.com"],
        fingerprint_sha256=fingerprint,
        raw_der=b"",
    )


def _add_cert(db, hostname: str, port: int, days_valid: int, fp: str) -> str:
    repo = SqliteCertificateRepository(db, hostname=hostname, port=port)
    return repo.add(_make_leaf(days_valid=days_valid, fingerprint=fp))


# ---------- list_calendar ----------


class TestListCalendar:
    def test_empty(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        result = list_calendar(db)
        assert result == []

    def test_month_bucket(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _add_cert(db, "h1.example.com", 443, 30, "fp1")
        _add_cert(db, "h2.example.com", 443, 35, "fp2")
        result = list_calendar(db, bucket="month")
        assert len(result) >= 1
        assert result[0]["count"] >= 1
        assert isinstance(result[0]["cert_ids"], list)

    def test_day_bucket(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _add_cert(db, "h1.example.com", 443, 30, "fp1")
        _add_cert(db, "h2.example.com", 443, 30, "fp2")
        result = list_calendar(db, bucket="day")
        assert len(result) >= 1
        # Both should be in the same day bucket
        assert result[0]["count"] == 2

    def test_week_bucket(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _add_cert(db, "h1.example.com", 443, 10, "fp1")
        result = list_calendar(db, bucket="week")
        assert len(result) >= 1

    def test_date_range_filter(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _add_cert(db, "h1.example.com", 443, 10, "fp1")
        _add_cert(db, "h2.example.com", 443, 200, "fp2")
        now = datetime.now(UTC)
        from_date = (now + timedelta(days=5)).isoformat()
        to_date = (now + timedelta(days=15)).isoformat()
        result = list_calendar(db, from_date=from_date, to_date=to_date, bucket="day")
        total = sum(b["count"] for b in result)
        assert total == 1  # only the 10-day cert

    def test_invalid_bucket_defaults_to_month(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _add_cert(db, "h1.example.com", 443, 30, "fp1")
        result = list_calendar(db, bucket="invalid")
        assert len(result) >= 1  # should work, defaulted to month

    def test_only_leaf_certs(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        repo = SqliteCertificateRepository(db, hostname="h.example.com", port=443)
        repo.add(_make_leaf(days_valid=30, fingerprint="leaf_fp"))
        # Add a chain cert (is_leaf=False)
        chain = Certificate(
            subject="CN=chain",
            issuer="CN=CA",
            not_before=datetime.now(UTC),
            not_after=datetime.now(UTC) + timedelta(days=365),
            san_dns_names=[],
            fingerprint_sha256="chain_fp",
            raw_der=b"",
            is_leaf=False,
        )
        repo.add(chain)
        result = list_calendar(db, bucket="month")
        total = sum(b["count"] for b in result)
        assert total == 1  # only the leaf


# ---------- API ----------


class TestCalendarAPI:
    def test_calendar_endpoint(self, tmp_path, reload_app):
        from starlette.testclient import TestClient

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        _add_cert(db, "h1.example.com", 443, 30, "fp1")

        with TestClient(app_mod.app) as client:
            resp = client.get("/api/calendar")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bucket"] == "month"
        assert isinstance(data["buckets"], list)

    def test_calendar_with_bucket_param(self, tmp_path, reload_app):
        from starlette.testclient import TestClient

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        _add_cert(db, "h1.example.com", 443, 30, "fp1")

        with TestClient(app_mod.app) as client:
            resp = client.get("/api/calendar?bucket=day")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bucket"] == "day"

    def test_calendar_invalid_bucket_defaults(self, tmp_path, reload_app):
        from starlette.testclient import TestClient

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)

        with TestClient(app_mod.app) as client:
            resp = client.get("/api/calendar?bucket=year")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bucket"] == "month"  # defaulted

    def test_calendar_empty(self, tmp_path, reload_app):
        from starlette.testclient import TestClient

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)

        with TestClient(app_mod.app) as client:
            resp = client.get("/api/calendar")
        assert resp.status_code == 200
        assert resp.json()["buckets"] == []
