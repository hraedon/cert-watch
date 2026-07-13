"""Tests for the triage work queue + horizon queries and page (Plan 053)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.app import app
from cert_watch.database.connection import _connect
from cert_watch.database.schema import init_schema
from cert_watch.database.triage import (
    count_failed_alerts_24h,
    list_critical_certs,
    list_expired_certs,
    list_expiry_horizon,
    list_failed_scans,
    list_renewal_stalls,
)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _insert_host(conn, hostname: str, port: int = 443, tags: str = "") -> str:
    host_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO hosts (id, hostname, port, tags, added_at) VALUES (?, ?, ?, ?, ?)",
        (host_id, hostname, port, tags, _iso(datetime.now(UTC))),
    )
    conn.commit()
    return host_id


def _insert_cert(
    conn,
    hostname: str | None,
    days_remaining: int,
    *,
    port: int = 443,
    subject: str | None = None,
    source: str = "scanned",
    tags: str = "",
) -> str:
    cert_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    not_after = now + timedelta(days=days_remaining, hours=12)
    conn.execute(
        """INSERT INTO certificates
           (id, subject, issuer, not_before, not_after, san_dns_names,
            fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
            tags, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
        (
            cert_id,
            subject or f"CN={hostname or 'uploaded.example.com'},O=Test Org",
            "CN=Test CA,O=Test Org",
            _iso(now - timedelta(days=300)),
            _iso(not_after),
            "[]",
            f"fp-{cert_id[:12]}",
            b"",
            source,
            hostname,
            port if hostname else None,
            tags,
            _iso(now),
            _iso(now),
        ),
    )
    conn.commit()
    return cert_id


def _insert_scan(
    conn, hostname: str, port: int, status: str, *,
    error: str | None = None, hours_ago: float = 0,
) -> None:
    conn.execute(
        "INSERT INTO scan_history (id, hostname, port, status, scanned_at, error_message)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()), hostname, port, status,
            _iso(datetime.now(UTC) - timedelta(hours=hours_ago)), error,
        ),
    )
    conn.commit()


def _insert_alert(conn, status: str, *, hours_ago: float = 0) -> None:
    conn.execute(
        "INSERT INTO alerts (id, cert_id, alert_type, status, message, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()), str(uuid.uuid4()), "expiry", status, "msg",
            _iso(datetime.now(UTC) - timedelta(hours=hours_ago)),
        ),
    )
    conn.commit()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "triage.sqlite3"
    init_schema(db)
    return db


class TestUrgentCerts:
    def test_expired_and_critical_buckets(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "old.example.com")
            _insert_host(conn, "soon.example.com")
            _insert_host(conn, "fine.example.com")
            _insert_cert(conn, "old.example.com", -5)
            _insert_cert(conn, "soon.example.com", 3)
            _insert_cert(conn, "fine.example.com", 50)

        expired = list_expired_certs(db_path)
        critical = list_critical_certs(db_path)

        assert [e["name"] for e in expired] == ["old.example.com"]
        assert expired[0]["days_remaining"] < 0
        assert [c["name"] for c in critical] == ["soon.example.com"]

    def test_expired_freshest_first(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "long-dead.example.com")
            _insert_host(conn, "just-died.example.com")
            _insert_cert(conn, "long-dead.example.com", -300)
            _insert_cert(conn, "just-died.example.com", -2)
        expired = list_expired_certs(db_path)
        assert [e["name"] for e in expired] == [
            "just-died.example.com", "long-dead.example.com",
        ]

    def test_uploaded_certs_included(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_cert(
                conn, None, -1, source="uploaded",
                subject="CN=uploaded-expired.example.com",
            )
        expired = list_expired_certs(db_path)
        assert [e["name"] for e in expired] == ["uploaded-expired.example.com"]
        assert expired[0]["host_id"] is None

    def test_tag_scoping(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "a.example.com", tags="team-a")
            _insert_host(conn, "b.example.com", tags="team-b")
            _insert_cert(conn, "a.example.com", -1)
            _insert_cert(conn, "b.example.com", -1)
        assert len(list_expired_certs(db_path)) == 2
        scoped = list_expired_certs(db_path, scope_tags=("team-a",))
        assert [e["name"] for e in scoped] == ["a.example.com"]


class TestHorizon:
    def test_clusters_by_day(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "one.example.com")
            _insert_host(conn, "two.example.com", port=8443)
            _insert_host(conn, "later.example.com")
            _insert_cert(conn, "one.example.com", 10)
            _insert_cert(conn, "two.example.com", 10, port=8443)
            _insert_cert(conn, "later.example.com", 40)

        horizon = list_expiry_horizon(db_path)
        assert [d["days"] for d in horizon] == [10, 40]
        assert horizon[0]["count"] == 2
        assert horizon[0]["urgency"] == "warning"
        assert horizon[1]["count"] == 1
        assert horizon[1]["urgency"] == "healthy"
        names = {c["name"] for c in horizon[0]["certs"]}
        assert names == {"one.example.com", "two.example.com"}

    def test_window_bounds(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "expired.example.com")
            _insert_host(conn, "beyond.example.com")
            _insert_cert(conn, "expired.example.com", -1)
            _insert_cert(conn, "beyond.example.com", 120)
        assert list_expiry_horizon(db_path) == []


class TestFailedScans:
    def test_latest_failure_surfaces(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "down.example.com")
            _insert_scan(conn, "down.example.com", 443, "success", hours_ago=2)
            _insert_scan(
                conn, "down.example.com", 443, "failure",
                error="Connection refused", hours_ago=1,
            )
        failed = list_failed_scans(db_path)
        assert len(failed) == 1
        assert failed[0]["hostname"] == "down.example.com"
        assert failed[0]["error_message"] == "Connection refused"

    def test_recovered_host_not_listed(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "flaky.example.com")
            _insert_scan(
                conn, "flaky.example.com", 443, "failure",
                error="timeout", hours_ago=2,
            )
            _insert_scan(conn, "flaky.example.com", 443, "success", hours_ago=1)
        assert list_failed_scans(db_path) == []

    def test_tag_scoping(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "a.example.com", tags="team-a")
            _insert_host(conn, "b.example.com", tags="team-b")
            _insert_scan(conn, "a.example.com", 443, "failure", error="x")
            _insert_scan(conn, "b.example.com", 443, "failure", error="x")
        scoped = list_failed_scans(db_path, scope_tags=("team-b",))
        assert [f["hostname"] for f in scoped] == ["b.example.com"]


class TestFailedAlerts:
    def test_counts_recent_failures_only(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_alert(conn, "failed", hours_ago=1)
            _insert_alert(conn, "failed", hours_ago=25)
            _insert_alert(conn, "sent", hours_ago=1)
        assert count_failed_alerts_24h(db_path) == 1


class TestRenewalStalls:
    def _seed_stalled_host(self, conn, hostname: str = "overdue.example.com") -> None:
        """Three 90-day certs renewed 30 days before expiry; current one 25
        days from expiry with no successor — past its usual renewal point."""
        now = datetime.now(UTC)
        for idx, scan_offset in enumerate((185, 125, 65)):
            scanned = now - timedelta(days=scan_offset)
            not_after = scanned + timedelta(days=90)
            conn.execute(
                """INSERT INTO cert_history
                   (id, hostname, port, fingerprint_sha256, issuer, not_after,
                    scanned_at, not_before)
                   VALUES (?, ?, 443, ?, ?, ?, ?, ?)""",
                (
                    str(uuid.uuid4()), hostname, f"fp-{idx}",
                    "CN=Let's Encrypt Authority X3",
                    _iso(not_after), _iso(scanned), _iso(scanned),
                ),
            )
        conn.commit()
        _insert_host(conn, hostname)
        _insert_cert(conn, hostname, 25)

    def test_stall_detected(self, db_path: Path):
        with _connect(db_path) as conn:
            self._seed_stalled_host(conn)
        stalls = list_renewal_stalls(db_path)
        assert len(stalls) == 1
        s = stalls[0]
        assert s["hostname"] == "overdue.example.com"
        assert s["days_overdue"] > 0
        assert s["confidence"] == "low"
        assert s["cert_id"]

    def test_healthy_cadence_not_stalled(self, db_path: Path):
        with _connect(db_path) as conn:
            _insert_host(conn, "fresh.example.com")
            _insert_cert(conn, "fresh.example.com", 55)
        assert list_renewal_stalls(db_path) == []


class TestTriagePage:
    def test_all_clear_when_empty(self):
        with TestClient(app) as client:
            r = client.get("/triage")
        assert r.status_code == 200
        assert 'data-testid="triage-heading"' in r.text
        assert 'data-testid="triage-all-clear"' in r.text
        assert "Nothing needs attention" in r.text

    def test_queue_sections_render(self, reload_app, tmp_path):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        with _connect(db) as conn:
            _insert_host(conn, "old.example.com")
            _insert_cert(conn, "old.example.com", -5)
            _insert_host(conn, "down.example.com")
            _insert_scan(
                conn, "down.example.com", 443, "failure",
                error="Connection refused",
            )
        with TestClient(app_mod.app) as client:
            r = client.get("/triage")
        assert r.status_code == 200
        assert 'data-testid="queue-expired"' in r.text
        assert 'data-testid="queue-failed-scans"' in r.text
        assert 'data-testid="triage-all-clear"' not in r.text
        assert "old.example.com" in r.text
        assert "Connection refused" in r.text
        # relative_short already prefixes past dates with "expired" — the
        # template must not add its own ("expired expired 5 days ago").
        assert "expired expired" not in r.text

    def test_timeline_markers_render(self, reload_app, tmp_path):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        with _connect(db) as conn:
            _insert_host(conn, "soon.example.com")
            _insert_cert(conn, "soon.example.com", 20)
        with TestClient(app_mod.app) as client:
            r = client.get("/triage")
        assert r.status_code == 200
        assert "cw-timeline-marker" in r.text
        assert "1 certificate expiring" in r.text

    def test_nav_link_present(self):
        with TestClient(app) as client:
            r = client.get("/")
        assert 'data-testid="nav-triage"' in r.text
