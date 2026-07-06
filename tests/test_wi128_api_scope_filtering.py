"""Regression tests for WI-128: API endpoints must respect scope-tag RBAC.

Each affected function/route must filter fleet-wide data by scope_tags so
scoped users only see their team's hosts/certs/events/trends.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.database import init_schema
from cert_watch.database.connection import _connect


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "wi128.sqlite3"
    init_schema(path)
    return path


def _insert_host(conn, hostname, port=443, tags=""):
    conn.execute(
        "INSERT INTO hosts (id, hostname, port, tags, added_at) VALUES (?, ?, ?, ?, ?)",
        (f"h-{hostname}", hostname, port, tags, datetime.now(UTC).isoformat()),
    )


def _insert_cert(conn, cert_id, hostname, port=443, tags="", source="scanned"):
    now = datetime.now(UTC)
    conn.execute(
        """
        INSERT INTO certificates
        (id, subject, issuer, not_before, not_after, san_dns_names,
         fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
         parent_cert_id, chain_valid, replaces_cert_id, notes, tags,
         created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cert_id, hostname, f"issuer-{hostname}",
            now.isoformat(), (now + timedelta(days=30)).isoformat(),
            "[]", f"fp-{cert_id}", b"der", source, hostname,
            port, 1, None, 1, None, "", tags,
            now.isoformat(), now.isoformat(),
        ),
    )


def _insert_event(conn, event_type, hostname, source="scan"):
    payload = json.dumps({"hostname": hostname, "cert_id": f"c-{hostname}"})
    conn.execute(
        "INSERT INTO event_log (event_type, timestamp, source, payload,"
        " delivery_status, error_message, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (event_type, datetime.now(UTC).isoformat(), source, payload,
         "delivered", None, datetime.now(UTC).isoformat()),
    )


def _insert_event_no_hostname(conn, event_type):
    payload = json.dumps({"cert_id": "admin-level"})
    conn.execute(
        "INSERT INTO event_log (event_type, timestamp, source, payload,"
        " delivery_status, error_message, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (event_type, datetime.now(UTC).isoformat(), "system", payload,
         "delivered", None, datetime.now(UTC).isoformat()),
    )


def _insert_cert_history(conn, hostname, port, fingerprint, issuer, protocol_version,
                         posture_grade, scanned_at, not_before, not_after):
    conn.execute(
        """INSERT INTO cert_history
           (id, hostname, port, fingerprint_sha256, issuer, not_after,
            key_algo, sig_algo, posture_grade, protocol_version, san_count,
            scanned_at, not_before)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (f"ch-{hostname}-{fingerprint[:8]}", hostname, port, fingerprint, issuer,
         not_after, "RSA", "SHA256", posture_grade, protocol_version, 1,
         scanned_at, not_before),
    )


def _insert_scan_posture(conn, cert_id, hostname, port, grade, chain_status, scanned_at):
    conn.execute(
        """INSERT INTO scan_posture
           (id, cert_id, hostname, port, grade, protocol_version, ocsp_stapling,
            hsts, must_staple, verify_requested, findings, scanned_at, chain_status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (f"sp-{cert_id}", cert_id, hostname, port, grade, "TLSv1.3", 0, 0, 0, 0,
         "[]", scanned_at, chain_status),
    )


def _seed_two_teams(db: Path) -> None:
    now = datetime.now(UTC)
    with _connect(db) as conn:
        _insert_host(conn, "host-a.example.com", tags="team-a")
        _insert_host(conn, "host-b.example.com", tags="team-b")
        _insert_cert(conn, "cert-a", "host-a.example.com", tags="team-a")
        _insert_cert(conn, "cert-b", "host-b.example.com", tags="team-b")
        _insert_event(conn, "cert_added", "host-a.example.com")
        _insert_event(conn, "cert_added", "host-b.example.com")
        _insert_event_no_hostname(conn, "posture_changed")
        for hn, port, fp, grade, cert_id in [
            ("host-a.example.com", 443, "fp-a1", "A", "cert-a"),
            ("host-b.example.com", 443, "fp-b1", "B", "cert-b"),
        ]:
            _insert_cert_history(
                conn, hn, port, fp, f"issuer-{hn}", "TLSv1.3", grade,
                now.isoformat(),
                (now - timedelta(days=60)).isoformat(),
                (now + timedelta(days=30)).isoformat(),
            )
            _insert_scan_posture(
                conn, cert_id, hn, port, grade, "public",
                now.isoformat(),
            )
        conn.commit()


# ── get_events ────────────────────────────────────────────────────────────


class TestEventsScopeFiltering:
    def test_scoped_sees_only_team_events(self, db: Path):
        from cert_watch.events import get_events

        _seed_two_teams(db)
        events = get_events(db, scope_tags=("team-a",))
        hostnames = {
            json.loads(e["payload"]).get("hostname")
            for e in events
            if e["payload"]
        }
        assert hostnames == {"host-a.example.com"}

    def test_scoped_excludes_events_without_hostname(self, db: Path):
        """Events without hostname and without a matching cert are excluded."""
        from cert_watch.events import get_events

        _seed_two_teams(db)
        events = get_events(db, scope_tags=("team-a",))
        cert_ids = {
            json.loads(e["payload"]).get("cert_id")
            for e in events
            if e["payload"]
        }
        assert "admin-level" not in cert_ids

    def test_scoped_sees_upload_event_via_cert_tags(self, db: Path):
        """WI-135: Events without hostname visible when cert tags match scope."""
        from cert_watch.events import get_events

        _seed_two_teams(db)
        with _connect(db) as conn:
            _insert_cert(conn, "cert-up-a", "", port=0, tags="team-a", source="uploaded")
            payload = json.dumps({"cert_id": "cert-up-a", "source": "upload"})
            conn.execute(
                "INSERT INTO event_log (event_type, timestamp, source, payload,"
                " delivery_status, error_message, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("cert_added", datetime.now(UTC).isoformat(), "upload", payload,
                 "delivered", None, datetime.now(UTC).isoformat()),
            )
            conn.commit()
        events = get_events(db, scope_tags=("team-a",))
        cert_ids = {
            json.loads(e["payload"]).get("cert_id")
            for e in events
            if e["payload"]
        }
        assert "cert-up-a" in cert_ids

    def test_scoped_excludes_upload_event_wrong_tag(self, db: Path):
        """WI-135: Events for certs with non-matching tags are excluded."""
        from cert_watch.events import get_events

        _seed_two_teams(db)
        with _connect(db) as conn:
            _insert_cert(conn, "cert-up-b", "", port=0, tags="team-b", source="uploaded")
            payload = json.dumps({"cert_id": "cert-up-b", "source": "upload"})
            conn.execute(
                "INSERT INTO event_log (event_type, timestamp, source, payload,"
                " delivery_status, error_message, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("cert_added", datetime.now(UTC).isoformat(), "upload", payload,
                 "delivered", None, datetime.now(UTC).isoformat()),
            )
            conn.commit()
        events = get_events(db, scope_tags=("team-a",))
        cert_ids = {
            json.loads(e["payload"]).get("cert_id")
            for e in events
            if e["payload"]
        }
        assert "cert-up-b" not in cert_ids

    def test_unscoped_sees_all_events(self, db: Path):
        from cert_watch.events import get_events

        _seed_two_teams(db)
        events = get_events(db, scope_tags=())
        assert len(events) == 3


# ── renewal analytics ─────────────────────────────────────────────────────


class TestRenewalAnalyticsScopeFiltering:
    def test_fleet_scoped_only_team_hosts(self, db: Path):
        from cert_watch.renewal_analytics import compute_fleet_analytics

        _seed_two_teams(db)
        fleet = compute_fleet_analytics(db, scope_tags=("team-a",))
        hostnames = {a.hostname for a in fleet}
        assert hostnames == {"host-a.example.com"}

    def test_fleet_unscoped_all_hosts(self, db: Path):
        from cert_watch.renewal_analytics import compute_fleet_analytics

        _seed_two_teams(db)
        fleet = compute_fleet_analytics(db, scope_tags=())
        hostnames = {a.hostname for a in fleet}
        assert hostnames == {"host-a.example.com", "host-b.example.com"}

    def test_host_scoped_denied_returns_empty(self, db: Path):
        from cert_watch.renewal_analytics import compute_host_analytics

        _seed_two_teams(db)
        analytics = compute_host_analytics(
            db, "host-b.example.com", scope_tags=("team-a",)
        )
        assert analytics.cert_count == 0

    def test_host_scoped_allowed_returns_data(self, db: Path):
        from cert_watch.renewal_analytics import compute_host_analytics

        _seed_two_teams(db)
        analytics = compute_host_analytics(
            db, "host-a.example.com", scope_tags=("team-a",)
        )
        assert analytics.cert_count >= 1


# ── pivot group entries ──────────────────────────────────────────────────


class TestPivotScopeFiltering:
    def test_pivot_scoped_only_team_entries(self, db: Path):
        from cert_watch.database import get_pivot_group_entries

        _seed_two_teams(db)
        in_scope = get_pivot_group_entries(
            db, "issuer", "issuer-host-a.example.com", scope_tags=("team-a",)
        )
        out_scope = get_pivot_group_entries(
            db, "issuer", "issuer-host-b.example.com", scope_tags=("team-a",)
        )
        assert len(in_scope) == 1
        assert len(out_scope) == 0

    def test_pivot_unscoped_all_entries(self, db: Path):
        from cert_watch.database import get_pivot_group_entries

        _seed_two_teams(db)
        a = get_pivot_group_entries(
            db, "issuer", "issuer-host-a.example.com", scope_tags=None
        )
        b = get_pivot_group_entries(
            db, "issuer", "issuer-host-b.example.com", scope_tags=None
        )
        assert len(a) == 1
        assert len(b) == 1


# ── trends ────────────────────────────────────────────────────────────────


class TestTrendsScopeFiltering:
    def test_tls_version_trends_scoped(self, db: Path):
        from cert_watch.database import list_tls_version_trends

        _seed_two_teams(db)
        trends = list_tls_version_trends(db, days=365, scope_tags=("team-a",))
        total = sum(t["count"] for t in trends)
        assert total == 1

    def test_tls_version_trends_unscoped(self, db: Path):
        from cert_watch.database import list_tls_version_trends

        _seed_two_teams(db)
        trends = list_tls_version_trends(db, days=365, scope_tags=())
        total = sum(t["count"] for t in trends)
        assert total == 2

    def test_grade_trends_scoped(self, db: Path):
        from cert_watch.database import list_grade_trends

        _seed_two_teams(db)
        trends = list_grade_trends(db, days=365, scope_tags=("team-b",))
        grades = {t["posture_grade"] for t in trends}
        assert grades == {"B"}

    def test_grade_trends_unscoped(self, db: Path):
        from cert_watch.database import list_grade_trends

        _seed_two_teams(db)
        trends = list_grade_trends(db, days=365, scope_tags=())
        total = sum(t["count"] for t in trends)
        assert total == 2


# ── calendar ──────────────────────────────────────────────────────────────


class TestCalendarScopeFiltering:
    def test_calendar_scoped_only_team_certs(self, db: Path):
        from cert_watch.database import list_calendar

        _seed_two_teams(db)
        buckets = list_calendar(db, bucket="month", scope_tags=("team-a",))
        total = sum(b["count"] for b in buckets)
        assert total == 1

    def test_calendar_unscoped_all_certs(self, db: Path):
        from cert_watch.database import list_calendar

        _seed_two_teams(db)
        buckets = list_calendar(db, bucket="month", scope_tags=())
        total = sum(b["count"] for b in buckets)
        assert total == 2

    def test_calendar_scoped_by_cert_tag(self, db: Path):
        from cert_watch.database import list_calendar

        with _connect(db) as conn:
            _insert_host(conn, "host-c.example.com")
            _insert_cert(conn, "cert-c", "host-c.example.com", tags="team-c")
            conn.commit()
        buckets = list_calendar(db, bucket="month", scope_tags=("team-c",))
        total = sum(b["count"] for b in buckets)
        assert total == 1

    def test_calendar_scoped_uploaded_cert_without_host(self, db: Path):
        """WI-136: Uploaded certs without a hosts row visible via cert tags."""
        from cert_watch.database import list_calendar

        with _connect(db) as conn:
            _insert_cert(conn, "cert-up", "", port=0, tags="team-a", source="uploaded")
            conn.commit()
        buckets = list_calendar(db, bucket="month", scope_tags=("team-a",))
        total = sum(b["count"] for b in buckets)
        assert total == 1

    def test_calendar_scoped_excludes_uploaded_cert_wrong_tag(self, db: Path):
        """WI-136: Uploaded certs with non-matching tags are excluded."""
        from cert_watch.database import list_calendar

        with _connect(db) as conn:
            _insert_cert(conn, "cert-up", "", port=0, tags="team-b", source="uploaded")
            conn.commit()
        buckets = list_calendar(db, bucket="month", scope_tags=("team-a",))
        total = sum(b["count"] for b in buckets)
        assert total == 0


# ── readiness ──────────────────────────────────────────────────────────────


class TestReadinessScopeFiltering:
    def test_readiness_scoped_only_team_hosts(self, db: Path):
        from cert_watch.readiness import build_readiness_report

        _seed_two_teams(db)
        report = build_readiness_report(db, scope_tags=("team-a",))
        hostnames = {h.hostname for h in report.hosts}
        hostnames |= {h.hostname for h in report.private_hosts}
        hostnames |= {h.hostname for h in report.unknown_hosts_list}
        assert hostnames == {"host-a.example.com"}
        assert report.total_hosts == 1

    def test_readiness_unscoped_all_hosts(self, db: Path):
        from cert_watch.readiness import build_readiness_report

        _seed_two_teams(db)
        report = build_readiness_report(db, scope_tags=())
        assert report.total_hosts == 2


# ── route-level tests ─────────────────────────────────────────────────────


def _make_scoped_app(db: Path, tmp_path: Path, *, scope_tag: str):
    from cert_watch.app import create_app
    from cert_watch.config import Settings
    from cert_watch.database import Role, SqliteRoleRepository

    role_repo = SqliteRoleRepository(db)
    role_repo.add(Role(name="global-op", permission_tier="operator", scope_tag=""))
    role_map = {"global-op": {"groups": ["op-grp"]}}
    groups = ["op-grp"]
    if scope_tag:
        role_repo.add(
            Role(name="team-role", permission_tier="viewer", scope_tag=scope_tag)
        )
        role_map["team-role"] = {"groups": ["team-grp"]}
        groups.append("team-grp")
    s = Settings(db_path=db, data_dir=tmp_path, role_map=role_map)

    class _Provider:
        provider_name = "mock"

    return create_app(auth_provider=_Provider(), settings=s), groups


def _scoped_client(app, groups):
    from fastapi.testclient import TestClient

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice", groups=groups)
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE, token)
    return client


class TestApiRoutesScopeFiltering:
    def test_api_events_scoped(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
        with _scoped_client(app, groups) as client:
            r = client.get("/api/events?limit=100")
        assert r.status_code == 200
        events = r.json()["events"]
        hostnames = {
            json.loads(e["payload"]).get("hostname")
            for e in events
            if e.get("payload")
        }
        assert hostnames == {"host-a.example.com"}

    def test_api_renewal_analytics_scoped(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
        with _scoped_client(app, groups) as client:
            r = client.get("/api/renewal-analytics")
        assert r.status_code == 200
        hostnames = {a["hostname"] for a in r.json()}
        assert hostnames == {"host-a.example.com"}

    def test_api_renewal_analytics_host_scoped_denied(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
        with _scoped_client(app, groups) as client:
            r = client.get("/api/renewal-analytics/host-b.example.com")
        assert r.status_code == 200
        assert r.json()["cert_count"] == 0

    def test_api_tls_version_trends_scoped(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
        with _scoped_client(app, groups) as client:
            r = client.get("/api/trends/tls-versions?days=365")
        assert r.status_code == 200
        total = sum(t["count"] for t in r.json()["trends"])
        assert total == 1

    def test_api_grade_trends_scoped(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-b")
        with _scoped_client(app, groups) as client:
            r = client.get("/api/trends/grades?days=365")
        assert r.status_code == 200
        grades = {t["posture_grade"] for t in r.json()["trends"]}
        assert grades == {"B"}

    def test_api_calendar_scoped(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
        with _scoped_client(app, groups) as client:
            r = client.get("/api/calendar")
        assert r.status_code == 200
        total = sum(b["count"] for b in r.json()["buckets"])
        assert total == 1

    def test_api_readiness_json_scoped(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
        with _scoped_client(app, groups) as client:
            r = client.get("/api/readiness.json")
        assert r.status_code == 200
        data = r.json()
        assert data["total_hosts"] == 1

    def test_readiness_view_scoped(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
        with _scoped_client(app, groups) as client:
            r = client.get("/readiness")
        assert r.status_code == 200

    def test_api_unscoped_sees_all(self, db: Path, tmp_path: Path):
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag="")
        with _scoped_client(app, groups) as client:
            r_evt = client.get("/api/events?limit=100")
            r_cal = client.get("/api/calendar")
            r_rd = client.get("/api/readiness.json")
        assert len(r_evt.json()["events"]) == 3
        assert sum(b["count"] for b in r_cal.json()["buckets"]) == 2
        assert r_rd.json()["total_hosts"] == 2
