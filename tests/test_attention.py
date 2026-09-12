"""Tests for the attention queue (attention.py) and the Home/Browse split."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
)
from cert_watch.database.repo import Alert
from tests._helpers import seed_scanned


def _mk_cert(seed: str, days: int) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={seed}.example.com",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=5),
        not_after=now + timedelta(days=days),
        san_dns_names=[f"{seed}.example.com"],
        fingerprint_sha256=(seed[:1] or "a") * 64,
    )


def _seed(db: Path, seed: str, days: int, *, renewal_method: str = "", owner: str = "") -> str:
    host = f"{seed}.example.com"
    repo = SqliteHostRepository(db)
    repo.add(host, 443, renewal_method=renewal_method, owner_name=owner)
    return seed_scanned(db, host, 443, _mk_cert(seed, days))


@pytest.fixture
def db(tmp_path: Path) -> Path:
    p = tmp_path / "cw.sqlite3"
    init_schema(p)
    return p


class TestQueueAssembly:
    def test_healthy_cert_not_queued(self, db: Path):
        from cert_watch.attention import build_attention_queue

        _seed(db, "ok", 90, renewal_method="acme")
        queue = build_attention_queue(db)
        assert len(queue) == 1
        assert queue[0]["kind"] == "chain_unknown"
        assert "issuer certificate" in queue[0]["reasons"][0]

    def test_expired_is_first(self, db: Path):
        from cert_watch.attention import build_attention_queue

        _seed(db, "warn", 20, renewal_method="manual")
        _seed(db, "gone", -3)
        q = build_attention_queue(db)
        assert q[0]["kind"] == "expired"
        assert q[0]["severity"] == "expired"
        # dashboard day math truncates ((not_after - now).days), so don't
        # pin the literal count here.
        assert q[0]["reasons"][0].startswith("expired ")
        assert q[0]["reasons"][0].endswith(" ago")

    def test_warning_manual_outranks_warning_auto(self, db: Path):
        from cert_watch.attention import build_attention_queue

        _seed(db, "auto", 20, renewal_method="acme")
        _seed(db, "manual", 20, renewal_method="manual")
        q = [i for i in build_attention_queue(db, window_days=0) if i["severity"] == "warning"]
        assert len(q) == 2
        assert q[0]["confidence"] == "manual"
        assert q[1]["confidence"] == "auto"
        assert q[0]["confidence_label"] == "manual renewal"

    def test_critical_under_seven_days(self, db: Path):
        from cert_watch.attention import build_attention_queue

        _seed(db, "crit", 5, renewal_method="acme")
        q = build_attention_queue(db, window_days=0)
        assert q[0]["severity"] == "critical"
        assert any(r.startswith("expires in ") for r in q[0]["reasons"])

    def test_pending_notification_does_not_duplicate_renewal_condition(self, db: Path):
        from cert_watch.attention import build_attention_queue

        cert_id = _seed(db, "stall", 20, renewal_method="acme")
        SqliteAlertRepository(db).create(
            Alert(
                cert_id=cert_id,
                alert_type="renewal_stalled",
                status="pending",
                message="stalled",
            )
        )
        q = build_attention_queue(db)
        stalled = [i for i in q if i["kind"] == "renewal_stalled"]
        assert len(stalled) == 1
        assert "renewal window" in stalled[0]["reasons"][0]
        # The same cert must not also appear as a plain expiry item.
        assert [i["cert_id"] for i in q].count(cert_id) == 1

    def test_grouped_stall_uses_affected_deployment(self, db: Path):
        from cert_watch.attention import build_attention_queue

        cert = _mk_cert("shared", 20)
        hosts = SqliteHostRepository(db)
        hosts.add("a.example.com", 443, renewal_method="acme", renewal_status="in_progress")
        hosts.add("z.example.com", 443, renewal_method="manual")
        first_id = seed_scanned(db, "a.example.com", 443, cert)
        affected_id = seed_scanned(db, "z.example.com", 443, cert)
        SqliteAlertRepository(db).create(
            Alert(
                cert_id=affected_id,
                alert_type="renewal_stalled",
                status="pending",
                message="stalled",
            )
        )

        stalled = [item for item in build_attention_queue(db) if item["kind"] == "renewal_stalled"]
        assert len(stalled) == 1
        assert stalled[0]["cert_id"] == affected_id
        assert stalled[0]["cert_id"] != first_id
        assert stalled[0]["host"] == "z.example.com:443"
        assert stalled[0]["confidence_label"] == "manual renewal"

    def test_configured_automation_is_not_claimed_as_observed(self, db: Path):
        from cert_watch.attention import build_attention_queue

        _seed(db, "auto-wording", 20, renewal_method="acme")
        item = build_attention_queue(db)[0]
        assert item["confidence_label"] == "automation configured"

    @pytest.mark.parametrize("days,severity", [(5, "critical"), (20, "warning")])
    def test_uploaded_expiry_has_replacement_guidance(self, db: Path, days: int, severity: str):
        from cert_watch.alerts import evaluate_renewal_window
        from cert_watch.attention import build_attention_queue

        cert_id = SqliteCertificateRepository(db, source="uploaded").add(_mk_cert("upload", days))
        # Preserve alert-engine compatibility while Home distinguishes a static
        # uploaded file from a monitored endpoint inside its renewal window.
        alerts = evaluate_renewal_window(db, SqliteAlertRepository(db))
        assert [alert.cert_id for alert in alerts] == [cert_id]

        item = build_attention_queue(db)[0]
        assert item["kind"] == "expiry"
        assert item["severity"] == severity
        assert item["host_id"] is None
        assert item["reasons"][-1] == "upload replacement certificate"
        assert "renewal unknown" not in item["reasons"]
        assert not any("renewal window" in reason for reason in item["reasons"])

    def test_deployment_endpoint_prefers_host_over_certificate_name(
        self, db: Path, monkeypatch
    ):
        import cert_watch.database as database
        from cert_watch.attention import build_attention_queue

        deployment = {
            "id": "cert-1",
            "kind": "scanned",
            "source": "scanned",
            "name": "*.example.com",
            "host": "api.example.com:443",
            "host_id": "host-1",
            "days_remaining": 20,
            "chain_status": "public",
            "renewal_method": "manual",
        }
        monkeypatch.setattr(
            database,
            "list_dashboard_grouped_page",
            lambda *args, **kwargs: ([{"kind": "grouped", "hosts": [deployment]}], 1),
        )

        item = build_attention_queue(db)[0]
        assert item["endpoint"] == "api.example.com:443"

    @pytest.mark.parametrize("delivery_status", [None, "pending", "sent", "failed"])
    def test_renewal_condition_does_not_depend_on_delivery_status(self, db: Path, delivery_status):
        from cert_watch.attention import build_attention_queue

        cert_id = _seed(db, "stall2", 20, renewal_method="acme")
        repo = SqliteAlertRepository(db)
        if delivery_status is not None:
            repo.create(Alert(
                cert_id=cert_id,
                alert_type="renewal_stalled",
                status=delivery_status,
                message="stalled",
            ))
        before = repo.list_for_cert(cert_id)
        items = [item for item in build_attention_queue(db) if item["cert_id"] == cert_id]
        assert len(items) == 1
        assert items[0]["kind"] == "renewal_stalled"
        assert items[0]["severity"] == "stalled"
        assert repo.list_for_cert(cert_id) == before  # Home only reads current state.

    @pytest.mark.parametrize("resolution", ["in_progress", "renewed", "successor"])
    def test_handled_condition_clears_despite_pending_notification(self, db: Path, resolution):
        from cert_watch.attention import build_attention_queue

        cert_id = _seed(db, "handled", 20, renewal_method="acme")
        SqliteAlertRepository(db).create(Alert(
            cert_id=cert_id, alert_type="renewal_stalled", status="pending", message="stalled",
        ))
        if resolution == "successor":
            SqliteCertificateRepository(
                db, source="scanned", hostname="handled.example.com", port=443,
                replaces_cert_id=cert_id,
            ).add(_mk_cert("successor", 300))
        else:
            with sqlite3_conn(db) as conn:
                conn.execute(
                    "UPDATE hosts SET renewal_status = ? WHERE hostname = ?",
                    (resolution, "handled.example.com"),
                )
                conn.commit()
        assert not any(item["kind"] == "renewal_stalled" for item in build_attention_queue(db))

    def test_scan_failing_host_queued(self, db: Path):
        from cert_watch.attention import build_attention_queue

        repo = SqliteHostRepository(db)
        repo.add("dead.example.com", 443)
        from datetime import UTC as _UTC

        from cert_watch.database.connection import _connect

        with _connect(db) as conn:
            conn.execute(
                "INSERT INTO scan_history (id, hostname, port, status, scanned_at, error_message)"
                " VALUES ('s1', 'dead.example.com', 443, 'failure', ?, 'connection refused')",
                (datetime.now(_UTC).isoformat(),),
            )
            conn.commit()
        q = build_attention_queue(db)
        assert q[0]["kind"] == "scan_failing"
        assert "connection refused" in q[0]["reasons"][0]

    def test_never_scanned_host_is_info(self, db: Path):
        from cert_watch.attention import build_attention_queue

        SqliteHostRepository(db).add("new.example.com", 443)
        q = build_attention_queue(db)
        assert q[0]["kind"] == "never_scanned"
        assert q[0]["severity"] == "info"

    def test_scope_tags_filter_queue(self, db: Path):
        from cert_watch.attention import build_attention_queue

        cert_id = _seed(db, "scoped", 5, renewal_method="manual")
        _seed(db, "other", 5, renewal_method="manual")
        with sqlite3_conn(db) as conn:
            conn.execute("UPDATE hosts SET tags = 'team-a' WHERE hostname = 'scoped.example.com'")
            conn.execute("UPDATE certificates SET tags = 'team-a' WHERE id = ?", (cert_id,))
            conn.commit()

        all_items = build_attention_queue(db)
        scoped_items = build_attention_queue(db, scope_tags=("team-a",))
        assert len(all_items) == 2
        assert len(scoped_items) == 1
        assert scoped_items[0]["endpoint"].startswith("scoped")


def sqlite3_conn(db: Path):
    import contextlib
    import sqlite3

    return contextlib.closing(sqlite3.connect(str(db)))


class TestHomeAndBrowseRoutes:
    @pytest.mark.parametrize("window_days", [0, 10, 30, 45])
    def test_home_uses_configured_renewal_window(self, tmp_path, window_days):
        from dataclasses import replace

        from cert_watch.app import create_app
        from cert_watch.config import Settings

        application = create_app(
            settings=replace(Settings.from_env(), renewal_window_days=window_days),
        )
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        cert_id = _seed(db, "window", 20, renewal_method="acme")
        SqliteAlertRepository(db).create(Alert(
            cert_id=cert_id, alert_type="renewal_stalled", status="pending", message="old notice",
        ))
        with TestClient(application) as client:
            response = client.get("/")
        assert response.status_code == 200
        assert ('data-severity="stalled"' in response.text) is (window_days >= 20)

    def test_home_renders_empty_state(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert 'data-testid="home-heading"' in r.text

    def test_legacy_filter_params_redirect_to_browse(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/?urgency=critical", follow_redirects=False)
        assert r.status_code == 307
        assert r.headers["location"].startswith("/browse")

    def test_browse_renders_inventory(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/browse")
        assert r.status_code == 200
        assert 'data-testid="dashboard-heading"' in r.text

    def test_home_shows_attention_item(self, reload_app, tmp_path):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        _seed(db, "crit", 4, renewal_method="manual", owner="ops")
        with TestClient(app_mod.app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert 'data-testid="attention-item"' in r.text
        assert "crit.example.com" in r.text
        assert "manual renewal" in r.text
        assert "ops" in r.text

    def test_home_tracked_summary_includes_expired_outside_future_horizon(
        self, reload_app, tmp_path
    ):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        _seed(db, "expired", -10)
        with TestClient(app_mod.app) as client:
            r = client.get("/")
        assert r.status_code == 200
        tracked = r.text.split('data-testid="home-tracked-stat"', 1)[1].split("</a>", 1)[0]
        assert '<div class="cw-stat-val">1</div>' in tracked
        assert "No expirations in the next 12 weeks" in r.text
