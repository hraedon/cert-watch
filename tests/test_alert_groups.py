"""Tests for alert groups (Plan 015): repo, routing, API, acceptance criteria."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.alerts import (
    evaluate_all_certs,
    evaluate_thresholds,
    resolve_all_group_recipients,
    resolve_group_recipients,
    resolve_group_thresholds,
)
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    Role,
    SqliteAlertGroupRepository,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteRoleRepository,
    init_schema,
)

# ---------- helpers ----------

def _make_cert(
    repo: SqliteCertificateRepository,
    *,
    fingerprint: str = "aa" * 32,
    not_after: datetime | None = None,
    subject: str = "CN=test.example.com",
) -> str:
    cert = Certificate(
        subject=subject,
        issuer="CN=issuer",
        not_before=datetime.now(UTC) - timedelta(days=360),
        not_after=not_after or (datetime.now(UTC) + timedelta(days=5)),
        san_dns_names=["test.example.com"],
        fingerprint_sha256=fingerprint,
        raw_der=b"\x00" * 10,
        is_leaf=True,
    )
    return repo.add(cert)


# ---------- fixtures ----------

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    init_schema(db)
    return db


@pytest.fixture
def group_repo(db_path: Path) -> SqliteAlertGroupRepository:
    return SqliteAlertGroupRepository(db_path)


# ---------- Repository CRUD ----------

class TestAlertGroupRepository:
    def test_create_and_get(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("web-team", ["a@b.com", "c@d.com"], ["web", "prod"])
        g = group_repo.get(gid)
        assert g is not None
        assert g.name == "web-team"
        assert g.recipients == ["a@b.com", "c@d.com"]
        assert g.match_tags == ["web", "prod"]

    def test_get_by_name(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("infra", ["ops@co.com"], ["infra"])
        g = group_repo.get_by_name("infra")
        assert g is not None
        assert g.id == gid
        assert group_repo.get_by_name("nope") is None

    def test_list_all_ordered_by_name(self, group_repo: SqliteAlertGroupRepository):
        group_repo.create("bravo", ["b@b.com"], [])
        group_repo.create("alpha", ["a@a.com"], [])
        groups = group_repo.list_all()
        assert len(groups) == 2
        assert [g.name for g in groups] == ["alpha", "bravo"]

    def test_update(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("old-name", ["a@b.com"], ["web"])
        assert group_repo.update(gid, name="new-name", recipients=["x@y.com"]) is True
        g = group_repo.get(gid)
        assert g.name == "new-name"
        assert g.recipients == ["x@y.com"]
        assert g.match_tags == ["web"]  # unchanged

    def test_update_nonexistent(self, group_repo: SqliteAlertGroupRepository):
        assert group_repo.update("nope", name="x") is False

    def test_update_no_changes(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("g", ["a@b.com"], [])
        assert group_repo.update(gid) is True  # no-op

    def test_delete_cascades_certs(self, group_repo: SqliteAlertGroupRepository, db_path: Path):
        gid = group_repo.create("g", ["a@b.com"], [])
        cert_repo = SqliteCertificateRepository(db_path)
        cid = _make_cert(cert_repo)
        group_repo.assign_cert(gid, cid)
        assert group_repo.groups_for_cert_manual(cid) == [gid]
        assert group_repo.delete(gid) is True
        assert group_repo.get(gid) is None
        assert group_repo.groups_for_cert_manual(cid) == []

    def test_delete_nonexistent(self, group_repo: SqliteAlertGroupRepository):
        assert group_repo.delete("nope") is False

    def test_unique_name_enforced(self, group_repo: SqliteAlertGroupRepository):
        group_repo.create("dup", ["a@b.com"], [])
        with pytest.raises(sqlite3.IntegrityError):
            group_repo.create("dup", ["c@d.com"], [])

    def test_assign_unassign_cert(self, group_repo: SqliteAlertGroupRepository, db_path: Path):
        gid = group_repo.create("g", ["a@b.com"], [])
        cert_repo = SqliteCertificateRepository(db_path)
        cid = _make_cert(cert_repo)
        group_repo.assign_cert(gid, cid)
        assert group_repo.groups_for_cert_manual(cid) == [gid]
        group_repo.unassign_cert(gid, cid)
        assert group_repo.groups_for_cert_manual(cid) == []

    def test_assign_ignored_on_duplicate(
        self, group_repo: SqliteAlertGroupRepository, db_path: Path
    ):
        gid = group_repo.create("g", ["a@b.com"], [])
        cert_repo = SqliteCertificateRepository(db_path)
        cid = _make_cert(cert_repo)
        group_repo.assign_cert(gid, cid)
        group_repo.assign_cert(gid, cid)  # no error
        assert group_repo.groups_for_cert_manual(cid) == [gid]

    def test_recipients_normalized(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("g", [" a@b.com ", "a@b.com", "c@d.com"], [])
        g = group_repo.get(gid)
        assert g.recipients == ["a@b.com", "c@d.com"]

    def test_match_tags_normalized(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("g", ["a@b.com"], [" Web ", "web", "Prod"])
        g = group_repo.get(gid)
        assert g.match_tags == ["Web", "Prod"]


# ---------- Routing ----------

class TestAlertGroupRouting:
    def _setup_cert_with_tags(self, db_path: Path) -> str:
        """Create a host + cert with tags, return cert_id."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="team-web, prod")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)
        cert_repo.set_tags(cert_id, "pci")
        return cert_id

    def test_tag_match_routes_to_group(self, db_path: Path):
        """AC-3: cert with effective tags matching a group gets group recipients."""
        cert_id = self._setup_cert_with_tags(db_path)
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("web-team", ["web@co.com"], ["team-web"])

        recipients = resolve_group_recipients(db_path, cert_id)
        assert "web@co.com" in recipients

    def test_manual_assignment_routes_regardless_of_tags(self, db_path: Path):
        """AC-4: manual assignment routes even without tag match."""
        cert_id = self._setup_cert_with_tags(db_path)
        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create("special", ["special@co.com"], ["nonexistent-tag"])
        group_repo.assign_cert(gid, cert_id)

        recipients = resolve_group_recipients(db_path, cert_id)
        assert "special@co.com" in recipients

    def test_no_match_returns_empty(self, db_path: Path):
        """AC-5: cert matching no group returns empty recipients."""
        cert_id = self._setup_cert_with_tags(db_path)
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("other", ["other@co.com"], ["unrelated"])

        recipients = resolve_group_recipients(db_path, cert_id)
        assert recipients == []

    def test_no_groups_defined_returns_empty(self, db_path: Path):
        """AC-6: no groups defined → empty recipients (backward compatible)."""
        cert_id = self._setup_cert_with_tags(db_path)
        recipients = resolve_group_recipients(db_path, cert_id)
        assert recipients == []

    def test_inherited_host_tag_drives_routing(self, db_path: Path):
        """AC-1 dependency: host tag inheritance drives group routing."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="team-infra")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)
        # Cert has no own tags, but inherits team-infra from host
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("infra-team", ["infra@co.com"], ["team-infra"])

        recipients = resolve_group_recipients(db_path, cert_id)
        assert "infra@co.com" in recipients

    def test_deduped_across_groups(self, db_path: Path):
        """Recipients appearing in multiple groups are de-duped."""
        cert_id = self._setup_cert_with_tags(db_path)
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("g1", ["shared@co.com"], ["team-web"])
        group_repo.create("g2", ["shared@co.com", "extra@co.com"], ["prod"])

        recipients = resolve_group_recipients(db_path, cert_id)
        assert recipients.count("shared@co.com") == 1
        assert "extra@co.com" in recipients

    def test_evaluate_all_certs_merges_group_and_owner(self, db_path: Path):
        """evaluate_all_certs merges group recipients with owner_email."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add(
            "h.example.com", 443,
            tags="team-web",
            owner_name="Alice",
            owner_email="alice@co.com",
        )
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        _make_cert(cert_repo)
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("web-team", ["webteam@co.com"], ["team-web"])

        alert_repo = SqliteAlertRepository(db_path)
        alerts = evaluate_all_certs(db_path, alert_repo)
        assert len(alerts) > 0
        for a in alerts:
            assert "webteam@co.com" in a.extra_recipients
            assert "alice@co.com" in a.extra_recipients

    def test_evaluate_all_certs_no_groups_uses_owner_only(self, db_path: Path):
        """Without groups, extra_recipients is just owner_email (backward compat)."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add(
            "h.example.com", 443,
            owner_email="alice@co.com",
        )
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        _make_cert(cert_repo)

        alert_repo = SqliteAlertRepository(db_path)
        alerts = evaluate_all_certs(db_path, alert_repo)
        assert len(alerts) > 0
        for a in alerts:
            assert a.extra_recipients == ["alice@co.com"]

    def test_evaluate_thresholds_accepts_extra_recipients(self, db_path: Path):
        """evaluate_thresholds uses passed extra_recipients when provided."""
        alert_repo = SqliteAlertRepository(db_path)
        cert = Certificate(
            subject="CN=test",
            issuer="CN=issuer",
            not_before=datetime.now(UTC) - timedelta(days=360),
            not_after=datetime.now(UTC) + timedelta(days=5),
            san_dns_names=["test.example.com"],
            fingerprint_sha256="bb" * 32,
            raw_der=b"\x00" * 10,
            is_leaf=True,
        )
        alerts = evaluate_thresholds(
            cert, alert_repo, extra_recipients=["group@co.com"]
        )
        assert len(alerts) > 0
        for a in alerts:
            assert a.extra_recipients == ["group@co.com"]


# ---------- API ----------

class TestAlertGroupAPI:
    def test_list_empty(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/alert-groups")
        assert r.status_code == 200
        assert r.json()["groups"] == []

    def test_create_and_get(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "web-team",
                "recipients": ["a@b.com"],
                "match_tags": ["web"],
            })
            assert r.status_code == 201, r.text
            data = r.json()
            assert data["name"] == "web-team"
            gid = data["id"]

            g = client.get(f"/api/alert-groups/{gid}")
            assert g.status_code == 200
            assert g.json()["recipients"] == ["a@b.com"]

    def test_create_duplicate_name_returns_409(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            client.post("/api/alert-groups", json={
                "name": "dup", "recipients": ["a@b.com"], "match_tags": [],
            })
            r = client.post("/api/alert-groups", json={
                "name": "dup", "recipients": ["c@d.com"], "match_tags": [],
            })
            assert r.status_code == 409

    def test_create_bad_body(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "", "recipients": [], "match_tags": [],
            })
            assert r.status_code == 400
            r2 = client.post("/api/alert-groups", json={"recipients": [], "match_tags": []})
            assert r2.status_code == 400
            r3 = client.post("/api/alert-groups", json={
                "name": "g", "recipients": ["not-an-email"], "match_tags": [],
            })
            assert r3.status_code == 400

    def test_patch(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g", "recipients": ["a@b.com"], "match_tags": ["web"],
            })
            gid = r.json()["id"]
            p = client.patch(f"/api/alert-groups/{gid}", json={
                "name": "g2", "recipients": ["x@y.com"],
            })
            assert p.status_code == 200
            assert p.json()["name"] == "g2"
            assert p.json()["recipients"] == ["x@y.com"]
            assert p.json()["match_tags"] == ["web"]  # unchanged

    def test_patch_duplicate_name_409(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            client.post("/api/alert-groups", json={
                "name": "a", "recipients": ["a@b.com"], "match_tags": [],
            })
            r2 = client.post("/api/alert-groups", json={
                "name": "b", "recipients": ["c@d.com"], "match_tags": [],
            })
            gid_b = r2.json()["id"]
            p = client.patch(f"/api/alert-groups/{gid_b}", json={"name": "a"})
            assert p.status_code == 409

    def test_delete(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g", "recipients": ["a@b.com"], "match_tags": [],
            })
            gid = r.json()["id"]
            d = client.delete(f"/api/alert-groups/{gid}")
            assert d.status_code == 200
            g = client.get(f"/api/alert-groups/{gid}")
            assert g.status_code == 404

    def test_delete_not_found(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            d = client.delete("/api/alert-groups/00000000-0000-0000-0000-000000000000")
            assert d.status_code == 404

    def test_assign_and_unassign_cert(self, reload_app, tmp_path, leaf_pem_file):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        from cert_watch.upload import store_uploaded, upload_certificate

        store_uploaded(upload_certificate(leaf_pem_file), db)
        with sqlite3.connect(str(db)) as conn:
            cert_id = conn.execute("SELECT id FROM certificates LIMIT 1").fetchone()[0]

        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g", "recipients": ["a@b.com"], "match_tags": [],
            })
            gid = r.json()["id"]

            a = client.post(f"/api/alert-groups/{gid}/certs/{cert_id}")
            assert a.status_code == 200
            assert a.json()["status"] == "assigned"

            u = client.delete(f"/api/alert-groups/{gid}/certs/{cert_id}")
            assert u.status_code == 200
            assert u.json()["status"] == "unassigned"

    def test_assign_group_not_found(self, reload_app):
        app_mod = reload_app()
        _MISSING = "00000000-0000-0000-0000-000000000000"
        with TestClient(app_mod.app) as client:
            r = client.post(f"/api/alert-groups/{_MISSING}/certs/{_MISSING}")
            assert r.status_code == 404

    def test_assign_cert_not_found(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g", "recipients": ["a@b.com"], "match_tags": [],
            })
            gid = r.json()["id"]
            a = client.post(f"/api/alert-groups/{gid}/certs/00000000-0000-0000-0000-000000000000")
            assert a.status_code == 404

    def test_alert_routing_preview(self, reload_app, tmp_path, leaf_pem_file):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        from cert_watch.upload import store_uploaded, upload_certificate

        store_uploaded(upload_certificate(leaf_pem_file), db)
        with sqlite3.connect(str(db)) as conn:
            cert_id = conn.execute("SELECT id FROM certificates LIMIT 1").fetchone()[0]

        with TestClient(app_mod.app) as client:
            # Create a group
            client.post("/api/alert-groups", json={
                "name": "g", "recipients": ["a@b.com"], "match_tags": [],
            })
            r = client.get(f"/api/certificates/{cert_id}/alert-routing")
            assert r.status_code == 200
            data = r.json()
            assert data["cert_id"] == cert_id
            assert "effective_tags" in data
            assert "matched_groups" in data
            assert "recipients" in data

    def test_alert_routing_not_found(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/certificates/00000000-0000-0000-0000-000000000000/alert-routing")
            assert r.status_code == 404

    def test_alert_routing_non_leaf_returns_empty(self, reload_app, tmp_path, chain_pem_file):
        """Non-leaf (chain) certs get an empty, consistent preview (WI-085)."""
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        from cert_watch.upload import store_uploaded, upload_certificate

        store_uploaded(upload_certificate(chain_pem_file), db)
        with sqlite3.connect(str(db)) as conn:
            # Pick a non-leaf cert (intermediate or root)
            row = conn.execute(
                "SELECT id FROM certificates WHERE is_leaf = 0 LIMIT 1"
            ).fetchone()
            assert row is not None
            cert_id = row[0]

        with TestClient(app_mod.app) as client:
            client.post("/api/alert-groups", json={
                "name": "g", "recipients": ["a@b.com"], "match_tags": [],
            })
            r = client.get(f"/api/certificates/{cert_id}/alert-routing")
            assert r.status_code == 200
            data = r.json()
            assert data["matched_groups"] == []
            assert data["recipients"] == []
            assert "note" in data

    def test_list_groups(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            client.post("/api/alert-groups", json={
                "name": "alpha", "recipients": ["a@b.com"], "match_tags": [],
            })
            client.post("/api/alert-groups", json={
                "name": "bravo", "recipients": ["c@d.com"], "match_tags": [],
            })
            r = client.get("/api/alert-groups")
            assert r.status_code == 200
            groups = r.json()["groups"]
            assert len(groups) == 2
            assert groups[0]["name"] == "alpha"


# ---------- Per-group threshold & digest config (WI-056) ----------


class TestAlertGroupConfig:
    def test_create_with_threshold_days(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create(
            "ops", ["ops@co.com"], ["infra"],
            threshold_days=10, digest_cadence_days=14,
        )
        g = group_repo.get(gid)
        assert g is not None
        assert g.threshold_days == 10
        assert g.digest_cadence_days == 14

    def test_create_defaults(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("web", ["a@b.com"], ["web"])
        g = group_repo.get(gid)
        assert g is not None
        assert g.threshold_days is None
        assert g.digest_cadence_days == 7

    def test_update_threshold_days(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("g", ["a@b.com"], [], threshold_days=10)
        group_repo.update(gid, threshold_days=5)
        g = group_repo.get(gid)
        assert g.threshold_days == 5

    def test_update_clear_threshold_days(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("g", ["a@b.com"], [], threshold_days=10)
        group_repo.update(gid, threshold_days=None)
        g = group_repo.get(gid)
        assert g.threshold_days is None

    def test_update_digest_cadence_days(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("g", ["a@b.com"], [], digest_cadence_days=7)
        group_repo.update(gid, digest_cadence_days=14)
        g = group_repo.get(gid)
        assert g.digest_cadence_days == 14

    def test_update_no_changes_leaves_config(self, group_repo: SqliteAlertGroupRepository):
        gid = group_repo.create("g", ["a@b.com"], [], threshold_days=10, digest_cadence_days=14)
        group_repo.update(gid)
        g = group_repo.get(gid)
        assert g.threshold_days == 10
        assert g.digest_cadence_days == 14

    def test_get_by_name_includes_config(self, group_repo: SqliteAlertGroupRepository):
        group_repo.create("g", ["a@b.com"], [], threshold_days=20, digest_cadence_days=30)
        g = group_repo.get_by_name("g")
        assert g is not None
        assert g.threshold_days == 20
        assert g.digest_cadence_days == 30

    def test_list_all_includes_config(self, group_repo: SqliteAlertGroupRepository):
        group_repo.create("a", ["a@b.com"], [], threshold_days=5)
        group_repo.create("b", ["b@b.com"], [])
        groups = group_repo.list_all()
        by_name = {g.name: g for g in groups}
        assert by_name["a"].threshold_days == 5
        assert by_name["b"].threshold_days is None


class TestGroupThresholdOverride:
    def test_resolve_group_thresholds_returns_matching(self, db_path: Path):
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="team-web")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("web-team", ["web@co.com"], ["team-web"], threshold_days=10)

        result = resolve_group_thresholds(db_path)
        assert cert_id in result
        assert result[cert_id] == 10

    def test_resolve_group_thresholds_ignores_null(self, db_path: Path):
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="team-web")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("web-team", ["web@co.com"], ["team-web"])

        result = resolve_group_thresholds(db_path)
        assert cert_id not in result

    def test_resolve_group_thresholds_picks_most_urgent(self, db_path: Path):
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="team-web, prod")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("web-team", ["a@co.com"], ["team-web"], threshold_days=20)
        group_repo.create("prod-team", ["b@co.com"], ["prod"], threshold_days=5)

        result = resolve_group_thresholds(db_path)
        assert result[cert_id] == 5

    def test_evaluate_all_certs_uses_group_threshold(self, db_path: Path):
        host_repo = SqliteHostRepository(db_path)
        host_repo.add(
            "h.example.com", 443,
            tags="team-web",
            owner_email="owner@co.com",
        )
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        _make_cert(cert_repo, not_after=datetime.now(UTC) + timedelta(days=8))
        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create(
            "web-team", ["web@co.com"], ["team-web"], threshold_days=10,
        )

        alert_repo = SqliteAlertRepository(db_path)
        alerts = evaluate_all_certs(db_path, alert_repo)
        assert len(alerts) > 0
        assert any(a.threshold_days == 10 for a in alerts)

    def test_evaluate_all_certs_without_group_uses_default(self, db_path: Path):
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, owner_email="owner@co.com")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        _make_cert(cert_repo, not_after=datetime.now(UTC) + timedelta(days=8))

        alert_repo = SqliteAlertRepository(db_path)
        alerts = evaluate_all_certs(db_path, alert_repo)
        for a in alerts:
            assert a.threshold_days in (14, 7, 3, 1)


class TestDigestCadence:
    def test_build_renewal_digest_cadence_days(self, db_path: Path):
        """cadence_days controls the lookback window for renewal events."""
        from cert_watch.database.connection import _connect, _iso
        from cert_watch.digest import build_renewal_digest

        # Seed a cert_renewed event 10 days ago
        event_ts = _iso(datetime.now(UTC) - timedelta(days=10))
        with _connect(db_path) as conn:
            conn.execute(
                "INSERT INTO event_log (event_type, timestamp, source, payload, created_at) "
                "VALUES ('cert_renewed', ?, '', ?, ?)",
                (event_ts, '{"hostname": "h.example.com"}', event_ts),
            )

        # With cadence_days=14, the event 10 days ago is inside the window
        result_14 = build_renewal_digest(db_path, cadence_days=14)
        assert len(result_14) > 0
        assert any("h.example.com" in d.renewed_hosts for d in result_14)

        # With cadence_days=5, the event 10 days ago is outside the window
        result_5 = build_renewal_digest(db_path, cadence_days=5)
        assert result_5 == []

    def test_build_renewal_digest_default_days(self, db_path: Path):
        """Default days=7 includes events within the last 7 days."""
        from cert_watch.database.connection import _connect, _iso
        from cert_watch.digest import build_renewal_digest

        # Seed a cert_renewed event 3 days ago
        event_ts = _iso(datetime.now(UTC) - timedelta(days=3))
        with _connect(db_path) as conn:
            conn.execute(
                "INSERT INTO event_log (event_type, timestamp, source, payload, created_at) "
                "VALUES ('cert_renewed', ?, '', ?, ?)",
                (event_ts, '{"hostname": "h2.example.com"}', event_ts),
            )

        result = build_renewal_digest(db_path)
        assert len(result) > 0
        assert any("h2.example.com" in d.renewed_hosts for d in result)


class TestAlertGroupConfigAPI:
    def test_create_with_config(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "ops",
                "recipients": ["ops@co.com"],
                "match_tags": ["infra"],
                "threshold_days": 10,
                "digest_cadence_days": 14,
            })
            assert r.status_code == 201, r.text
            data = r.json()
            assert data["threshold_days"] == 10
            assert data["digest_cadence_days"] == 14

    def test_create_with_null_threshold(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
                "threshold_days": None,
            })
            assert r.status_code == 201, r.text
            data = r.json()
            assert data["threshold_days"] is None
            assert data["digest_cadence_days"] == 7

    def test_create_defaults(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
            })
            assert r.status_code == 201
            data = r.json()
            assert data["threshold_days"] is None
            assert data["digest_cadence_days"] == 7

    def test_create_invalid_threshold(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
                "threshold_days": 0,
            })
            assert r.status_code == 400

            r2 = client.post("/api/alert-groups", json={
                "name": "g2",
                "recipients": ["a@b.com"],
                "match_tags": [],
                "threshold_days": -5,
            })
            assert r2.status_code == 400

    def test_create_invalid_digest_cadence(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
                "digest_cadence_days": 0,
            })
            assert r.status_code == 400

    def test_patch_config(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
            })
            gid = r.json()["id"]

            p = client.patch(f"/api/alert-groups/{gid}", json={
                "threshold_days": 10,
                "digest_cadence_days": 14,
            })
            assert p.status_code == 200
            data = p.json()
            assert data["threshold_days"] == 10
            assert data["digest_cadence_days"] == 14

    def test_patch_clear_threshold(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
                "threshold_days": 10,
            })
            gid = r.json()["id"]

            p = client.patch(f"/api/alert-groups/{gid}", json={
                "threshold_days": None,
            })
            assert p.status_code == 200
            assert p.json()["threshold_days"] is None

    def test_patch_invalid_threshold(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
            })
            gid = r.json()["id"]

            p = client.patch(f"/api/alert-groups/{gid}", json={
                "threshold_days": 0,
            })
            assert p.status_code == 400

    def test_get_includes_config(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
                "threshold_days": 10,
                "digest_cadence_days": 14,
            })
            gid = r.json()["id"]

            g = client.get(f"/api/alert-groups/{gid}")
            assert g.status_code == 200
            data = g.json()
            assert data["threshold_days"] == 10
            assert data["digest_cadence_days"] == 14

    def test_list_includes_config(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            client.post("/api/alert-groups", json={
                "name": "g",
                "recipients": ["a@b.com"],
                "match_tags": [],
                "threshold_days": 10,
            })
            r = client.get("/api/alert-groups")
            groups = r.json()["groups"]
            assert len(groups) == 1
            assert groups[0]["threshold_days"] == 10


# ---------- Per-cert == batch resolution (WI-085) ----------


class TestPerCertMatchesBatchResolution:
    def test_per_cert_matches_batch_resolution(self, db_path: Path):
        """Property test: resolve_group_recipients(cert) == resolve_all_group_recipients()[cert].

        Enforces that the per-cert path (now a thin wrapper over the batch path)
        cannot diverge from the batch resolver across all routing modes:
        tag-match (host + cert-level), manual-assignment, role-link, and no-match.
        """
        host_repo = SqliteHostRepository(db_path)
        group_repo = SqliteAlertGroupRepository(db_path)
        role_repo = SqliteRoleRepository(db_path)

        # --- alert groups with different match_tags ---
        group_repo.create("tag-group", ["tag@co.com"], ["team-web"])
        gid_manual = group_repo.create(
            "manual-group", ["manual@co.com"], ["nonexistent-tag"]
        )
        gid_role = group_repo.create("role-group", ["role@co.com"], ["unrelated"])
        group_repo.create("lonely", ["lonely@co.com"], ["never-matches"])

        # --- cert 1: matches a group by inherited host tag (team-web) ---
        host_repo.add("tag-host.example.com", 443, tags="team-web")
        cert_repo_tag = SqliteCertificateRepository(
            db_path, hostname="tag-host.example.com", port=443
        )
        cid_tag = _make_cert(cert_repo_tag, fingerprint="11" * 32)

        # --- cert 2: matches a group by cert-level tag (prod) ---
        host_repo.add("certtag-host.example.com", 443, tags="")
        cert_repo_certtag = SqliteCertificateRepository(
            db_path, hostname="certtag-host.example.com", port=443
        )
        cid_certtag = _make_cert(cert_repo_certtag, fingerprint="22" * 32)
        cert_repo_certtag.set_tags(cid_certtag, "prod")
        group_repo.create("prod-group", ["prod@co.com"], ["prod"])

        # --- cert 3: manually assigned to a group (no tag match) ---
        host_repo.add("manual-host.example.com", 443, tags="")
        cert_repo_manual = SqliteCertificateRepository(
            db_path, hostname="manual-host.example.com", port=443
        )
        cid_manual = _make_cert(cert_repo_manual, fingerprint="33" * 32)
        group_repo.assign_cert(gid_manual, cid_manual)

        # --- cert 4: matches a role-link (scope_tag=epic → role-group) ---
        host_repo.add("role-host.example.com", 443, tags="epic")
        cert_repo_role = SqliteCertificateRepository(
            db_path, hostname="role-host.example.com", port=443
        )
        cid_role = _make_cert(cert_repo_role, fingerprint="44" * 32)
        role_repo.add(Role(
            name="epic-team",
            permission_tier="viewer",
            scope_tag="epic",
            alert_group_id=gid_role,
        ))

        # --- cert 5: matches nothing (empty list) ---
        host_repo.add("nomatch-host.example.com", 443, tags="orphan")
        cert_repo_none = SqliteCertificateRepository(
            db_path, hostname="nomatch-host.example.com", port=443
        )
        cid_none = _make_cert(cert_repo_none, fingerprint="55" * 32)

        # --- the property: per-cert == batch for every leaf cert ---
        batch = resolve_all_group_recipients(db_path)
        for cert_id in (cid_tag, cid_certtag, cid_manual, cid_role, cid_none):
            per_cert = resolve_group_recipients(db_path, cert_id)
            assert per_cert == batch.get(cert_id, []), (
                f"divergence for {cert_id}: "
                f"per_cert={per_cert!r} batch={batch.get(cert_id, [])!r}"
            )

        # sanity: each routing mode actually exercised (guards against a vacuous pass)
        assert "tag@co.com" in batch[cid_tag]
        assert "prod@co.com" in batch[cid_certtag]
        assert "manual@co.com" in batch[cid_manual]
        assert "role@co.com" in batch[cid_role]
        assert batch.get(cid_none, []) == []


# ── Alert-group admin gate ──────────────────────────────────────────────────


class TestAlertGroupAdminGate:
    """Alert-group mutations must require admin, not just write."""

    def test_create_alert_group_imports_admin(self):
        import inspect

        from cert_watch.routes.api.alerts import api_create_alert_group

        source = inspect.getsource(api_create_alert_group)
        assert "require_admin_write" in source, (
            "Alert-group creation should require admin write, not just write"
        )

    def test_delete_alert_group_imports_admin(self):
        import inspect

        from cert_watch.routes.api.alerts import api_delete_alert_group

        source = inspect.getsource(api_delete_alert_group)
        assert "require_admin_write" in source
