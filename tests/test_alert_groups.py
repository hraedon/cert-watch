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
    resolve_group_recipients,
)
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteAlertGroupRepository,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
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
        not_before=datetime.now(UTC),
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
            not_before=datetime.now(UTC),
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
