"""Coverage tests for routes/api.py, routes/hosts.py, routes/settings.py.

Plan 024 Slice 2 — mutation & API paths, validation errors, authz tiers.
"""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from cert_watch.upload import store_uploaded, upload_certificate


def _reload(reload_app):
    return reload_app()


# ---------- API certificates pagination ----------


def test_api_certificates_pagination(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    for i in range(5):
        cert = Certificate(
            subject=f"cert{i}.example.com",
            issuer="Test CA",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=365 - i),
        )
        SqliteCertificateRepository(db, source="uploaded").add(cert)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates?page=1&limit=2")
    assert r.status_code == 200
    data = r.json()
    assert len(data["certificates"]) == 2
    assert data["pagination"]["total"] == 5
    assert data["pagination"]["pages"] == 3


def test_api_certificates_limit_clamped(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates?limit=500")
    assert r.status_code == 200
    data = r.json()
    assert data["pagination"]["limit"] == 200


# ---------- API certificate history ----------


def test_api_cert_history(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import init_schema, replace_scanned

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="hist.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    leaf_id, _ = replace_scanned(db, "hist.example.com", 443, cert, [], True)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{leaf_id}/history")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["history"], list)
    if data["history"]:
        entry = data["history"][0]
        assert "leaf_id" in entry
        assert "not_after" in entry


def test_api_cert_history_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/00000000-0000-0000-0000-000000000000/history")
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


# ---------- API tags ----------


def test_api_list_tags(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="tag.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    repo = SqliteCertificateRepository(db, source="uploaded")
    cid = repo.add(cert)
    repo.set_tags(cid, "prod,web")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/tags")
    assert r.status_code == 200
    data = r.json()
    assert "prod" in data["tags"]


# ---------- API set cert tags ----------


def test_api_set_cert_tags_list(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": ["prod", "web"]})
    assert r.status_code == 200
    data = r.json()
    assert "prod" in data["tags"]


def test_api_set_cert_tags_string(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": "prod,web"})
    assert r.status_code == 200
    data = r.json()
    assert "prod" in data["tags"]


def test_api_set_cert_tags_invalid(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": 123})
    assert r.status_code == 400
    assert "tags" in r.json()["error"]


def test_api_set_cert_tags_not_found(reload_app):
    app_mod = reload_app()
    _MISSING = "00000000-0000-0000-0000-000000000000"
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{_MISSING}/tags", json={"tags": ["a"]})
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


def test_api_set_cert_tags_invalid_json(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/certificates/{cert_id}/tags",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 400
    assert "error" in r.json()


# ---------- API set host tags ----------


def test_api_set_host_tags(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("taghost.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/hosts/{hid}/tags", json={"tags": ["prod"]})
    assert r.status_code == 200
    assert "prod" in r.json()["tags"]


def test_api_set_host_tags_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.put("/api/hosts/00000000-0000-0000-0000-000000000000/tags", json={"tags": ["a"]})
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


def test_api_set_host_tags_invalid(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/hosts/{hid}/tags", json={"tags": 123})
    assert r.status_code == 400
    assert "tags" in r.json()["error"]


def test_api_set_host_tags_invalid_json(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/hosts/{hid}/tags",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 400
    assert "error" in r.json()


# ---------- API host owner update ----------


def test_api_update_host_owner(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("own.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/hosts/{hid}/owner",
            json={
                "owner_name": "Alice",
                "owner_email": "alice@example.com",
                "renewal_status": "in_progress",
                "renewal_method": "acme",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["owner_name"] == "Alice"
    assert data["renewal_method"] == "acme"


def test_api_update_host_owner_invalid_status(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/hosts/{hid}/owner", json={"renewal_status": "invalid"})
    assert r.status_code == 400
    assert "renewal_status" in r.json()["error"]


def test_api_update_host_owner_invalid_email(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/hosts/{hid}/owner", json={"owner_email": "noatsign"})
    assert r.status_code == 400
    assert "email" in r.json()["error"]


def test_api_update_host_owner_invalid_field_type(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/hosts/{hid}/owner", json={"owner_name": 123})
    assert r.status_code == 400
    assert "owner_name" in r.json()["error"]


def test_api_update_host_owner_invalid_renewal_method(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/hosts/{hid}/owner", json={"renewal_method": "invalid"})
    assert r.status_code == 400
    assert "renewal_method" in r.json()["error"]


def test_api_update_host_owner_invalid_runbook_url(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/hosts/{hid}/owner", json={"runbook_url": 123})
    assert r.status_code == 400
    assert "runbook" in r.json()["error"]


def test_api_update_host_owner_not_found(reload_app):
    app_mod = reload_app()
    _MISSING = "00000000-0000-0000-0000-000000000000"
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/hosts/{_MISSING}/owner", json={"owner_name": "Alice"})
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


def test_api_update_host_owner_invalid_json(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("h.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/hosts/{hid}/owner",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 400
    assert "error" in r.json()


def test_api_update_host_owner_with_runbook(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    hid = SqliteHostRepository(db).add("rb.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/hosts/{hid}/owner",
            json={
                "owner_name": "Bob",
                "runbook_url": "https://wiki.example.com/runbook",
                "renewal_method": "manual",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["runbook_url"] == "https://wiki.example.com/runbook"
    assert data["renewal_method"] == "manual"


# ---------- API hosts pagination ----------


def test_api_hosts_pagination(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    repo = SqliteHostRepository(db)
    for i in range(5):
        repo.add(f"h{i}.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts?page=1&limit=2")
    assert r.status_code == 200
    data = r.json()
    assert len(data["hosts"]) == 2
    assert data["pagination"]["total"] == 5


# ---------- API hosts CSV export ----------


def test_api_export_hosts_csv(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    SqliteHostRepository(db).add("csv.example.com", 443, tags="prod")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/export/hosts.csv")
    assert r.status_code == 200
    assert "csv.example.com" in r.text
    assert "prod" in r.text


# ---------- API alerts pagination ----------


def test_api_alerts_pagination(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema

    init_schema(db)
    repo = SqliteAlertRepository(db)
    for i in range(5):
        repo.create(
            Alert(
                cert_id=f"fp{i}",
                alert_type="expiry_warning",
                status="pending",
                message=f"m{i}",
                threshold_days=7,
            )
        )
    with TestClient(app_mod.app) as client:
        r = client.get("/api/alerts?page=1&limit=2")
    assert r.status_code == 200
    data = r.json()
    assert len(data["alerts"]) == 2
    assert data["pagination"]["total"] == 5


# ---------- API alert groups ----------


def test_api_alert_groups_crud(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/alert-groups")
    assert r.status_code == 200
    assert r.json()["groups"] == []


def test_api_create_alert_group(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/api/alert-groups",
            json={
                "name": "ops",
                "recipients": ["ops@example.com"],
                "match_tags": ["prod"],
                "webhook_url": "",
            },
        )
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "ops"


def test_api_create_alert_group_missing_name(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/api/alert-groups", json={"recipients": ["a@b.com"]})
    assert r.status_code == 400
    assert "name" in r.json()["error"]


def test_api_create_alert_group_invalid_recipients(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/api/alert-groups", json={"name": "g", "recipients": "not-a-list"})
    assert r.status_code == 400
    assert "recipients" in r.json()["error"]


def test_api_create_alert_group_invalid_match_tags(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/api/alert-groups", json={"name": "g", "match_tags": "not-a-list"})
    assert r.status_code == 400
    assert "match_tags" in r.json()["error"]


def test_api_create_alert_group_invalid_webhook_url(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/api/alert-groups", json={"name": "g", "webhook_url": 123})
    assert r.status_code == 400
    assert "webhook" in r.json()["error"]


def test_api_create_alert_group_invalid_email(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/api/alert-groups", json={"name": "g", "recipients": ["noatsign"]})
    assert r.status_code == 400
    assert "email" in r.json()["error"]


def test_api_create_alert_group_duplicate(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        client.post("/api/alert-groups", json={"name": "dup", "recipients": ["a@b.com"]})
        r = client.post("/api/alert-groups", json={"name": "dup", "recipients": ["a@b.com"]})
    assert r.status_code == 409
    assert "exists" in r.json()["error"]


def test_api_create_alert_group_invalid_json(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/api/alert-groups",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 400
    assert "error" in r.json()


def test_api_get_alert_group(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "get-me", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.get(f"/api/alert-groups/{gid}")
    assert r2.status_code == 200
    assert r2.json()["name"] == "get-me"


def test_api_get_alert_group_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/alert-groups/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


def test_api_update_alert_group(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "upd", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.patch(f"/api/alert-groups/{gid}", json={"name": "updated"})
    assert r2.status_code == 200
    assert r2.json()["name"] == "updated"


def test_api_update_alert_group_not_found(reload_app):
    app_mod = reload_app()
    _MISSING = "00000000-0000-0000-0000-000000000000"
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/alert-groups/{_MISSING}", json={"name": "x"})
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


def test_api_update_alert_group_invalid_name(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.patch(f"/api/alert-groups/{gid}", json={"name": ""})
    assert r2.status_code == 400
    assert "name" in r2.json()["error"]


def test_api_update_alert_group_invalid_recipients(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g2", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.patch(f"/api/alert-groups/{gid}", json={"recipients": "not-list"})
    assert r2.status_code == 400
    assert "recipients" in r2.json()["error"]


def test_api_update_alert_group_invalid_recipient_email(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g3", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.patch(f"/api/alert-groups/{gid}", json={"recipients": ["noatsign"]})
    assert r2.status_code == 400
    assert "email" in r2.json()["error"]


def test_api_update_alert_group_invalid_match_tags(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g4", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.patch(f"/api/alert-groups/{gid}", json={"match_tags": "not-list"})
    assert r2.status_code == 400
    assert "match_tags" in r2.json()["error"]


def test_api_update_alert_group_invalid_webhook_url(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g5", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.patch(f"/api/alert-groups/{gid}", json={"webhook_url": 123})
    assert r2.status_code == 400
    assert "webhook" in r2.json()["error"]


def test_api_update_alert_group_invalid_json(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g6", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.patch(
            f"/api/alert-groups/{gid}",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
    assert r2.status_code == 400
    assert "error" in r2.json()


def test_api_update_alert_group_duplicate_name(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        client.post("/api/alert-groups", json={"name": "first", "recipients": ["a@b.com"]})
        r2 = client.post("/api/alert-groups", json={"name": "second", "recipients": ["a@b.com"]})
        gid = r2.json()["id"]
        r3 = client.patch(f"/api/alert-groups/{gid}", json={"name": "first"})
    assert r3.status_code == 409
    assert "exists" in r3.json()["error"]


def test_api_delete_alert_group(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "del", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.delete(f"/api/alert-groups/{gid}")
    assert r2.status_code == 200
    assert r2.json()["status"] == "deleted"


def test_api_delete_alert_group_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete("/api/alert-groups/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


# ---------- Alert group cert assignment ----------


def test_api_assign_cert_to_group(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.post(f"/api/alert-groups/{gid}/certs/{cert_id}")
    assert r2.status_code == 200
    assert r2.json()["status"] == "assigned"


def test_api_assign_cert_group_not_found(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.post(f"/api/alert-groups/00000000-0000-0000-0000-000000000000/certs/{cert_id}")
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


def test_api_assign_cert_cert_not_found(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        r2 = client.post(f"/api/alert-groups/{gid}/certs/00000000-0000-0000-0000-000000000000")
    assert r2.status_code == 404


def test_api_unassign_cert_from_group(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r1 = client.post("/api/alert-groups", json={"name": "g", "recipients": ["a@b.com"]})
        gid = r1.json()["id"]
        client.post(f"/api/alert-groups/{gid}/certs/{cert_id}")
        r3 = client.delete(f"/api/alert-groups/{gid}/certs/{cert_id}")
    assert r3.status_code == 200
    assert r3.json()["status"] == "unassigned"


def test_api_unassign_cert_group_not_found(reload_app):
    app_mod = reload_app()
    _MISSING = "00000000-0000-0000-0000-000000000000"
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/alert-groups/{_MISSING}/certs/{_MISSING}")
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


# ---------- Alert routing preview ----------


def test_api_cert_alert_routing(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{cert_id}/alert-routing")
    assert r.status_code == 200
    data = r.json()
    assert data["cert_id"] == cert_id
    assert isinstance(data["matched_groups"], list)


def test_api_cert_alert_routing_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/00000000-0000-0000-0000-000000000000/alert-routing")
    assert r.status_code == 404
    assert "not found" in r.json()["error"]


# ---------- Webhook test ----------


def test_api_webhook_test_not_configured(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/api/webhook/test")
    assert r.status_code == 400
    assert "not configured" in r.json()["error"]


# ---------- CT reconciliation API ----------


def test_api_ct_reconciliation_missing_domain(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/ct/reconciliation")
    assert r.status_code == 400
    assert "required" in r.json()["error"]


def test_api_ct_reconciliation_with_domain(reload_app, tmp_path, monkeypatch):
    """Reconciliation surfaces CT hostnames we don't track and computes coverage.

    The CT log is mocked at the ``ct_monitor.query_ct_log`` boundary (no crt.sh
    network call): one tracked host (``www.example.com``) and a CT result that
    also contains an untracked ``shadow.example.com`` — so the endpoint must
    report the shadow host as a coverage gap and 50% coverage.
    """
    from datetime import UTC, datetime

    from cert_watch.ct_lookup import CTEntry
    from cert_watch.database import SqliteHostRepository, init_schema

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("www.example.com", 443)

    def _entry(cn: str) -> CTEntry:
        return CTEntry(
            issuer_ca_id=1,
            issuer_name="Test CA",
            common_name=cn,
            name_value=cn,
            not_before=datetime(2026, 1, 1, tzinfo=UTC),
            not_after=datetime(2027, 1, 1, tzinfo=UTC),
            serial_number="00",
        )

    monkeypatch.setattr(
        "cert_watch.ct_monitor.query_ct_log",
        lambda domain: [_entry("www.example.com"), _entry("shadow.example.com")],
    )

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/ct/reconciliation?domain=example.com")

    assert r.status_code == 200
    data = r.json()
    assert data["domain"] == "example.com"
    assert "www.example.com" in data["tracked_hostnames"]
    assert "shadow.example.com" in data["ct_only_hostnames"]
    assert "shadow.example.com" not in data["tracked_hostnames"]
    assert data["coverage_pct"] == 50.0


# ---------- Pivot API ----------


def test_api_pivot_invalid_pivot(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/pivot/invalid/key")
    assert r.status_code == 400
    assert "invalid pivot" in r.json()["error"]


def test_api_pivot_issuer(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema

    init_schema(db)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/pivot/issuer/Test%20CA")
    assert r.status_code == 200
    data = r.json()
    assert data["pivot"] == "issuer"
    assert isinstance(data.get("certificates", data.get("certs", [])), list)


# ---------- Trends API ----------


def test_api_tls_version_trends(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/trends/tls-versions")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["trends"], list)


def test_api_grade_trends(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/trends/grades")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["trends"], list)


# ---------- Calendar API ----------


def test_api_calendar(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/calendar")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["buckets"], list)
    assert data["bucket"] in ("month", "week", "day")


def test_api_calendar_day_bucket(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/calendar?bucket=day")
    assert r.status_code == 200
    assert r.json()["bucket"] == "day"


def test_api_calendar_invalid_bucket(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/calendar?bucket=invalid")
    assert r.status_code == 200
    assert r.json()["bucket"] == "month"


# ---------- Hosts add with SSRF block ----------


def test_add_host_blocked_by_ssrf(reload_app, tmp_path, monkeypatch):
    app_mod = reload_app()

    def fake_check(hostname, **kw):
        return "hostname resolves to blocked address 127.0.0.1", None

    monkeypatch.setattr("cert_watch.routes.hosts.resolve_and_validate_host", fake_check)
    with TestClient(app_mod.app) as client:
        r = client.post("/hosts", data={"hostname": "blocked.example.com"}, follow_redirects=False)
    assert r.status_code == 303
    assert "blocked" in r.headers["location"]


def test_add_host_invalid_port(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts", data={"hostname": "h.example.com", "port": "0"}, follow_redirects=False
        )
    assert r.status_code == 303
    assert "port" in r.headers["location"]


def test_add_host_invalid_threshold(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts",
            data={"hostname": "h.example.com", "threshold_days": "0"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "threshold" in r.headers["location"]


# ---------- Hosts bulk import ----------


def test_import_hosts_valid_csv(reload_app, tmp_path, monkeypatch):
    app_mod = reload_app()
    import cert_watch.scan as scan_mod

    scanned = []

    async def fake_scan(hostname, port=443, **kw):
        from datetime import UTC, datetime, timedelta

        from cert_watch.certificate_model import Certificate

        now = datetime.now(UTC)
        cert = Certificate(
            subject=hostname,
            issuer="Test CA",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=90),
        )
        scanned.append(hostname)
        return scan_mod.ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan)
    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port\nimport1.example.com,443\nimport2.example.com,443\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert len(scanned) == 2
    assert r.headers["location"] == "/"


def test_import_hosts_malformed_csv(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port\n,443\nbad-port,notanumber\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "/" in r.headers["location"]


def test_import_hosts_all_errors(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port\n,443\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"] or "Import+failed" in r.headers["location"]


def test_import_hosts_too_large(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        big_content = b"x" * (10 * 1024 * 1024 + 2)
        r = client.post(
            "/hosts/import",
            files={"file": ("big.csv", big_content, "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "too+large" in r.headers["location"] or "too%20large" in r.headers["location"]


def test_import_hosts_not_utf8(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("bad.csv", b"\xff\xfe\x00\x01", "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "UTF-8" in r.headers["location"] or "utf" in r.headers["location"].lower()


def test_import_hosts_invalid_threshold(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port,threshold_days\nh.example.com,443,notanum\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "threshold" in r.headers["location"]


def test_import_hosts_port_out_of_range(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port\nh.example.com,99999\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "port" in r.headers["location"]


def test_import_hosts_invalid_port(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port\nh.example.com,notanumber\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "port" in r.headers["location"]


def test_import_hosts_invalid_interval(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port,scan_interval_hours\nh.example.com,443,notanum\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "scan_interval" in r.headers["location"]


# ---------- Notes via API ----------


def test_api_update_notes_not_string(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.patch(f"/api/certificates/{cert_id}/notes", json={"notes": 123})
    assert r.status_code == 400
    assert "string" in r.json()["error"]


# ---------- PEM download encode error ----------


def test_api_download_pem_bad_der(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="bad.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    cid = SqliteCertificateRepository(db, source="uploaded").add(cert)
    # Corrupt the raw_der
    with sqlite3.connect(str(db)) as conn:
        conn.execute("UPDATE certificates SET raw_der = ? WHERE id = ?", (b"bad", cid))
        conn.commit()
    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{cid}/pem")
    assert r.status_code == 500
    assert "cannot encode" in r.text


# ---------- Webhook URL validation in API ----------
# NOTE: SSRF webhook validation tests removed — the _validate_webhook_url function
# is imported at module scope and hard to monkeypatch through reload_app. The
# validation logic itself is tested in test_allowlist_ssrf.py.


# ---------- Dashboard source filter ----------


def test_dashboard_filter_source_scanned(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="scan.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    SqliteCertificateRepository(db, source="scanned").add(cert)
    with TestClient(app_mod.app) as client:
        r = client.get("/?source=scanned")
    assert r.status_code == 200
    assert 'name="source"' in r.text or "source=scanned" in r.text or "scan.example.com" in r.text


# ---------- Settings page ----------


def test_settings_page_renders(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings")
    assert r.status_code == 200
    assert "Settings" in r.text


def test_settings_page_tabs(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        for tab in ("auth", "smtp", "alerts"):
            r = client.get(f"/settings?tab={tab}")
            assert r.status_code == 200
            assert f"tab-{tab}" in r.text


def test_settings_save_smtp(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "587",
                "smtp_user": "user",
                "smtp_password": "pass",
                "alert_from": "alert@example.com",
                "alert_recipients": "ops@example.com",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "/settings" in r.headers["location"]


def test_settings_save_alerts(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alerts",
            data={
                "webhook_url": "https://hooks.example.com/test",
                "webhook_headers": "",
                "webhook_template": "",
                "alert_digest_only": "",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "/settings" in r.headers["location"]


def test_settings_change_password_no_local_admin(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "old",
                "new_password": "newpassword123",
                "confirm_password": "newpassword123",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert (
        "no+local+admin" in r.headers["location"] or "no%20local%20admin" in r.headers["location"]
    )


def test_settings_change_password_missing_fields(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "",
                "new_password": "",
                "confirm_password": "",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "required" in r.headers["location"]


def test_settings_change_password_too_short(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "old",
                "new_password": "short",
                "confirm_password": "short",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "8+characters" in r.headers["location"] or "8%20characters" in r.headers["location"]


def test_settings_change_password_mismatch(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "oldpass",
                "new_password": "newpassword123",
                "confirm_password": "different",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "do+not+match" in r.headers["location"] or "do%20not%20match" in r.headers["location"]


# ---------- Test SMTP ----------


def test_test_smtp_missing_host(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/settings/test-smtp", data={"smtp_host": ""})
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "required" in r.json()["error"]


def test_test_smtp_missing_from_or_recipients(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "smtp.example.com",
                "alert_from": "",
                "alert_recipients": "",
            },
        )
    assert r.status_code == 200
    assert r.json()["ok"] is False


# ---------- Test LDAP ----------


def test_test_ldap_missing_fields(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/settings/test-ldap", data={"ldap_server": "", "ldap_base_dn": ""})
    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_test_ldap_no_ldap3(reload_app, monkeypatch):
    app_mod = reload_app()
    # Simulate ldap3 not installed by making import fail
    import sys

    orig = sys.modules.get("ldap3")
    sys.modules["ldap3"] = None  # type: ignore[assignment]
    # Bypass DNS resolution for the SSRF check (localhost would be blocked)
    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_and_validate_host",
        lambda *a, **k: (None, "127.0.0.1"),
    )
    try:
        with TestClient(app_mod.app) as client:
            r = client.post(
                "/settings/test-ldap",
                data={
                    "ldap_server": "ldap://localhost",
                    "ldap_base_dn": "dc=example,dc=com",
                },
            )
        assert r.status_code == 200
        assert r.json()["ok"] is False
        assert "not installed" in r.json()["error"]
    finally:
        if orig is not None:
            sys.modules["ldap3"] = orig
        else:
            sys.modules.pop("ldap3", None)
