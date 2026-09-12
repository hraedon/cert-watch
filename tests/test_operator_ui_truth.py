"""Operator controls describe the delivery and verification actually provided."""

from fastapi.testclient import TestClient

from cert_watch.database import SqliteAlertGroupRepository, init_schema, store_scan_posture
from cert_watch.upload import store_uploaded, upload_certificate


def test_group_ui_preserves_legacy_webhook_when_edit_omits_control(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteAlertGroupRepository(db)
    stored_url = "https://hooks.example.test/legacy-private-token"
    group_id = repo.create("legacy", ["ops@example.test"], ["old-tag"], stored_url)
    with TestClient(app_mod.app) as client:
        response = client.post(
            f"/settings/alert-groups/{group_id}",
            data={"name": "renamed", "recipients": "team@example.test", "match_tags": "new-tag"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        group = repo.get(group_id)
        assert group.name == "renamed"
        assert group.webhook_url == stored_url
        page = client.get("/settings/alert-groups")
    assert page.status_code == 200
    assert 'name="webhook_url"' not in page.text
    assert "legacy webhook value is stored" in page.text
    assert "delivery does not use it" in page.text
    assert stored_url not in page.text
    assert 'href="/settings/channels"' in page.text


def test_group_ui_describes_additive_email_routes_and_global_webhook(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        page = client.get("/settings/alert-groups")
    assert page.status_code == 200
    assert 'name="webhook_url"' not in page.text
    assert "in addition to global SMTP recipients" in page.text
    assert "Group webhooks are not used for delivery" in page.text


def test_explicit_legacy_webhook_clear_still_works(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteAlertGroupRepository(db)
    group_id = repo.create("legacy", [], [], "https://hooks.example.test/stored-value")
    with TestClient(app_mod.app) as client:
        response = client.post(
            f"/settings/alert-groups/{group_id}",
            data={"name": "legacy", "webhook_url": ""}, follow_redirects=False,
        )
    assert response.status_code == 303
    assert repo.get(group_id).webhook_url == ""


def test_channels_label_global_routes_and_endpoint_reachability(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        page = client.get("/settings/channels")
    assert page.status_code == 200
    assert "Global SMTP recipients" in page.text
    assert "SMTP fails or is not configured" in page.text
    assert "OCSP/CRL endpoint reachability" in page.text
    assert "does not determine whether a certificate is revoked" in page.text
    assert "to flag revoked certificates" not in page.text


def test_detail_describes_reachability_without_claiming_revocation_status(
    reload_app, tmp_path, chain_pem_file,
):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(chain_pem_file), db)
    store_scan_posture(db, cert_id, None, None, "B", [])
    with TestClient(app_mod.app) as client:
        page = client.get(f"/certificates/{cert_id}")
    assert page.status_code == 200
    assert 'id="check-revocation"' in page.text  # Existing client/API wiring stays compatible.
    assert "Check endpoint reachability" in page.text
    assert "does not determine whether this certificate is revoked" in page.text
    assert "Check revocation</button>" not in page.text
