"""Uploaded notes have their own lifetime, authorization and upgrade path."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth.rbac import AuthContext
from cert_watch.auth.scope import MissingAuthContextError, ScopeDeniedError
from cert_watch.database import SqliteCertificateRepository, SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.services.resource_metadata import (
    ResourceMetadataNotFoundError,
    update_uploaded_certificate_notes,
)
from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate


@pytest.fixture
def upload(tmp_path, leaf_pem_file):
    db = tmp_path / "cert-watch.sqlite3"
    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    return db, store_uploaded(entry, db)


def _update(db: Path, cert_id: str, notes, *, auth=None):
    return update_uploaded_certificate_notes(
        db, cert_id, notes, auth=auth or AuthContext.system(),
        actor="test-operator", source_ip=None,
    )


def test_upload_notes_form_save_clear_and_escape(upload, reload_app):
    app = reload_app().app
    db, cert_id = upload
    text = "<script>alert('note')</script>\nrenew with the offline CA"
    with TestClient(app) as client:
        page = client.get(f"/certificates/{cert_id}")
        assert page.status_code == 200
        assert 'data-testid="certificate-notes"' in page.text
        assert 'data-testid="edit-certificate-notes"' in page.text
        assert 'name="_csrf_token"' in page.text
        saved = client.post(
            f"/certificates/{cert_id}/notes", data={"notes": text},
            follow_redirects=False,
        )
        assert saved.status_code == 303
        page = client.get(f"/certificates/{cert_id}")
        assert "&lt;script&gt;" in page.text
        assert "<script>alert('note')</script>" not in page.text
        assert client.get(f"/api/certificates/{cert_id}").json()["notes"] == text
        cleared = client.post(f"/certificates/{cert_id}/notes", data={"notes": ""})
        assert cleared.status_code == 200
    assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == ""
    assert SqliteHostRepository(db).list_all() == []


@pytest.mark.parametrize("notes", [None, 42, [], {}, "x" * 10001])
def test_invalid_json_notes_are_atomic(upload, reload_app, notes):
    app = reload_app().app
    db, cert_id = upload
    _update(db, cert_id, "keep me")
    with TestClient(app) as client:
        response = client.patch(f"/api/certificates/{cert_id}/notes", json={"notes": notes})
    assert response.status_code == 400
    assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == "keep me"
    with _connect(db) as conn:
        assert conn.execute(
            "SELECT count(*) FROM audit_log WHERE action='cert.update_notes'"
        ).fetchone()[0] == 1


@pytest.mark.parametrize("raw", ["not json", "[]", "null"])
def test_malformed_json_notes(upload, reload_app, raw):
    app = reload_app().app
    _, cert_id = upload
    with TestClient(app) as client:
        response = client.patch(
            f"/api/certificates/{cert_id}/notes", content=raw,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 400


def test_maximum_unicode_notes_and_audit_privacy(upload):
    db, cert_id = upload
    notes = "\N{SNOWMAN}" * 10000
    assert _update(db, cert_id, notes) == notes
    assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == notes
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT * FROM audit_log WHERE action='cert.update_notes'"
        ).fetchone()
        assert row is not None
        assert "10000" in str(dict(row))
        assert notes not in str(dict(row))


def test_form_validation_keeps_draft_and_previous_notes(upload, reload_app):
    app = reload_app().app
    db, cert_id = upload
    _update(db, cert_id, "original")
    with TestClient(app) as client:
        response = client.post(
            f"/certificates/{cert_id}/notes", data={"notes": "x" * 10001},
        )
    assert response.status_code == 400
    assert "x" * 10001 in response.text
    assert "notes too long" in response.text
    assert 'aria-invalid="true"' in response.text
    other_editor = re.search(r'<details\b[^>]*\bid="edit-host"[^>]*>', response.text)
    assert other_editor is not None and "open" not in other_editor.group().split()
    notes_editor = re.search(
        r'<details\b([^>]*)>\s*<summary[^>]*data-testid="edit-certificate-notes"', response.text,
    )
    assert notes_editor is not None and "open" in notes_editor.group(1).split()
    assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == "original"


def test_legacy_upload_editor_uses_certificate_scope(tmp_path, monkeypatch, csrf_strict):
    from tests.test_authz_characterization import (
        PRINCIPALS,
        _authenticate,
        _build_app,
        _csrf_header,
        _seed,
    )

    principal = next(p for p in PRINCIPALS if p.name == "operator-scoped-A")
    db = tmp_path / "cert-watch.sqlite3"
    seeded = _seed(db, principal)
    cert_id = seeded.ids["upload_a"]
    with _connect(db) as conn:
        host = conn.execute(
            "SELECT hostname, port FROM hosts WHERE id=?", (seeded.ids["host_b"],)
        ).fetchone()
        conn.execute(
            "UPDATE certificates SET hostname=?, port=? WHERE id=?",
            (host["hostname"], host["port"], cert_id),
        )
        conn.commit()
    with TestClient(_build_app(principal, tmp_path, monkeypatch)) as client:
        _authenticate(client, principal, seeded)
        response = client.patch(
            f"/api/certificates/{cert_id}/notes", json={"notes": "legacy upload note"},
            headers=_csrf_header(client),
        )
        assert response.status_code == 200
        page = client.get(f"/certificates/{cert_id}")
        assert page.status_code == 200
        assert 'data-testid="edit-certificate-notes"' in page.text
        assert 'data-testid="save-host"' not in page.text


def test_invalid_upload_notes_keep_legacy_host_editor_values(upload, reload_app):
    app = reload_app().app
    db, cert_id = upload
    SqliteHostRepository(db).add("leaf.example.com", notes="existing host runbook")
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET hostname='leaf.example.com', port=443 WHERE id=?", (cert_id,),
        )
        conn.commit()
    with TestClient(app) as client:
        page = client.post(f"/certificates/{cert_id}/notes", data={"notes": "x" * 10001})
    assert page.status_code == 400
    host_field = re.search(
        r'<textarea\b[^>]*\bid="host-notes"[^>]*>(.*?)</textarea>', page.text, re.DOTALL,
    )
    assert host_field is not None and host_field.group(1) == "existing host runbook"
    assert page.text.count('aria-invalid="true"') == 1
    assert page.text.count('data-testid="certificate-notes-editor"') == 1


def test_scanned_certificate_cannot_acquire_upload_notes(upload, reload_app):
    app = reload_app().app
    db, cert_id = upload
    host_id = SqliteHostRepository(db).add("leaf.example.com", 443, notes="host note")
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET source='scanned', hostname='leaf.example.com', port=443 "
            "WHERE id=?", (cert_id,),
        )
        conn.commit()
    with TestClient(app) as client:
        response = client.patch(
            f"/api/certificates/{cert_id}/notes", json={"notes": "certificate note"},
        )
        assert response.status_code == 400
        page = client.get(f"/certificates/{cert_id}")
        assert 'data-testid="certificate-notes"' not in page.text
        assert "host note" in page.text
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and host.notes == "host note"
    assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == ""


@pytest.mark.parametrize(
    ("scope", "tier", "allowed"),
    [("ops", "operator", True), ("other", "operator", False), ("ops", "viewer", False)],
)
def test_service_checks_target_scope_before_parsing(upload, scope, tier, allowed):
    db, cert_id = upload
    with _connect(db) as conn:
        conn.execute("UPDATE certificates SET tags='ops' WHERE id=?", (cert_id,))
        conn.commit()
    auth = AuthContext.from_tier("operator", tier, scope_tag=scope)
    parsed = []

    def value():
        parsed.append(True)
        return "scoped note"

    if allowed:
        assert _update(db, cert_id, value, auth=auth) == "scoped note"
        assert parsed == [True]
    else:
        with pytest.raises(ScopeDeniedError):
            _update(db, cert_id, value, auth=auth)
        assert parsed == []
        assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == ""


def test_service_requires_explicit_principal(upload):
    db, cert_id = upload
    with pytest.raises(MissingAuthContextError):
        update_uploaded_certificate_notes(
            db, cert_id, "note", auth=None, actor="operator", source_ip=None,
        )


def test_notes_and_audit_rollback_together(upload, monkeypatch):
    import cert_watch.services.resource_metadata as service

    db, cert_id = upload
    _update(db, cert_id, "original")

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("audit unavailable")

    monkeypatch.setattr(service, "record_audit", fail)
    with pytest.raises(sqlite3.OperationalError, match="audit unavailable"):
        _update(db, cert_id, "replacement")
    assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == "original"


def test_missing_target(upload, reload_app):
    app = reload_app().app
    db, _ = upload
    missing = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(ResourceMetadataNotFoundError):
        _update(db, missing, "note")
    with TestClient(app) as client:
        assert client.patch(
            f"/api/certificates/{missing}/notes", json={"notes": "note"},
        ).status_code == 404


def test_deleting_upload_cascades_notes(upload):
    db, cert_id = upload
    _update(db, cert_id, "delete me too")
    SqliteCertificateRepository(db).delete(cert_id)
    with _connect(db) as conn:
        assert conn.execute("SELECT * FROM uploaded_certificate_notes").fetchall() == []


@pytest.mark.parametrize("legacy_endpoint", [False, True])
def test_scanning_and_renewing_the_same_certificate_keeps_upload_notes(upload, legacy_endpoint):
    from cert_watch.certificate_model import parse_certificate
    from tests._helpers import seed_scanned
    from tests.conftest import _make_cert

    db, cert_id = upload
    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    assert cert is not None
    _update(db, cert_id, "belongs to the uploaded file")
    host_id = SqliteHostRepository(db).add("leaf.example.com", notes="endpoint runbook")
    if legacy_endpoint:
        with _connect(db) as conn:
            conn.execute(
                "UPDATE certificates SET hostname='leaf.example.com', port=443 WHERE id=?",
                (cert_id,),
            )
            conn.commit()
    scanned_id = seed_scanned(db, "leaf.example.com", 443, cert)
    seed_scanned(db, "leaf.example.com", 443, cert)
    replacement = parse_certificate(_make_cert("leaf.example.com", days_valid=90).der)
    seed_scanned(db, "leaf.example.com", 443, replacement)
    assert repo.get_by_id(cert_id) is not None
    assert repo.get_uploaded_notes(cert_id) == "belongs to the uploaded file"
    assert repo.get_uploaded_notes(scanned_id) == ""
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and host.notes == "endpoint runbook"


def test_deleting_a_host_keeps_a_legacy_uploaded_file_and_its_notes(upload):
    db, cert_id = upload
    _update(db, cert_id, "uploaded file context")
    hosts = SqliteHostRepository(db)
    host_id = hosts.add("leaf.example.com")
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET hostname='leaf.example.com', port=443 WHERE id=?", (cert_id,),
        )
        conn.commit()
    assert hosts.delete(host_id)
    assert SqliteCertificateRepository(db).get_by_id(cert_id) is not None
    assert SqliteCertificateRepository(db).get_uploaded_notes(cert_id) == "uploaded file context"


def test_deleting_a_legacy_upload_keeps_the_matching_scan_history(upload):
    from tests._helpers import seed_scanned

    db, cert_id = upload
    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    assert cert is not None
    SqliteHostRepository(db).add("leaf.example.com")
    scanned_id = seed_scanned(db, "leaf.example.com", 443, cert)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET hostname='leaf.example.com', port=443 WHERE id=?", (cert_id,),
        )
        history = [tuple(row) for row in conn.execute("SELECT * FROM cert_history")]
        assert history
        conn.commit()
    _update(db, cert_id, "remove this file")
    repo.delete(cert_id)
    assert repo.get_by_id(scanned_id) is not None
    assert repo.get_uploaded_notes(cert_id) == ""
    with _connect(db) as conn:
        assert [tuple(row) for row in conn.execute("SELECT * FROM cert_history")] == history


@pytest.mark.parametrize("with_predecessor", [False, True])
def test_scan_resolves_only_the_actual_scanned_predecessor(upload, monkeypatch, with_predecessor):
    from cert_watch.alerting.model import WebhookConfig
    from cert_watch.certificate_model import parse_certificate
    from cert_watch.database import Alert, SqliteAlertRepository
    from cert_watch.scan import ScannedEntry, store_scanned
    from tests.conftest import _make_cert

    db, upload_id = upload
    hostname = "leaf.example.com"
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET hostname=?, port=443 WHERE id=?", (hostname, upload_id),
        )
        conn.commit()
    alerts = SqliteAlertRepository(db)

    def sent_alert(cert_id):
        return alerts.create(Alert(
            cert_id=cert_id, alert_type="expiry_warning", status="sent", message="synthetic",
            trigger_cert_id=cert_id, dedupe_key=f"expiry:{cert_id}",
        ))

    sent_alert(upload_id)
    head_id = None
    if with_predecessor:
        old_id = SqliteCertificateRepository(db, source="scanned", hostname=hostname, port=443).add(
            parse_certificate(_make_cert(hostname, days_valid=30).der)
        )
        head_id = SqliteCertificateRepository(
            db, source="scanned", hostname=hostname, port=443, replaces_cert_id=old_id,
        ).add(parse_certificate(_make_cert(hostname, days_valid=60).der))
        with _connect(db) as conn:
            conn.execute(
                "UPDATE certificates SET created_at='2099-01-01T00:00:00+00:00' WHERE id=?",
                (old_id,),
            )
            conn.commit()
        sent_alert(head_id)
    resolved = []

    def resolve(cert_id, *args, **kwargs):
        resolved.append(cert_id)
        return True

    monkeypatch.setattr("cert_watch.alerting.resolve.send_webhook_resolve", resolve)
    store_scanned(
        ScannedEntry(
            host=hostname, port=443,
            leaf=parse_certificate(_make_cert(hostname, days_valid=90).der), chain=[],
        ),
        db,
        webhook_config=WebhookConfig(url="https://hooks.example.invalid/resolve", kind="pagerduty"),
    )
    assert resolved == ([head_id] if with_predecessor else [])
    assert SqliteCertificateRepository(db).get_by_id(upload_id) is not None
    assert alerts.list_for_cert(upload_id)[0].status == "sent"


@pytest.mark.parametrize("detach", ["host_removal", "orphan_upgrade"])
def test_new_host_scope_cannot_capture_legacy_upload_notes(upload, tmp_path, detach):
    from cert_watch.migrations.m0050_uploaded_certificate_notes import upgrade
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db, cert_id = upload
    hostname = "leaf.example.com"
    repo = SqliteCertificateRepository(db)
    repo.set_tags(cert_id, "team-a")
    _update(db, cert_id, "team-a private runbook")
    hosts = SqliteHostRepository(db)
    host_id = hosts.add(hostname, tags="team-a") if detach == "host_removal" else None
    with _connect(db) as conn:
        conn.execute("UPDATE certificates SET hostname=?, port=443 WHERE id=?", (hostname, cert_id))
        conn.commit()
    if host_id:
        assert hosts.delete(host_id)
    else:
        with _connect(db) as conn:
            upgrade(conn)
            conn.commit()
    hosts.add(hostname, tags="team-b")
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-b")
    with _scoped_client(app, groups) as client:
        assert client.get(f"/api/certificates/{cert_id}").status_code == 404
        assert client.patch(
            f"/api/certificates/{cert_id}/notes", json={"notes": "team-b attempted overwrite"},
        ).status_code == 403
    assert repo.effective_tags(cert_id) == ["team-a"]
    assert _update(
        db, cert_id, "team-a updated runbook",
        auth=AuthContext.from_tier("operator-a", "operator", scope_tag="team-a"),
    ) == "team-a updated runbook"


@pytest.mark.parametrize("legacy", [False, True])
def test_migration_preserves_legacy_uploads_and_never_overwrites_edits(tmp_path, legacy):
    from cert_watch.migrations.m0050_uploaded_certificate_notes import upgrade

    db = tmp_path / "migration.sqlite3"
    init_schema(db)
    with _connect(db) as conn:
        conn.execute("DROP TABLE uploaded_certificate_notes")
        if legacy:
            conn.execute("ALTER TABLE certificates ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
            # Copy a genuine certificate row shape; raw DER is irrelevant to migration.
            conn.execute(
                "INSERT INTO certificates "
                "(id,subject,issuer,not_before,not_after,san_dns_names,"
                "fingerprint_sha256,raw_der,source,notes,created_at,updated_at) "
                "VALUES ('uploaded','CN=example.test','CN=CA','2026-01-01','2027-01-01',"
                "'[]','ab',X'00','uploaded','preserved note','2026-01-01','2026-01-01')"
            )
        upgrade(conn)
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='uploaded_certificate_notes'"
        ).fetchone() is not None
        if legacy:
            assert conn.execute(
                "SELECT notes FROM uploaded_certificate_notes WHERE cert_id='uploaded'"
            ).fetchone()[0] == "preserved note"
            conn.execute("UPDATE uploaded_certificate_notes SET notes='edited'")
        upgrade(conn)
        if legacy:
            assert conn.execute(
                "SELECT notes FROM uploaded_certificate_notes"
            ).fetchone()[0] == "edited"
        conn.commit()


@pytest.mark.parametrize("source", ["scanned", "unknown"])
def test_migration_does_not_claim_nonupload_legacy_notes(tmp_path, source):
    from cert_watch.migrations.m0050_uploaded_certificate_notes import upgrade

    db = tmp_path / "legacy.sqlite3"
    init_schema(db)
    with _connect(db) as conn:
        conn.execute("ALTER TABLE certificates ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "INSERT INTO certificates "
            "(id,subject,issuer,not_before,not_after,san_dns_names,"
            "fingerprint_sha256,raw_der,source,notes,created_at,updated_at) "
            "VALUES ('legacy','CN=example.test','CN=CA','2026-01-01','2027-01-01',"
            "'[]','ab',X'00',?,'preserved note','2026-01-01','2026-01-01')",
            (source,),
        )
        upgrade(conn)
        assert conn.execute("SELECT * FROM uploaded_certificate_notes").fetchall() == []
        assert conn.execute("SELECT notes FROM certificates WHERE id='legacy'").fetchone()[0] == (
            "preserved note"
        )
        conn.commit()
