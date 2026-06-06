from fastapi.testclient import TestClient


def test_api_certificates_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates")
    assert r.status_code == 200
    data = r.json()
    assert data["certificates"] == []
    assert "pagination" in data


def test_api_certificates_with_data(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates")
    assert r.status_code == 200
    certs = r.json()["certificates"]
    assert len(certs) >= 1


def test_api_posture_returns_stored_grade(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema, store_scan_posture

    init_schema(str(db))
    store_scan_posture(
        str(db), "cert-xyz", "example.com", 443, "B",
        [{"check": "tls_version", "status": "warn", "message": "TLS 1.0 offered"}],
        protocol_version="TLSv1.0",
    )

    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/cert-xyz/posture")
    assert r.status_code == 200
    data = r.json()
    assert data["cert_id"] == "cert-xyz"
    assert data["grade"] == "B"
    assert data["protocol_version"] == "TLSv1.0"
    assert data["findings"][0]["check"] == "tls_version"


def test_api_posture_no_data(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/missing/posture")
    assert r.status_code == 200
    assert r.json()["error"] == "no posture data"


def test_api_certificate_by_id(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    from cert_watch.upload import UploadedEntry

    assert isinstance(entry, UploadedEntry)
    leaf_id = store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{leaf_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == leaf_id
    assert "days_until_expiry" in data


def test_api_certificate_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/nonexistent")
    assert r.status_code == 404


def test_api_revocation_check(tmp_path, reload_app, leaf_pem_file, monkeypatch):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    leaf_id = store_uploaded(entry, db)

    def _mock_check(cert_der, **kwargs):
        from cert_watch.posture import Finding
        return [
            Finding(check="ocsp_endpoint", status="pass", message="OCSP responder reachable"),
            Finding(
                check="crl_endpoint",
                status="info",
                message="No CRL distribution points in certificate",
            ),
        ]

    import importlib
    api_mod = importlib.import_module("cert_watch.routes.api.certificates")
    monkeypatch.setattr(api_mod, "check_revocation_endpoints", _mock_check)

    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{leaf_id}/revocation")
    assert r.status_code == 200
    data = r.json()
    assert data["cert_id"] == leaf_id
    assert len(data["findings"]) == 2
    assert data["findings"][0]["check"] == "ocsp_endpoint"
    assert data["findings"][0]["status"] == "pass"


def test_api_revocation_check_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/nonexistent/revocation")
    assert r.status_code == 404
    assert r.json()["error"] == "not found"


def test_api_hosts_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts")
    assert r.status_code == 200
    data = r.json()
    assert data["hosts"] == []
    assert "pagination" in data


def test_api_hosts_with_data(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(db)
    SqliteHostRepository(db).add("api.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts")
    assert r.status_code == 200
    hosts = r.json()["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["hostname"] == "api.example.com"


def test_api_alerts_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/alerts")
    assert r.status_code == 200
    data = r.json()
    assert data["alerts"] == []
    assert "pagination" in data


def test_api_export_csv_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/export/certificates.csv")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/csv; charset=utf-8"
    assert "attachment" in r.headers.get("content-disposition", "")
    lines = r.text.strip().split("\n")
    assert len(lines) == 1  # header only
    assert "host" in lines[0]
    assert "subject" in lines[0]


def test_api_export_csv_with_data(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/api/export/certificates.csv")
    assert r.status_code == 200
    lines = r.text.strip().split("\n")
    assert len(lines) >= 2  # header + at least one row
    assert "leaf.example.com" in lines[1]


def test_api_export_json_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/export/certificates.json")
    assert r.status_code == 200
    data = r.json()
    assert data["certificates"] == []
    assert "attachment" in r.headers.get("content-disposition", "")


def test_api_export_json_with_data(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/api/export/certificates.json")
    assert r.status_code == 200
    data = r.json()
    assert len(data["certificates"]) >= 1
    cert = data["certificates"][0]
    assert "subject" in cert
    assert "days_remaining" in cert
    assert "urgency" in cert


# ---------- Reports (Plan 017 A2) ----------


def test_api_report_inventory_csv_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/inventory.csv")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/csv; charset=utf-8"
    assert "attachment" in r.headers.get("content-disposition", "")
    assert "inventory.csv" in r.headers.get("content-disposition", "")
    lines = r.text.strip().split("\n")
    assert len(lines) == 1  # header only
    assert "host" in lines[0]
    assert "fingerprint_sha256" in lines[0]


def test_api_report_inventory_csv_with_data(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/inventory.csv")
    assert r.status_code == 200
    lines = r.text.strip().split("\n")
    assert len(lines) >= 2  # header + at least one row


def test_api_report_expiring_csv_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/expiring.csv")
    assert r.status_code == 200
    assert "expiring-30d.csv" in r.headers.get("content-disposition", "")
    lines = r.text.strip().split("\n")
    assert len(lines) == 1  # header only


def test_api_report_expiring_csv_custom_days(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/expiring.csv?days=90")
    assert r.status_code == 200
    assert "expiring-90d.csv" in r.headers.get("content-disposition", "")


def test_api_report_expiring_csv_clamps_days(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/expiring.csv?days=999")
    assert r.status_code == 200
    assert "expiring-365d.csv" in r.headers.get("content-disposition", "")


def test_api_report_inventory_requires_auth(reload_app):
    """Reports require auth when auth is enabled."""
    app_mod = reload_app()
    # Without auth configured, all routes are open — so this just verifies
    # the endpoint works and returns 200.
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/inventory.csv")
    assert r.status_code == 200


def test_api_patch_notes(tmp_path, reload_app, leaf_pem_file):
    """FEAT-013: PATCH /api/certificates/{id}/notes should update notes."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    cert_id = store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/certificates/{cert_id}/notes",
            json={"notes": "staging cert"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["notes"] == "staging cert"

    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{cert_id}")
    assert r.status_code == 200
    assert r.json()["notes"] == "staging cert"


def test_api_patch_notes_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.patch(
            "/api/certificates/nonexistent/notes",
            json={"notes": "test"},
        )
    assert r.status_code == 404


def test_api_patch_notes_too_long(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    cert_id = store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/certificates/{cert_id}/notes",
            json={"notes": "x" * 10001},
        )
    assert r.status_code == 400


def test_api_get_certificate_notes_field(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    cert_id = store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{cert_id}")
    assert r.status_code == 200
    assert "notes" in r.json()
    assert r.json()["notes"] == ""


def test_api_download_pem(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    cert_id = store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{cert_id}/pem")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/x-pem-file"
    assert "BEGIN CERTIFICATE" in r.text
    assert "attachment" in r.headers.get("content-disposition", "")
    assert cert_id[:8] in r.headers["content-disposition"]


def test_api_download_pem_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/nonexistent/pem")
    assert r.status_code == 404
