"""Additional coverage tests to reach 90%.

Targets: scan.py error paths, certificates.py detail branches, settings.py,
middleware.py branches, cert_chain.py error paths.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from cert_watch.upload import store_uploaded, upload_certificate


def _reload(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    import importlib

    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)
    return app_mod


# ---------- scan.py: _is_blocked_ip and SSRF checks ----------


def test_is_blocked_ip_loopback():
    import ipaddress

    from cert_watch.scan import _is_blocked_ip

    assert _is_blocked_ip(ipaddress.ip_address("127.0.0.1")) is True
    assert _is_blocked_ip(ipaddress.ip_address("::1")) is True


def test_is_blocked_ip_link_local():
    import ipaddress

    from cert_watch.scan import _is_blocked_ip

    assert _is_blocked_ip(ipaddress.ip_address("169.254.1.1")) is True
    assert _is_blocked_ip(ipaddress.ip_address("fe80::1")) is True


def test_is_blocked_ip_private_allowed():
    import ipaddress

    from cert_watch.scan import _is_blocked_ip

    assert _is_blocked_ip(ipaddress.ip_address("10.0.0.1"), allow_private=True) is False
    assert _is_blocked_ip(ipaddress.ip_address("192.168.1.1"), allow_private=True) is False


def test_is_blocked_ip_private_blocked():
    import ipaddress

    from cert_watch.scan import _is_blocked_ip

    assert _is_blocked_ip(ipaddress.ip_address("10.0.0.1"), allow_private=False) is True
    assert _is_blocked_ip(ipaddress.ip_address("192.168.1.1"), allow_private=False) is True


def test_is_blocked_ip_allowed_subnets():
    import ipaddress

    from cert_watch.scan import _is_blocked_ip

    assert (
        _is_blocked_ip(
            ipaddress.ip_address("10.0.0.1"),
            allow_private=False,
            allowed_subnets=("10.0.0.0/8",),
        )
        is False
    )


def test_is_blocked_ip_public():
    import ipaddress

    from cert_watch.scan import _is_blocked_ip

    assert _is_blocked_ip(ipaddress.ip_address("8.8.8.8")) is False
    assert _is_blocked_ip(ipaddress.ip_address("1.1.1.1")) is False


def test_is_blocked_ip_metadata():
    import ipaddress

    from cert_watch.scan import _is_blocked_ip

    assert _is_blocked_ip(ipaddress.ip_address("169.254.169.254")) is True


# ---------- scan.py: ScannedEntry and ScanError ----------


def test_scanned_entry_dataclass():
    from cert_watch.certificate_model import Certificate
    from cert_watch.scan import ScannedEntry

    now = datetime.now(UTC)
    cert = Certificate(
        subject="test.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    entry = ScannedEntry(host="test.example.com", port=443, leaf=cert, chain=[])
    assert entry.host == "test.example.com"
    assert entry.port == 443
    assert entry.leaf.subject == "test.example.com"


def test_scan_error_dataclass_fields():
    from cert_watch.scan import ScanError

    err = ScanError(hostname="h.example.com", port=443, error_message="connection refused")
    assert err.hostname == "h.example.com"
    assert err.port == 443
    assert err.error_message == "connection refused"


# ---------- cert_chain.py additional paths ----------


def test_chain_status_with_intermediates(chain_triplet):
    from cert_watch.cert_chain import chain_status
    from cert_watch.certificate_model import parse_certificate

    leaf = parse_certificate(chain_triplet["leaf"].der)
    intermediate = parse_certificate(chain_triplet["intermediate"].der)
    root = parse_certificate(chain_triplet["root"].der)
    # With full chain
    cs = chain_status(leaf, [intermediate, root], [])
    assert cs in ("public", "complete", "unknown")


def test_chain_status_with_anchors(chain_triplet):
    from cert_watch.cert_chain import chain_status
    from cert_watch.certificate_model import parse_certificate

    leaf = parse_certificate(chain_triplet["leaf"].der)
    intermediate = parse_certificate(chain_triplet["intermediate"].der)
    root = parse_certificate(chain_triplet["root"].der)
    cs = chain_status(leaf, [intermediate], [root])
    assert cs in ("public", "complete", "unknown", "private")


# ---------- routes/certificates.py detail branches ----------


def test_certificate_detail_uploaded(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "leaf.example.com" in r.text


def test_certificate_detail_with_posture(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema, store_scan_posture

    init_schema(db)
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    store_scan_posture(
        str(db),
        cert_id,
        "leaf.example.com",
        443,
        "A",
        [
            {"check": "tls_version", "status": "ok", "message": "TLS 1.3"},
        ],
        protocol_version="TLSv1.3",
    )
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "TLS" in r.text


def test_certificate_detail_revocation_button(tmp_path, monkeypatch, leaf_pem_file):
    """The detail page shows a Check revocation button when posture is present."""
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema, store_scan_posture

    init_schema(db)
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    store_scan_posture(
        str(db),
        cert_id,
        "leaf.example.com",
        443,
        "A",
        [{"check": "tls_version", "status": "ok", "message": "TLS 1.3"}],
        protocol_version="TLSv1.3",
    )
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "Check revocation" in r.text
    assert "data-action=\"check-revocation\"" in r.text


def test_certificate_detail_ecdsa_key(tmp_path, monkeypatch):
    """Test detail page with ECDSA key type."""

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ecdsa.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)
    tmp_file = tmp_path / "ecdsa.der"
    tmp_file.write_bytes(der)

    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import upload_certificate

    entry = upload_certificate(tmp_file)
    cert_id = store_uploaded(entry, db)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "ECDSA" in r.text


# ---------- routes/certificates.py upload paths ----------


def test_upload_pfx_with_password(tmp_path, monkeypatch, pfx_file_with_password):
    app_mod = _reload(monkeypatch, tmp_path)
    path, pw = pfx_file_with_password
    with TestClient(app_mod.app) as client, open(path, "rb") as f:
        r = client.post(
            "/upload",
            files={"file": ("bundle-pw.pfx", f, "application/x-pkcs12")},
            data={"password": pw.decode()},
            follow_redirects=False,
        )
    assert r.status_code == 303


def test_upload_p7c(tmp_path, monkeypatch, p7c_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client, open(p7c_pem_file, "rb") as f:
        r = client.post(
            "/upload",
            files={"file": ("chain.p7c", f, "application/x-pkcs7-certificates")},
            follow_redirects=False,
        )
    assert r.status_code == 303


# ---------- routes/settings.py additional paths ----------


# The env-hash-override path (CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH blocking in-UI
# rotation) is exercised end-to-end through the route in
# test_settings.py::test_settings_env_hash_override_shows_warning, which asserts the
# redirect carries the override notice. A duplicate tautological stub that only
# re-read the env var it had just set lived here and was removed in the 2026-06-04
# test-quality pass.


def test_settings_save_auth(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/auth",
            data={
                "auth_provider": "",
                "ldap_server": "",
                "ldap_base_dn": "",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303


# ---------- routes/views.py: pivot_tls_monthly and pivot_grade_monthly ----------


def test_pivot_tls_monthly():
    from cert_watch.routes.views import _pivot_tls_monthly

    rows = [
        {"date": "2026-01-01", "protocol_version": "TLSv1.3", "count": 5},
        {"date": "2026-01-02", "protocol_version": "TLSv1.2", "count": 3},
        {"date": "2026-01-03", "protocol_version": "TLSv1.3", "count": 2},
        {"date": "2026-02-01", "protocol_version": "TLSv1.0", "count": 1},
    ]
    result, max_total = _pivot_tls_monthly(rows)
    assert len(result) == 2
    assert result[0]["month"] == "2026-01"
    assert result[0]["tls_1_3"] == 7
    assert result[0]["tls_1_2"] == 3
    assert result[1]["tls_1_0"] == 1
    assert max_total >= 10


def test_pivot_tls_monthly_empty():
    from cert_watch.routes.views import _pivot_tls_monthly

    result, max_total = _pivot_tls_monthly([])
    assert result == []
    assert max_total == 1


def test_pivot_grade_monthly():
    from cert_watch.routes.views import _pivot_grade_monthly

    rows = [
        {"date": "2026-01-01", "posture_grade": "A", "count": 5},
        {"date": "2026-01-02", "posture_grade": "B", "count": 3},
        {"date": "2026-01-03", "posture_grade": "A+", "count": 2},
        {"date": "2026-02-01", "posture_grade": "F", "count": 1},
        {"date": "2026-02-02", "posture_grade": "C", "count": 4},
    ]
    result, max_total = _pivot_grade_monthly(rows)
    assert len(result) == 2
    assert result[0]["month"] == "2026-01"
    assert result[0]["grade_a"] == 7  # A + A+
    assert result[0]["grade_b"] == 3
    assert result[1]["grade_f"] == 1
    assert result[1]["grade_c"] == 4


def test_pivot_grade_monthly_empty():
    from cert_watch.routes.views import _pivot_grade_monthly

    result, max_total = _pivot_grade_monthly([])
    assert result == []
    assert max_total == 1


# ---------- middleware.py: rate_limit_headers_middleware ----------


def test_rate_limit_headers_on_api(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates")
    assert r.status_code == 200
    assert "x-ratelimit-remaining" in {k.lower(): v for k, v in r.headers.items()}


# ---------- routes/api.py: certificate PUT tags with no tags key ----------


def test_api_set_cert_tags_no_tags_key(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"not_tags": "value"})
    assert r.status_code == 400


# ---------- config.py additional branches ----------


def test_config_smtp_port_invalid(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SMTP_PORT", "notanumber")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.smtp_port == 587  # fallback default


def test_config_ldap_connect_timeout_invalid(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "notanumber")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.ldap_connect_timeout == 5


def test_config_webhook_headers_json(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com")
    monkeypatch.setenv("ALERT_WEBHOOK_HEADERS", '{"Authorization": "Bearer tok"}')
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.webhook_headers is not None
    assert s.webhook_headers["Authorization"] == "Bearer tok"


def test_config_webhook_headers_invalid_json(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com")
    monkeypatch.setenv("ALERT_WEBHOOK_HEADERS", "not json")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.webhook_headers is None


def test_config_log_format(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_LOG_FORMAT", "json")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.log_format == "json"


def test_config_tls_verify(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_TLS_VERIFY", "1")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.tls_verify is True


def test_config_auth_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUTH_PROVIDER", "ldap")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.auth_provider == "ldap"


def test_config_ldap_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUTH_PROVIDER", "ldap")
    monkeypatch.setenv("LDAP_SERVER", "ldap://dc.example.com")
    monkeypatch.setenv("LDAP_BASE_DN", "dc=example,dc=com")
    monkeypatch.setenv("LDAP_BIND_DN", "cn=svc,dc=example,dc=com")
    monkeypatch.setenv("LDAP_USER_FILTER", "(uid={username})")
    monkeypatch.setenv("LDAP_START_TLS", "1")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.ldap_server == "ldap://dc.example.com"
    assert s.ldap_base_dn == "dc=example,dc=com"
    assert s.ldap_start_tls is True
    assert s.ldap_user_filter == "(uid={username})"


def test_config_oauth_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUTH_PROVIDER", "oauth")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("OAUTH_ISSUER_URL", "https://login.example.com")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.oauth_client_id == "client-id"
    assert s.oauth_issuer_url == "https://login.example.com"


def test_config_admin_write_users(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ADMINS", "alice,bob")
    monkeypatch.setenv("CERT_WATCH_WRITE_USERS", "charlie")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert "alice" in s.admin_users
    assert "bob" in s.admin_users
    assert "charlie" in s.write_users


def test_config_allowed_groups_roles(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ALLOWED_GROUPS", "infra-team,devops")
    monkeypatch.setenv("CERT_WATCH_ALLOWED_ROLES", "admin,viewer")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert "infra-team" in s.allowed_groups
    assert "admin" in s.allowed_roles


def test_config_base_url(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_BASE_URL", "https://cert.example.com")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.base_url == "https://cert.example.com"


# ---------- database/repo.py: host update methods ----------


def test_host_repo_update_owner(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("h.example.com", 443)
    repo.update_owner(hid, owner_name="Alice", owner_email="alice@example.com", owner_slack="#ops")
    host = repo.get(hid)
    assert host.owner_name == "Alice"
    assert host.owner_email == "alice@example.com"
    assert host.owner_slack == "#ops"


def test_host_repo_update_renewal(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("h.example.com", 443)
    repo.update_renewal(hid, renewal_method="acme", runbook_url="https://wiki.example.com")
    host = repo.get(hid)
    assert host.renewal_method == "acme"
    assert host.runbook_url == "https://wiki.example.com"


def test_host_repo_count_all(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    assert repo.count_all() == 0
    repo.add("h1.example.com", 443)
    repo.add("h2.example.com", 443)
    assert repo.count_all() == 2


def test_host_repo_list_page(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    for i in range(5):
        repo.add(f"h{i}.example.com", 443)
    page = repo.list_page(offset=0, limit=2)
    assert len(page) == 2
    page2 = repo.list_page(offset=2, limit=2)
    assert len(page2) == 2


# ---------- database queries: additional paths ----------


def test_count_dashboard_leaves(tmp_path):
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, count_dashboard_leaves, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="test.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    SqliteCertificateRepository(db, source="uploaded").add(cert)
    assert count_dashboard_leaves(db) == 1


def test_distinct_tags(tmp_path):
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, distinct_tags, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="test.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    repo = SqliteCertificateRepository(db, source="uploaded")
    cid = repo.add(cert)
    repo.set_tags(cid, "prod,web")
    tags = distinct_tags(db)
    assert "prod" in tags
    assert "web" in tags


# ---------- middleware.py: more CSRF paths ----------


def test_csrf_token_with_invalid_timestamp():
    import cert_watch.middleware as mw

    mw.set_csrf_secret("test")
    # Token with non-numeric timestamp
    token = "session:abc:sig"
    assert mw.validate_csrf_token(token, "session") is False


def test_session_id_cookie_priority():
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    req = MagicMock()
    req.cookies = {"cw_sid": "cookie-sid"}
    req.scope = {"session_id": "scope-sid"}
    assert mw.get_session_id(req) == "cookie-sid"


# ---------- database/connection.py ----------


def test_connect_wal_mode(tmp_path):
    from cert_watch.database.connection import _connect

    db = tmp_path / "wal.sqlite3"
    with _connect(db) as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"
