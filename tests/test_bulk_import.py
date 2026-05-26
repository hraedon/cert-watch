from fastapi.testclient import TestClient


def _reload_app(monkeypatch, tmp_path):
    import importlib

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)
    return app_mod


def test_import_hosts_csv(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository

    csv_content = "hostname,port\nbulk1.example.com,443\nbulk2.example.com,8443\n"
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content, "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303

    host_repo = SqliteHostRepository(db)
    hosts = host_repo.list_all()
    hostnames = {h.hostname for h in hosts}
    assert "bulk1.example.com" in hostnames
    assert "bulk2.example.com" in hostnames


def test_import_hosts_csv_default_port(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository

    csv_content = "hostname\nportless.example.com\n"
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content, "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303

    host_repo = SqliteHostRepository(db)
    hosts = host_repo.list_all()
    assert any(h.hostname == "portless.example.com" and h.port == 443 for h in hosts)


def test_import_hosts_csv_bad_port(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)

    csv_content = "hostname,port\nbad.example.com,notaport\n"
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content, "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_import_hosts_empty_csv(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)

    csv_content = "hostname,port\n"
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content, "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303


def test_import_hosts_too_large(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)

    big = "hostname\n" + "a.com\n" * 2_000_000
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", big, "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "too%20large" in r.headers["location"]


def test_upload_cert_too_large(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)

    big_content = b"x" * (10 * 1024 * 1024 + 1)
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/upload",
            files={"file": ("big.pem", big_content, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "too%20large" in r.headers["location"]
