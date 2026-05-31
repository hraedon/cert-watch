from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from cert_watch.ct_monitor import ct_reconciliation, run_ct_monitor
from cert_watch.database import init_schema


def test_ct_monitor_no_hosts(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    result = run_ct_monitor(db)
    assert result["checked"] == 0
    assert result["new"] == 0
    assert result["errors"] == 0


def test_ct_monitor_finds_new_cert(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("monitor.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "monitor.example.com"
    mock_entry.issuer_name = "Test CA"
    mock_entry.serial_number = "new-serial-123"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 1
    assert result["errors"] == 0


def test_ct_monitor_skips_known_serial(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("known.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "known.example.com"
    mock_entry.issuer_name = "Test CA"
    mock_entry.serial_number = "known-serial-456"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 1
    assert result["errors"] == 0


def test_ct_monitor_dedup_within_run(tmp_path):
    """Duplicate (serial, issuer) entries within a single CT response are deduplicated."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("dup.example.com", 443)

    mock_entry1 = MagicMock()
    mock_entry1.common_name = "dup.example.com"
    mock_entry1.issuer_name = "Test CA"
    mock_entry1.serial_number = "dup-serial-789"

    mock_entry2 = MagicMock()
    mock_entry2.common_name = "dup.example.com"
    mock_entry2.issuer_name = "Test CA"
    mock_entry2.serial_number = "dup-serial-789"

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_entry1, mock_entry2],
    ):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 1
    assert result["errors"] == 0


def test_ct_monitor_handles_error(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("err.example.com", 443)

    with patch("cert_watch.ct_monitor.query_ct_log", return_value="network error"):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 0
    assert result["errors"] == 1


# ---------- CT reconciliation tests ----------


def test_ct_reconciliation_finds_gaps(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("www.example.com", 443)
    repo.add("api.example.com", 443)

    mock_entry1 = MagicMock()
    mock_entry1.common_name = "www.example.com"
    mock_entry1.name_value = "www.example.com"
    mock_entry1.issuer_name = "Let's Encrypt"
    mock_entry1.serial_number = "aaa"

    mock_entry2 = MagicMock()
    mock_entry2.common_name = "staging.example.com"
    mock_entry2.name_value = "staging.example.com"
    mock_entry2.issuer_name = "Let's Encrypt"
    mock_entry2.serial_number = "bbb"

    mock_entry3 = MagicMock()
    mock_entry3.common_name = "api.example.com"
    mock_entry3.name_value = "api.example.com"
    mock_entry3.issuer_name = "Let's Encrypt"
    mock_entry3.serial_number = "ccc"

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_entry1, mock_entry2, mock_entry3],
    ):
        result = ct_reconciliation(db, "example.com")

    assert result.error == ""
    assert "www.example.com" in result.tracked_hostnames
    assert "api.example.com" in result.tracked_hostnames
    assert "staging.example.com" in result.ct_only_hostnames
    assert "staging.example.com" not in result.tracked_hostnames
    assert result.coverage_pct == 66.7


def test_ct_reconciliation_full_coverage(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "app.example.com"
    mock_entry.name_value = "app.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "x"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert result.ct_only_hostnames == []
    assert result.coverage_pct == 100.0


def test_ct_reconciliation_ct_error(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)

    with patch("cert_watch.ct_monitor.query_ct_log", return_value="timeout"):
        result = ct_reconciliation(db, "example.com")

    assert result.error != ""
    assert "app.example.com" in result.tracked_hostnames
    assert result.ct_hostnames == []


def test_ct_reconciliation_no_hosts(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)

    mock_entry = MagicMock()
    mock_entry.common_name = "orphan.example.com"
    mock_entry.name_value = "orphan.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "y"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert result.tracked_hostnames == []
    assert "orphan.example.com" in result.ct_only_hostnames
    assert result.coverage_pct == 0.0


def test_ct_reconciliation_san_parsing(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("main.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "main.example.com"
    mock_entry.name_value = "main.example.com\nextra.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "z"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert "main.example.com" in result.tracked_hostnames
    assert "extra.example.com" in result.ct_only_hostnames


def test_ct_reconciliation_filters_by_domain(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)
    SqliteHostRepository(db).add("other.notexample.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "app.example.com"
    mock_entry.name_value = "app.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "w"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert "other.notexample.com" not in result.tracked_hostnames
    assert "app.example.com" in result.tracked_hostnames


def test_ct_reconciliation_empty_ct_results(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[]):
        result = ct_reconciliation(db, "example.com")

    assert result.error == ""
    assert "app.example.com" in result.tracked_hostnames
    assert "app.example.com" in result.tracked_only_hostnames
    assert result.ct_hostnames == []
    assert result.coverage_pct == 100.0


def test_api_ct_reconciliation(tmp_path, reload_app):
    app_mod = reload_app()
    from cert_watch.database import SqliteHostRepository, init_schema
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("app.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "app.example.com"
    mock_entry.name_value = "app.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "q"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]), \
         TestClient(app_mod.app) as client:
        r = client.get("/api/ct/reconciliation?domain=example.com")
    assert r.status_code == 200
    data = r.json()
    assert data["domain"] == "example.com"
    assert "app.example.com" in data["tracked_hostnames"]


def test_api_ct_reconciliation_missing_domain(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/ct/reconciliation")
    assert r.status_code == 400
    assert "domain" in r.json()["error"]
