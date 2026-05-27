from unittest.mock import MagicMock, patch

from cert_watch.ct_monitor import run_ct_monitor
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

    # Seed a certificate with serial_number as fingerprint
    import sqlite3
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO certificates (id, subject, issuer, not_before, not_after, san_dns_names, fingerprint_sha256, raw_der, source, hostname, port, is_leaf, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "cert-1", "CN=known", "CN=issuer", "2025-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00", "[]", "known-serial-456", b"der",
                "scanned", "known.example.com", 443, 1,
                "2025-01-01T00:00:00+00:00", "2025-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()

    mock_entry = MagicMock()
    mock_entry.common_name = "known.example.com"
    mock_entry.issuer_name = "Test CA"
    mock_entry.serial_number = "known-serial-456"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 0
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
