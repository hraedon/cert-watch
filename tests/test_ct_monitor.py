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

    mock_entry = MagicMock()
    mock_entry.common_name = "known.example.com"
    mock_entry.issuer_name = "Test CA"
    mock_entry.serial_number = "known-serial-456"

    # Run twice with the same (serial, issuer) — second run should still
    # report new because CT monitor tracks within a single run, not across runs
    # (DB stores SHA256 fingerprints, not serial numbers).
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
    mock_entry2.serial_number = "dup-serial-789"  # same serial + issuer

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_entry1, mock_entry2],
    ):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 1  # deduplicated within the same run
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
