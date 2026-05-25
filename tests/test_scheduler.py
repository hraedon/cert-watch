from unittest.mock import MagicMock

from cert_watch.database import init_schema
from cert_watch.scheduler import ScanHistory, record_scan_history, run_scan_now


def test_run_scan_now_success(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    scan_fn = MagicMock(return_value=MagicMock(spec=[]))  # no error_message attr
    alert_fn = MagicMock(return_value={"sent": 2, "failed": 0})
    counts = run_scan_now(
        scan_fn,
        alert_fn,
        db_path=db,
        host_provider=lambda: [("a.example.com", 443), ("b.example.com", 8443)],
        store_fn=lambda _r: "id",
    )
    assert counts["scanned"] == 2
    assert counts["alerts_sent"] == 2
    assert counts["failures"] == 0
    assert scan_fn.call_count == 2


def test_run_scan_now_continues_on_failure(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)

    def scan_fn(host, port):
        if host == "broken":
            raise RuntimeError("boom")
        return MagicMock(spec=[])

    alert_fn = MagicMock(return_value={"sent": 0, "failed": 0})
    counts = run_scan_now(
        scan_fn,
        alert_fn,
        db_path=db,
        host_provider=lambda: [("broken", 443), ("good", 443)],
        store_fn=lambda _r: "id",
    )
    assert counts["scanned"] == 1
    assert counts["failures"] == 1


def test_run_scan_now_handles_scan_error(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    err = MagicMock()
    err.error_message = "tls failed"
    scan_fn = MagicMock(return_value=err)
    alert_fn = MagicMock(return_value={"sent": 0, "failed": 0})
    counts = run_scan_now(
        scan_fn,
        alert_fn,
        db_path=db,
        host_provider=lambda: [("h", 443)],
        store_fn=lambda _r: "id",
    )
    assert counts["scanned"] == 0
    assert counts["failures"] == 1


def test_record_scan_history(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    sid = record_scan_history(
        db, ScanHistory(hostname="h", port=443, status="success")
    )
    assert sid
