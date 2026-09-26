"""#113 item 4: a failing endpoint's detail page shows the current scan state.

A failed scan keeps the last good certificate, so the page said "Healthy A+"
and never showed the error; Scan now on the page also sent the user Home.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.scan_error_guidance import describe_scan_error
from cert_watch.scheduler import ScanHistory, record_scan_history
from tests._helpers import seed_scanned

_HOST = "leaf.example.com"
_EOF = (
    "Connection failed: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in "
    "violation of protocol (_ssl.c:1032)"
)



@pytest.fixture(autouse=True)
def _no_startup_scan(monkeypatch):
    """The app's lifespan starts the real scheduler, whose startup scan of the
    registered host would record a newer result than the fixed one these
    tests assert on (#115 review: it raced, failing about one run in four)."""
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _failing_estate(tmp_path, leaf_der):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(_HOST, 443)
    cert_id = seed_scanned(db, _HOST, 443, parse_certificate(leaf_der))
    record_scan_history(
        db,
        ScanHistory(
            hostname=_HOST, port=443, status="success", scanned_at=datetime(2026, 9, 1, tzinfo=UTC)
        ),
    )
    record_scan_history(
        db,
        ScanHistory(
            hostname=_HOST,
            port=443,
            status="failure",
            error_message=_EOF,
            scanned_at=datetime(2026, 9, 24, 7, 29, tzinfo=UTC),
        ),
    )
    return db, host_id, cert_id


def test_detail_shows_the_current_scan_failure(tmp_path, reload_app, self_signed_leaf):
    _db, _host_id, cert_id = _failing_estate(tmp_path, self_signed_leaf.der)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        page = client.get(f"/certificates/{cert_id}").text
        browse = client.get("/browse?grouped=0").text
        api_row = client.get("/api/certificates").json()["certificates"][0]
        report = client.get("/api/reports/inventory.csv").text

    assert 'data-testid="cert-scan-failed-status"' in page
    assert 'data-testid="scan-failure-panel"' in page
    assert "2026-09-24 07:29 UTC" in page
    # Plain-language cause and next step, with the raw text kept beside them.
    assert "closed the connection during the TLS handshake" in page
    assert "Next step:" in page
    assert "UNEXPECTED_EOF_WHILE_READING" in page
    assert "from the last successful scan" in page
    # A fine last-seen certificate remains condition=ok, but no surface may
    # describe the endpoint as healthy while current monitoring is failing.
    assert api_row["status"]["condition"]["state"] == "ok"
    assert api_row["status"]["monitoring"]["state"] == "failing"
    assert api_row["urgency"] == "failing"
    assert "Healthy" not in page
    assert "Healthy" not in browse
    assert ",healthy," not in report


def test_detail_of_a_healthy_endpoint_has_no_failure_panel(
    tmp_path, reload_app, self_signed_leaf
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    cert_id = seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der))
    record_scan_history(db, ScanHistory(hostname=_HOST, port=443, status="success"))
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        page = client.get(f"/certificates/{cert_id}").text
    assert "scan-failure-panel" not in page
    assert "cert-scan-failed-status" not in page


def _stub_scan(monkeypatch, status, error=None):
    async def _fake(*_args, **_kwargs):
        return status, error

    monkeypatch.setattr("cert_watch.routes.hosts._scan_and_store", _fake)


@pytest.mark.parametrize(
    ("status", "error", "expected_query"),
    [("success", None, "scanned=1"), ("scan_error", _EOF, "scanned=1")],
)
def test_scan_now_from_detail_returns_to_detail(
    tmp_path, reload_app, monkeypatch, self_signed_leaf, status, error, expected_query
):
    _db, host_id, _cert_id = _failing_estate(tmp_path, self_signed_leaf.der)
    _stub_scan(monkeypatch, status, error)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/hosts/{host_id}/scan", data={"return_to": "detail"}, follow_redirects=False
        )
    assert r.status_code == 303
    assert r.headers["location"] == f"/certificates/{host_id}?{expected_query}"


def test_scan_now_from_home_still_returns_home(
    tmp_path, reload_app, monkeypatch, self_signed_leaf
):
    _db, host_id, _cert_id = _failing_estate(tmp_path, self_signed_leaf.der)
    _stub_scan(monkeypatch, "scan_error", _EOF)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(f"/hosts/{host_id}/scan", follow_redirects=False)
        # An unknown target is ignored, never followed.
        r2 = client.post(
            f"/hosts/{host_id}/scan",
            data={"return_to": "https://evil.example"},
            follow_redirects=False,
        )
    assert r.headers["location"].startswith("/?warning=scan%20failed")
    assert r2.headers["location"].startswith("/?warning=scan%20failed")


def test_scan_now_round_trip_lands_on_the_current_certificate(
    tmp_path, reload_app, monkeypatch, self_signed_leaf
):
    _db, host_id, cert_id = _failing_estate(tmp_path, self_signed_leaf.der)
    _stub_scan(monkeypatch, "success")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/hosts/{host_id}/scan", data={"return_to": "detail"}, follow_redirects=True
        )
    assert r.status_code == 200
    assert r.url.path == f"/certificates/{cert_id}"


def test_flash_messages_render_on_the_detail_page(tmp_path, reload_app, self_signed_leaf):
    _db, _host_id, cert_id = _failing_estate(tmp_path, self_signed_leaf.der)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        page = client.get(f"/certificates/{cert_id}?error=invalid+tag").text
    assert 'id="cw-flash-error"' in page
    assert "invalid tag" in page


@pytest.mark.parametrize(
    ("message", "fragment"),
    [
        (_EOF, "closed the connection"),
        ("Connection failed: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1032)",
         "not with TLS"),
        ("DNS resolution failed: Could not resolve hostname: DNS resolution failed for x",
         "does not resolve"),
        ("Connection refused — the host is not accepting connections on this port",
         "Nothing is accepting"),
        ("Connection timed out — the host did not respond in time", "did not answer"),
        ("hostname resolves to blocked address 10.0.0.1. Set CERT_WATCH_ALLOW_PRIVATE_IPS=1",
         "not allowed to scan"),
        ("no certificate presented", "without the server presenting"),
        ("TLS handshake failed", "rejected the TLS handshake"),
        (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "unable to get local issuer certificate",
            "does not lead to an issuer cert-watch trusts",
        ),
        (
            "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate",
            "self-signed certificate that cert-watch does not trust",
        ),
        (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired",
            "presented an expired certificate",
        ),
        (
            "[SSL: CERTIFICATE_VERIFY_FAILED] hostname mismatch",
            "does not cover the host name",
        ),
        (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
            "could not verify the server's certificate",
        ),
    ],
)
def test_known_scan_errors_have_plain_language_guidance(message, fragment):
    guidance = describe_scan_error(message)
    assert guidance is not None
    assert fragment in guidance.cause
    assert guidance.next_step


@pytest.mark.parametrize("message", [None, "", "store failed: disk I/O error"])
def test_unrecognised_scan_errors_have_no_guess(message):
    assert describe_scan_error(message) is None
