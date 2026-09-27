"""S5 posture headline: distribution first, actionable offenders, honest trends."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from cert_watch.certificate_model import Certificate
from cert_watch.database import init_schema, record_cert_history, store_scan_posture
from cert_watch.services.posture_page import _reason
from tests.test_route_coverage import _insert_certificate


def test_posture_leads_with_linked_distribution_and_offender_reason(
    tmp_path, reload_app,
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _insert_certificate(db, "cert-a")
    _insert_certificate(db, "cert-f")
    store_scan_posture(
        db,
        "cert-a",
        "good.example.test",
        443,
        "A",
        [{"check": "tls_version", "status": "pass", "message": "TLS 1.3"}],
    )
    store_scan_posture(
        db,
        "cert-f",
        "bad.example.test",
        443,
        "F",
        [{
            "check": "rsa_key_size",
            "status": "fail",
            "message": "RSA key size 1024 < 2048 bits",
        }],
    )
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        response = client.get("/posture")
    assert response.status_code == 200
    assert "Fleet grade" not in response.text
    assert 'href="/posture?grade=A#certificate-grades"' in response.text
    assert 'href="/posture?grade=F#certificate-grades"' in response.text
    assert "RSA key size 1024 &lt; 2048 bits" in response.text



def test_posture_reason_uses_only_worst_grade_contributors() -> None:
    findings = [
        {
            "check": "long_validity",
            "status": "warn",
            "message": "Validity exceeds advisory limit",
        },
        {
            "check": "chain_completeness",
            "status": "warn",
            "message": "Incomplete chain — server missing intermediate(s)",
        },
    ]
    assert _reason(findings) == "Incomplete chain — server missing intermediate(s)"

    findings.append(
        {
            "check": "rsa_key_size",
            "status": "fail",
            "message": "RSA key size 1024 < 2048 bits",
        }
    )
    assert _reason(findings) == "RSA key size 1024 < 2048 bits"


def test_posture_reason_ignores_advisory_only_warnings() -> None:
    assert (
        _reason(
            [
                {
                    "check": "long_validity",
                    "status": "warn",
                    "message": "Validity exceeds advisory limit",
                }
            ]
        )
        == "No failing posture checks recorded."
    )

def test_posture_hides_trends_until_history_spans_more_than_a_month(
    tmp_path, reload_app,
):
    init_schema(tmp_path / "cert-watch.sqlite3")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        response = client.get("/posture")
    assert "Trends appear after more than a month of scan history." in response.text
    assert "Posture grades over time" not in response.text


def test_posture_shows_trends_after_history_spans_more_than_a_month(
    tmp_path, reload_app,
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="trend.example.test",
        issuer="Example CA",
        not_before=now - timedelta(days=90),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="AB" * 32,
    )
    record_cert_history(
        db,
        "trend.example.test",
        443,
        cert,
        posture_grade="B",
        protocol_version="TLSv1.2",
        scanned_at=(now - timedelta(days=31)).isoformat(),
    )
    record_cert_history(
        db,
        "trend.example.test",
        443,
        cert,
        posture_grade="A",
        protocol_version="TLSv1.3",
        scanned_at=now.isoformat(),
    )
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        response = client.get("/posture")
    assert "Posture grades over time" in response.text
    assert "TLS versions across the fleet" in response.text
    assert "Trends appear after more than a month of scan history." not in response.text
