from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import HostEntry, LatestScanRecord
from cert_watch.presenters.certificate_detail import (
    present_certificate_detail,
    present_certificate_technical_details,
)
from cert_watch.services.certificate_detail import (
    PendingHostDetailData,
    StoredCertificateDetailData,
)
from cert_watch.upload import UploadedEntry, upload_certificate


def test_presenter_builds_template_values_without_http(leaf_pem_file) -> None:
    uploaded = upload_certificate(leaf_pem_file)
    assert isinstance(uploaded, UploadedEntry)

    view = present_certificate_technical_details(uploaded.leaf, [], "public")
    context = view.template_context()

    assert view.key_type.startswith("RSA ")
    assert view.sig_alg != "unknown"
    assert view.serial != "unknown"
    assert context["chain"] == []
    assert context["days_remaining"] == uploaded.leaf.days_until_expiry()
    assert context["chain_issue"] is None


def test_presenter_degrades_unparseable_crypto_and_surfaces_chain_issue() -> None:
    now = datetime.now(UTC)
    cert = Certificate(
        subject="CN=leaf.example.test",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="ab" * 32,
        raw_der=b"not a certificate",
    )

    view = present_certificate_technical_details(cert, [], "incomplete")

    assert view.key_type == view.sig_alg == view.serial == "unknown"
    assert view.fingerprint == ":".join(["AB"] * 32)
    assert view.chain_issue == "incomplete"
    assert view.urgency == "warning"


def _host() -> HostEntry:
    return HostEntry(
        id="host-1",
        hostname="vpn.example.test",
        port=443,
        tags="production, network",
        owner_name="Network team",
        renewal_method="manual",
        renewal_status="in_progress",
        runbook_url="https://runbooks.example.test/vpn",
        threshold_days=14,
        scan_interval_hours=12,
    )


def test_full_detail_presenter_builds_stored_certificate_view() -> None:
    now = datetime(2026, 9, 22, 12, tzinfo=UTC)
    cert = Certificate(
        subject="CN=vpn.example.test",
        issuer="CN=Example CA",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
        san_dns_names=["vpn.example.test", "alt.example.test"],
        fingerprint_sha256="ab" * 32,
        raw_der=b"not a certificate",
        source="scanned",
    )
    data = StoredCertificateDetailData(
        cert_id="cert-1",
        cert=cert,
        chain=(),
        chain_status="public",
        hostname="vpn.example.test",
        port=443,
        host=_host(),
        scan_evidence=None,
        posture={
            "grade": "B",
            "findings": [
                {
                    "check": "chain_completeness",
                    "status": "pass",
                    "message": "Certificate chain is complete",
                }
            ],
            "protocol_version": "TLSv1.3",
            "scanned_at": "2026-09-22T08:00:00+00:00",
            "chain_incomplete": False,
            "chain_status": "public",
        },
        posture_is_stored=True,
        renewal_history=[
            {
                "id": "cert-1",
                "fingerprint_sha256": "abcdef123456",
                "not_before": "2026-08-23T12:00:00+00:00",
                "is_current": True,
            }
        ],
        history_entries=[
            {
                "issuer": "CN=New CA",
                "key_algo": "RSA 2048",
                "sig_algo": "sha256",
                "posture_grade": "B",
                "scanned_at": "2026-09-22T08:00:00+00:00",
            },
            {
                "issuer": "CN=Old CA",
                "key_algo": "RSA 2048",
                "sig_algo": "sha256",
                "posture_grade": "A",
                "scanned_at": "2026-08-22T08:00:00+00:00",
            },
        ],
        cert_tags=["production"],
        effective_tags=["production", "network"],
        all_tags=["network", "production"],
    )

    view = present_certificate_detail(
        data,
        settings_writable=True,
        slack_configured=False,
        now=now,
    )

    assert view.source_label == "Scanned"
    assert view.source_meta == "scanned from vpn.example.test:443"
    assert view.renewal_method_label == "Manual"
    assert view.renewal_method_indicator == "requires manual action"
    assert view.host_info is not None
    assert view.host_info.scan_cadence_label == "Every 12 hours"
    assert view.host_info.renewal_status_label == "In progress — operator reported"
    assert view.validity_percent == 33
    assert view.shown_tags[1].inherited is True
    assert view.renewal_history[0].fingerprint_short == "abcdef12"
    assert {event.field for event in view.drift_events} == {
        "Issuer changed",
        "Posture grade dropped",
    }


def test_full_detail_presenter_builds_pending_host_view() -> None:
    data = PendingHostDetailData(
        cert_id="host-1",
        host=_host(),
        latest_scan=LatestScanRecord(
            status="failure",
            scanned_at="2026-09-22T08:00:00+00:00",
            error_message="connection refused",
        ),
        scan_evidence=None,
        all_tags=["network", "production"],
    )

    view = present_certificate_detail(
        data,
        settings_writable=False,
        slack_configured=True,
    )

    assert view.cert is None
    assert view.subject_cn == "vpn.example.test:443"
    assert view.scan_status == "failure"
    assert view.scan_error == "connection refused"
    assert view.source_label == "Monitored"
    assert view.source_meta == "last scan failed"
    assert [tag.label for tag in view.shown_tags] == ["production", "network"]
    assert view.host_info is not None
    assert view.host_info.settings_writable is False
