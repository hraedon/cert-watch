from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.presenters.certificate_detail import present_certificate_technical_details
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
