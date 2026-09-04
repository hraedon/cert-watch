"""Operator guidance follows the stored chain, without fetching issuer URLs."""
import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import extract_chain_from_pem
from cert_watch.database import store_scan_posture
from cert_watch.upload import store_uploaded, upload_certificate


def test_detail_names_untrusted_root_and_gives_remediation(reload_app, tmp_path, chain_pem_file):
    app_mod = reload_app()
    entry = upload_certificate(chain_pem_file)
    cert_id = store_uploaded(entry, tmp_path / "cert-watch.sqlite3")
    with TestClient(app_mod.app) as client:
        response = client.get(f"/certificates/{cert_id}")
    assert response.status_code == 200
    assert "Root certificate is present but not trusted" in response.text
    assert "Settings → Trust anchors" in response.text
    assert "server missing intermediate(s)" not in response.text


@pytest.mark.parametrize("stored_status", ["public", None])
def test_detail_labels_stale_chain_posture(reload_app, tmp_path, chain_pem_file, stored_status):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    entry = upload_certificate(chain_pem_file)
    cert_id = store_uploaded(entry, db)
    store_scan_posture(db, cert_id, None, None, "A+", [
        {"check": "chain_completeness", "status": "pass", "message": "Chain complete"},
        {"check": "tls_version", "status": "pass", "message": "TLS TLSv1.3"},
    ], chain_status=stored_status, protocol_version="TLSv1.3",
        scanned_at="2026-09-01T12:00:00+00:00")
    with TestClient(app_mod.app) as client:
        response = client.get(f"/certificates/{cert_id}")
    assert response.status_code == 200
    assert 'data-testid="chain-posture-changed"' in response.text
    assert "Last scan grade" in response.text
    assert "Chain complete</span>" not in response.text
    assert "TLS TLSv1.3" in response.text


def test_guidance_names_gap_and_distinguishes_untrusted_root(chain_pem_bytes):
    from cert_watch.chain_guidance import describe_chain

    leaf, intermediate, root = extract_chain_from_pem(chain_pem_bytes.decode())
    gap = describe_chain(leaf, [root], "invalid")
    assert gap.expected_issuer == intermediate.subject
    assert gap.kind == "missing_issuer"
    assert "intermediate" in gap.remediation
    trust = describe_chain(leaf, [intermediate, root], "incomplete")
    assert trust.kind == "untrusted_root"
    assert root.subject in trust.explanation
    assert trust.expected_issuer == ""


def test_leaf_only_guidance_does_not_guess_issuer_type(chain_pem_bytes):
    from cert_watch.chain_guidance import describe_chain

    leaf, intermediate, _root = extract_chain_from_pem(chain_pem_bytes.decode())
    guidance = describe_chain(leaf, [], "unknown")
    assert guidance.expected_issuer == intermediate.subject
    assert "intermediate or a root" in guidance.explanation
    assert "server is missing" not in guidance.explanation
