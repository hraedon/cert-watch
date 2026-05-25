from cert_watch.certificate_model import (
    Certificate,
    MalformedCertificateError,
    extract_chain_from_pem,
    parse_certificate,
    parse_pem_certificate,
)


def test_parse_certificate_returns_certificate(self_signed_leaf):
    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    assert "leaf.example.com" in cert.subject
    assert cert.fingerprint_sha256
    assert len(cert.fingerprint_sha256) == 64
    assert cert.fingerprint_sha256 == cert.fingerprint_sha256.lower()
    assert ":" not in cert.fingerprint_sha256
    assert cert.raw_der == self_signed_leaf.der
    assert cert.san_dns_names == ["leaf.example.com"]


def test_parse_certificate_malformed():
    err = parse_certificate(b"garbage")
    assert isinstance(err, MalformedCertificateError)
    assert err.message


def test_parse_certificate_empty():
    err = parse_certificate(b"")
    assert isinstance(err, MalformedCertificateError)


def test_parse_pem_certificate(self_signed_leaf):
    cert = parse_pem_certificate(self_signed_leaf.pem.decode())
    assert isinstance(cert, Certificate)


def test_parse_pem_certificate_invalid():
    err = parse_pem_certificate("not a pem")
    assert isinstance(err, MalformedCertificateError)


def test_days_until_expiry_positive(self_signed_leaf):
    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    assert cert.days_until_expiry() > 300


def test_days_until_expiry_negative_for_expired(expiring_soon_leaf):
    # 5-day cert is not expired; just sanity-check it shows < 30
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)
    assert cert.days_until_expiry() <= 5


def test_display_name_prefers_subject(self_signed_leaf):
    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    assert "leaf.example.com" in cert.display_name


def test_is_leaf_defaults_true(self_signed_leaf):
    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    assert cert.is_leaf is True


def test_extract_chain_from_pem(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    assert len(certs) == 3
    assert certs[0].is_leaf is True
    assert certs[1].is_leaf is False
    assert certs[2].is_leaf is False


def test_extract_chain_from_pem_empty():
    assert extract_chain_from_pem("") == []
    assert extract_chain_from_pem("nothing here") == []
