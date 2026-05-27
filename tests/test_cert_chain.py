from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from cert_watch.cert_chain import (
    chain_status,
    deduplicate_chain,
    is_anchored_by_user,
    split_leaf_intermediates,
    validate_chain_order,
    validate_chain_with_anchors,
    validate_is_ca_certificate,
)
from cert_watch.certificate_model import extract_chain_from_pem, parse_certificate


def _make_ca_cert(ca: bool) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None),
            critical=True,
        )
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


def test_validate_chain_order_correct(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    assert validate_chain_order(certs) is True


def test_validate_chain_order_reversed(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    assert validate_chain_order(list(reversed(certs))) is False


def test_validate_chain_order_empty_and_single(self_signed_leaf):
    assert validate_chain_order([]) is None

    leaf = parse_certificate(self_signed_leaf.der)
    assert validate_chain_order([leaf]) is None


def test_split_leaf_intermediates(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    leaf, intermediates = split_leaf_intermediates(certs)
    assert leaf is not None
    assert leaf.is_leaf is True
    assert len(intermediates) == 2


def test_split_leaf_intermediates_empty():
    leaf, ints = split_leaf_intermediates([])
    assert leaf is None
    assert ints == []


def test_deduplicate_chain(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    duped = certs + [certs[0], certs[1]]
    out = deduplicate_chain(duped)
    assert len(out) == 3
    # Order preserved.
    assert out[0].fingerprint_sha256 == certs[0].fingerprint_sha256


# ---------- chain_status ----------

def test_chain_status_self_signed(self_signed_leaf):
    leaf = parse_certificate(self_signed_leaf.der)
    assert chain_status(leaf, [], []) == "self-signed"


def test_chain_status_unknown_no_chain(chain_triplet):
    leaf = parse_certificate(chain_triplet["leaf"].der)
    assert chain_status(leaf, [], []) == "unknown"


def test_chain_status_public_root(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    assert chain_status(certs[0], certs[1:], []) == "public"


def test_chain_status_invalid(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    assert chain_status(certs[0], list(reversed(certs[1:])), []) == "invalid"


def test_chain_status_incomplete(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    # Drop the root so the chain ends at an intermediate
    incomplete = certs[:-1]
    assert chain_status(incomplete[0], incomplete[1:], []) == "incomplete"


def test_chain_status_private_with_anchor(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    root = certs[-1]
    assert chain_status(certs[0], certs[1:-1], [root]) == "private"


def test_is_anchored_by_user_fingerprint_match(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    root = certs[-1]
    assert is_anchored_by_user(certs, [root]) is True


def test_is_anchored_by_user_issuer_subject_match(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    root = certs[-1]
    # Remove the root from chain so last.issuer == anchor.subject
    assert is_anchored_by_user(certs[:-1], [root]) is True


def test_validate_chain_with_anchors_empty():
    assert validate_chain_with_anchors([], []) is False


def test_validate_chain_with_anchors_self_signed(self_signed_leaf):
    leaf = parse_certificate(self_signed_leaf.der)
    assert validate_chain_with_anchors([leaf], []) is True


def test_validate_chain_with_anchors_missing_root(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    # Without root, chain is structurally valid but not anchored
    assert validate_chain_with_anchors(certs[:-1], []) is False


def test_validate_chain_with_anchors_with_root(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    root = certs[-1]
    assert validate_chain_with_anchors(certs, [root]) is True


# ---------- validate_is_ca_certificate (BC-026) ----------


def test_validate_is_ca_valid_root():
    der = _make_ca_cert(ca=True)
    assert validate_is_ca_certificate(der) is None


def test_validate_is_ca_non_ca_cert():
    der = _make_ca_cert(ca=False)
    result = validate_is_ca_certificate(der)
    assert result is not None
    assert "CA=FALSE" in result


def test_validate_is_ca_no_basic_constraints():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No BC")])
    der = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )
    result = validate_is_ca_certificate(der)
    assert result is not None
    assert "BasicConstraints" in result


def test_validate_is_ca_invalid_der():
    result = validate_is_ca_certificate(b"not-a-certificate")
    assert result == "failed to parse certificate"


def test_validate_is_ca_empty_der():
    result = validate_is_ca_certificate(b"")
    assert result == "failed to parse certificate"
