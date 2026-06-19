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
    validate_chain_signatures,
    validate_chain_with_anchors,
    validate_is_ca_certificate,
)
from cert_watch.certificate_model import extract_chain_from_pem, parse_certificate


def _issue(subject_cn, issuer_name, issuer_key, subject_key=None):
    """Build a DER cert: subject_cn signed by issuer_key, issuer=issuer_name.

    By passing a wrong issuer_key while keeping issuer_name aligned with the
    parent's subject, we forge a cert whose NAMES link to the parent but whose
    SIGNATURE was made by an unrelated key (BC-061 attack model).
    """
    skey = subject_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(skey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, skey


def _to_cert(der_cert):
    return parse_certificate(der_cert.public_bytes(Encoding.DER))


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


def test_chain_status_public_root(chain_pem_bytes, monkeypatch):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    monkeypatch.setattr(
        "cert_watch.cert_chain._is_anchored_by_system_root", lambda chain: True
    )
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


# ---------- BC-061: signature verification, not just name matching ----------


def test_validate_chain_signatures_genuine(chain_triplet):
    """A genuinely-signed leaf->intermediate->root chain verifies."""
    certs = [
        parse_certificate(chain_triplet["leaf"].der),
        parse_certificate(chain_triplet["intermediate"].der),
        parse_certificate(chain_triplet["root"].der),
    ]
    assert validate_chain_signatures(certs) is True


def test_validate_chain_signatures_forged():
    """Names line up but a forged intermediate's signature does not verify."""
    # Self-signed root.
    root_self_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Forge Root CA")])
    root_cert, root_key = _issue("Forge Root CA", root_name, root_self_key, root_self_key)

    # Forged intermediate: issuer NAME == root's subject, but signed by an
    # ATTACKER key, not root_key. Name linkage holds; signature is bogus.
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_cert, inter_key = _issue("Forge Intermediate CA", root_name, attacker_key)
    inter_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Forge Intermediate CA")]
    )
    leaf_cert, _ = _issue("forge-leaf.example.com", inter_name, inter_key)

    chain = [_to_cert(leaf_cert), _to_cert(inter_cert), _to_cert(root_cert)]
    # Names link end to end...
    assert validate_chain_order(chain) is True
    # ...but the forged intermediate breaks signature verification.
    assert validate_chain_signatures(chain) is not True


def test_chain_status_forged_intermediate_not_public():
    """A name-matching-but-forged chain must NOT grade as public/private/valid."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Forge Root CA")])
    root_cert, _ = _issue("Forge Root CA", root_name, root_key, root_key)

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_cert, inter_key = _issue("Forge Intermediate CA", root_name, attacker_key)
    inter_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Forge Intermediate CA")]
    )
    leaf_cert, _ = _issue("forge-leaf.example.com", inter_name, inter_key)

    leaf = _to_cert(leaf_cert)
    chain = [_to_cert(inter_cert), _to_cert(root_cert)]
    anchor = _to_cert(root_cert)

    # Without anchor: not "public", not "incomplete" — graded invalid.
    assert chain_status(leaf, chain, []) == "invalid"
    # Even with the real root uploaded as an anchor, the forged link is caught.
    assert chain_status(leaf, chain, [anchor]) == "invalid"
    assert chain_status(leaf, chain, [anchor]) not in ("public", "private")


def test_chain_status_genuine_chain_private_with_anchor(chain_triplet):
    """A genuinely-signed chain is still graded 'private' when anchored."""
    leaf = parse_certificate(chain_triplet["leaf"].der)
    intermediate = parse_certificate(chain_triplet["intermediate"].der)
    root = parse_certificate(chain_triplet["root"].der)
    assert chain_status(leaf, [intermediate, root], [root]) == "private"


def test_chain_status_genuine_chain_public_root(chain_triplet, monkeypatch):
    """A genuinely-signed chain ending at its self-signed root is 'public'
    when the root is verified against the system CA store."""
    leaf = parse_certificate(chain_triplet["leaf"].der)
    intermediate = parse_certificate(chain_triplet["intermediate"].der)
    root = parse_certificate(chain_triplet["root"].der)
    monkeypatch.setattr(
        "cert_watch.cert_chain._is_anchored_by_system_root", lambda chain: True
    )
    assert chain_status(leaf, [intermediate, root], []) == "public"


def test_self_signed_cert_still_scans_no_inventory_regression(self_signed_leaf):
    """Inventory must not regress: a self-signed cert still parses + grades.

    The trust grade is 'self-signed' (honest: not cryptographically trusted),
    but the cert is fully parsed and usable — scanning/storing is unaffected.
    """
    leaf = parse_certificate(self_signed_leaf.der)
    assert leaf is not None
    assert leaf.raw_der  # stored/usable for inventory
    assert chain_status(leaf, [], []) == "self-signed"
