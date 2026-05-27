from cert_watch.cert_chain import (
    chain_status,
    deduplicate_chain,
    is_anchored_by_user,
    split_leaf_intermediates,
    validate_chain_order,
    validate_chain_with_anchors,
)
from cert_watch.certificate_model import Certificate, extract_chain_from_pem, parse_certificate


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
