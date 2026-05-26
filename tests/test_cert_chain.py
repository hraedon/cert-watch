from cert_watch.cert_chain import (
    deduplicate_chain,
    split_leaf_intermediates,
    validate_chain_order,
)
from cert_watch.certificate_model import extract_chain_from_pem


def test_validate_chain_order_correct(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    assert validate_chain_order(certs) is True


def test_validate_chain_order_reversed(chain_pem_bytes):
    certs = extract_chain_from_pem(chain_pem_bytes.decode())
    assert validate_chain_order(list(reversed(certs))) is False


def test_validate_chain_order_empty_and_single(self_signed_leaf):
    assert validate_chain_order([]) is None
    from cert_watch.certificate_model import parse_certificate

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
