"""An unordered PKCS#7 certificate bag must identify the monitored certificate."""

from itertools import permutations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from cert_watch.cert_chain import validate_chain_order, validate_chain_signatures
from cert_watch.database import SqliteCertificateRepository
from cert_watch.upload import ParseError, UploadedEntry, store_uploaded, upload_certificate


@pytest.mark.parametrize("order", list(permutations(("leaf", "intermediate", "root"))))
@pytest.mark.parametrize("encoding,extension", [(Encoding.DER, ".p7b"), (Encoding.PEM, ".p7c")])
def test_pkcs7_bag_selects_leaf_and_orders_chain(
    tmp_path, chain_triplet, order, encoding, extension
):
    path = tmp_path / ("synthetic" + extension)
    path.write_bytes(pkcs7.serialize_certificates([chain_triplet[k].cert for k in order], encoding))

    entry = upload_certificate(path)

    assert isinstance(entry, UploadedEntry)
    assert [cert.fingerprint_sha256 for cert in [entry.leaf, *entry.chain]] == [
        chain_triplet[key].cert.fingerprint(hashes.SHA256()).hex()
        for key in ("leaf", "intermediate", "root")
    ]
    assert entry.leaf.is_leaf
    assert all(not cert.is_leaf for cert in entry.chain)
    assert validate_chain_order([entry.leaf, *entry.chain]) is True


def test_pkcs7_upload_persists_server_as_inventory_leaf(tmp_path, chain_triplet):
    path = tmp_path / "synthetic.p7b"
    path.write_bytes(
        pkcs7.serialize_certificates(
            [chain_triplet[key].cert for key in ("root", "leaf", "intermediate")], Encoding.DER
        )
    )
    entry = upload_certificate(path)
    assert isinstance(entry, UploadedEntry)
    database = tmp_path / "certificates.sqlite3"

    certificate_id = store_uploaded(entry, database)

    stored = SqliteCertificateRepository(database).get_by_id(certificate_id)
    assert stored is not None
    assert (
        stored.fingerprint_sha256 == chain_triplet["leaf"].cert.fingerprint(hashes.SHA256()).hex()
    )
    assert stored.not_after == entry.leaf.not_after
    assert stored.is_leaf


@pytest.mark.parametrize("encoding", [Encoding.DER, Encoding.PEM])
@pytest.mark.parametrize(
    "case",
    [
        "single",
        "partial",
        "duplicates",
        "multiple",
        "ambiguous",
        "cycle",
        "invalid-signature",
        "over-cap",
    ],
)
def test_pkcs7_chain_boundaries(tmp_path, chain_triplet, self_signed_leaf, encoding, case):
    from tests.conftest import _make_cert

    root, intermediate, leaf = [chain_triplet[key] for key in ("root", "intermediate", "leaf")]
    certs = [root.cert, leaf.cert, intermediate.cert]
    expected_error = case in {"multiple", "ambiguous", "cycle", "over-cap"}
    expected = [leaf.cert, intermediate.cert, root.cert]
    if case == "single":
        certs = expected = [self_signed_leaf.cert]
    elif case == "partial":
        certs = [intermediate.cert, leaf.cert]
        expected = [leaf.cert, intermediate.cert]
    elif case == "duplicates":
        certs += [leaf.cert, root.cert, intermediate.cert]
    elif case == "multiple":
        certs.append(self_signed_leaf.cert)
    elif case == "ambiguous":
        other = _make_cert(
            "Test Intermediate CA", issuer_cert=root.cert, issuer_key=root.key, ca=True
        )
        certs.append(other.cert)
    elif case == "cycle":
        seed = _make_cert("Cycle A", ca=True)
        b = _make_cert("Cycle B", issuer_cert=seed.cert, issuer_key=seed.key, ca=True)
        a = _make_cert("Cycle A", issuer_cert=b.cert, issuer_key=b.key, ca=True)
        tip = _make_cert("cycle.example.com", issuer_cert=a.cert, issuer_key=a.key)
        certs = [tip.cert, a.cert, b.cert]
    elif case == "invalid-signature":
        invalid = _make_cert(
            "invalid.example.com", issuer_cert=intermediate.cert, issuer_key=root.key
        )
        certs = [root.cert, invalid.cert, intermediate.cert]
        expected = [invalid.cert, intermediate.cert, root.cert]
    elif case == "over-cap":
        certs = [leaf.cert] * 101
    path = tmp_path / "synthetic.p7b"
    path.write_bytes(pkcs7.serialize_certificates(certs, encoding))

    result = upload_certificate(path)

    if expected_error:
        assert isinstance(result, ParseError)
        assert ("max 100" if case == "over-cap" else "unambiguous") in result.error_message
        return
    assert isinstance(result, UploadedEntry)
    actual = [result.leaf, *result.chain]
    assert [cert.fingerprint_sha256 for cert in actual] == [
        cert.fingerprint(hashes.SHA256()).hex() for cert in expected
    ]
    if case == "invalid-signature":
        assert validate_chain_order(actual) is True
        assert validate_chain_signatures(actual) is False
