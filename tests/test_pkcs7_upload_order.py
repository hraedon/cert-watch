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


def _fingerprints(certs):
    return [cert.fingerprint(hashes.SHA256()).hex() for cert in certs]


@pytest.fixture(scope="module")
def cross_signed(chain_triplet):
    """A public-CA style bundle: the intermediate and root are also cross-signed
    by a legacy root, reusing their keys under the same names."""
    from tests.conftest import _make_cert

    root, intermediate = chain_triplet["root"], chain_triplet["intermediate"]
    legacy = _make_cert("Legacy Root CA", days_valid=3650, ca=True)
    return {
        "legacy": legacy,
        "intermediate-cross": _make_cert(
            "Test Intermediate CA", issuer_cert=legacy.cert, issuer_key=legacy.key,
            key=intermediate.key, days_valid=365, ca=True,
        ),
        "root-cross": _make_cert(
            "Test Root CA", issuer_cert=legacy.cert, issuer_key=legacy.key,
            key=root.key, days_valid=365, ca=True,
        ),
    }


@pytest.mark.parametrize("with_legacy_root", [False, True])
@pytest.mark.parametrize("order", [(0, 1, 2, 3, 4), (4, 3, 2, 1, 0), (2, 4, 0, 3, 1)])
def test_pkcs7_cross_signed_bundle_selects_leaf_and_complete_chain(
    tmp_path, chain_triplet, cross_signed, with_legacy_root, order
):
    pool = [
        chain_triplet["leaf"].cert, chain_triplet["intermediate"].cert,
        cross_signed["intermediate-cross"].cert, chain_triplet["root"].cert,
        cross_signed["root-cross"].cert,
    ]
    certs = [pool[index] for index in order]
    if with_legacy_root:
        certs.append(cross_signed["legacy"].cert)
    path = tmp_path / "cross-signed.p7b"
    path.write_bytes(pkcs7.serialize_certificates(certs, Encoding.DER))

    entry = upload_certificate(path)

    assert isinstance(entry, UploadedEntry)
    actual = [entry.leaf, *entry.chain]
    assert [cert.fingerprint_sha256 for cert in actual] == _fingerprints(
        [chain_triplet[key].cert for key in ("leaf", "intermediate", "root")]
    )
    assert validate_chain_order(actual) is True
    assert validate_chain_signatures(actual) is True
    database = tmp_path / "certificates.sqlite3"
    stored = SqliteCertificateRepository(database).get_by_id(store_uploaded(entry, database))
    assert stored is not None and stored.is_leaf


@pytest.mark.parametrize("cross_days,chosen", [(365, "intermediate"), (3000, "cross")])
def test_pkcs7_cross_signs_without_roots_prefer_the_longest_valid_issuer(
    tmp_path, chain_triplet, cross_days, chosen
):
    from tests.conftest import _make_cert

    legacy = _make_cert("Legacy Root CA", days_valid=3650, ca=True)
    cross = _make_cert(
        "Test Intermediate CA", issuer_cert=legacy.cert, issuer_key=legacy.key,
        key=chain_triplet["intermediate"].key, days_valid=cross_days, ca=True,
    )
    leaf, intermediate = chain_triplet["leaf"].cert, chain_triplet["intermediate"].cert
    path = tmp_path / "intermediates.p7b"
    path.write_bytes(pkcs7.serialize_certificates([cross.cert, leaf, intermediate], Encoding.DER))

    entry = upload_certificate(path)

    assert isinstance(entry, UploadedEntry)
    expected = intermediate if chosen == "intermediate" else cross.cert
    assert [entry.leaf.fingerprint_sha256, *(c.fingerprint_sha256 for c in entry.chain)] == (
        _fingerprints([leaf, expected])
    )


@pytest.mark.parametrize("case", ["different-key", "unrelated", "detached-cycle"])
def test_pkcs7_cross_signs_do_not_excuse_ambiguous_bags(
    tmp_path, chain_triplet, cross_signed, self_signed_leaf, case
):
    from tests.conftest import _make_cert

    root = chain_triplet["root"]
    certs = [
        chain_triplet["leaf"].cert, chain_triplet["intermediate"].cert,
        cross_signed["intermediate-cross"].cert, root.cert,
    ]
    if case == "different-key":
        # Same name as the leaf's issuer but another key: only one of the two
        # can have issued the leaf, and the bag does not say which.
        certs.append(_make_cert(
            "Test Intermediate CA", issuer_cert=root.cert, issuer_key=root.key, ca=True,
        ).cert)
    elif case == "unrelated":
        certs.append(self_signed_leaf.cert)
    else:
        seed = _make_cert("Detached A", ca=True)
        b = _make_cert("Detached B", issuer_cert=seed.cert, issuer_key=seed.key, ca=True)
        a = _make_cert("Detached A", issuer_cert=b.cert, issuer_key=b.key, ca=True)
        certs += [a.cert, b.cert]
    path = tmp_path / "ambiguous.p7b"
    path.write_bytes(pkcs7.serialize_certificates(certs, Encoding.DER))

    result = upload_certificate(path)

    assert isinstance(result, ParseError)
    assert "unambiguous" in result.error_message


def test_pkcs7_path_search_is_bounded(tmp_path, chain_triplet, cross_signed, monkeypatch):
    import cert_watch.upload as upload

    monkeypatch.setattr(upload, "_PKCS7_PATH_STEPS", 2)
    certs = [
        chain_triplet["leaf"].cert, chain_triplet["intermediate"].cert,
        cross_signed["intermediate-cross"].cert, chain_triplet["root"].cert,
    ]
    path = tmp_path / "bounded.p7b"
    path.write_bytes(pkcs7.serialize_certificates(certs, Encoding.DER))

    result = upload_certificate(path)

    assert isinstance(result, ParseError)
    assert "unambiguous" in result.error_message
