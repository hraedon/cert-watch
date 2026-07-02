from cryptography.hazmat.primitives import hashes

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteCertificateRepository
from cert_watch.upload import ParseError, UploadedEntry, store_uploaded, upload_certificate


def _fp(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def test_upload_pem_leaf(leaf_pem_file, self_signed_leaf):
    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)
    assert entry.chain == []
    # Subject and fingerprint must round-trip from the bytes we wrote.
    assert entry.leaf.fingerprint_sha256 == _fp(self_signed_leaf.cert)
    assert "leaf.example.com" in entry.leaf.subject


def test_upload_der_leaf(leaf_der_file, self_signed_leaf):
    entry = upload_certificate(leaf_der_file)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)
    # DER is the same certificate as PEM (modulo encoding) — fingerprint must match.
    assert entry.leaf.fingerprint_sha256 == _fp(self_signed_leaf.cert)


def test_upload_pem_chain(chain_pem_file, chain_triplet):
    entry = upload_certificate(chain_pem_file)
    assert isinstance(entry, UploadedEntry)
    assert len(entry.chain) == 2  # intermediate + root
    # Subject is stored in RFC4514 form (CN=Test Intermediate CA, etc.).
    chain_subjects = [c.subject for c in entry.chain]
    assert "CN=Test Intermediate CA" in chain_subjects
    assert "CN=Test Root CA" in chain_subjects
    # The leaf must be the first cert the parser picked (chain-leaf.example.com).
    assert "CN=chain-leaf.example.com" in entry.leaf.subject


def test_upload_pfx_no_password(pfx_file_no_password):
    entry = upload_certificate(pfx_file_no_password)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)
    assert len(entry.chain) == 2
    # PKCS#12 must surface the same intermediate/root as the PEM bundle.
    chain_subjects = sorted(c.subject for c in entry.chain)
    assert "CN=Test Intermediate CA" in chain_subjects
    assert "CN=Test Root CA" in chain_subjects


def test_upload_pfx_with_password(pfx_file_with_password):
    path, pw = pfx_file_with_password
    entry = upload_certificate(path, password=pw)
    assert isinstance(entry, UploadedEntry)
    assert len(entry.chain) == 2
    assert "CN=chain-leaf.example.com" in entry.leaf.subject


def test_upload_pfx_wrong_password(pfx_file_with_password):
    path, _ = pfx_file_with_password
    err = upload_certificate(path, password=b"wrong")
    assert isinstance(err, ParseError)
    # The error message must clearly indicate the password problem so the
    # operator can fix it; not just "could not parse" which could mean anything.
    assert err.error_message and "password" in err.error_message.lower()


def test_upload_p7b_der(p7b_der_file):
    entry = upload_certificate(p7b_der_file)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)
    assert len(entry.chain) >= 1
    # PKCS#7 cert bag must contain the intermediate and the root (3 total).
    all_subjects = [entry.leaf.subject] + [c.subject for c in entry.chain]
    assert "CN=Test Intermediate CA" in all_subjects
    assert "CN=Test Root CA" in all_subjects


def test_upload_p7c_pem(p7c_pem_file):
    entry = upload_certificate(p7c_pem_file)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)
    assert len(entry.chain) >= 1
    all_subjects = [entry.leaf.subject] + [c.subject for c in entry.chain]
    assert "CN=Test Intermediate CA" in all_subjects
    assert "CN=Test Root CA" in all_subjects


def test_upload_malformed(malformed_blob):
    err = upload_certificate(malformed_blob)
    assert isinstance(err, ParseError)
    # The error must distinguish "garbage bytes" from "couldn't open" — a
    # silent success would let a user upload a non-cert and get a dashboard
    # row with no data.
    assert err.error_message and (
        "parse" in err.error_message.lower()
        or "decode" in err.error_message.lower()
        or "expected" in err.error_message.lower()
    )


def test_upload_unknown_extension(tmp_path):
    p = tmp_path / "file.xyz"
    p.write_bytes(b"random")
    err = upload_certificate(p)
    assert isinstance(err, ParseError)
    # The error must mention the unknown extension so the user knows what to fix.
    assert (
        ".xyz" in err.error_message
        or "extension" in err.error_message.lower()
        or "unsupported" in err.error_message.lower()
    )


def test_store_uploaded_persists_chain(tmp_path, chain_pem_file, chain_triplet):
    entry = upload_certificate(chain_pem_file)
    assert isinstance(entry, UploadedEntry)
    db = tmp_path / "cw.sqlite3"
    leaf_id = store_uploaded(entry, db)
    repo = SqliteCertificateRepository(db)
    all_certs = repo.list_all()
    # Leaf + intermediate + root must all be persisted (3 distinct certs).
    assert len(all_certs) == 3
    # The leaf we uploaded must be retrievable by the returned id.
    fetched = repo.get_by_id(leaf_id)
    assert fetched is not None
    assert fetched.fingerprint_sha256 == entry.leaf.fingerprint_sha256
    # The intermediate and root must be in the DB too — distinct fingerprints
    # from the leaf (a duplicate-leaf bug would let this test pass silently).
    expected_others = {
        _fp(chain_triplet["intermediate"].cert),
        _fp(chain_triplet["root"].cert),
    }
    leaf_fp = entry.leaf.fingerprint_sha256
    actual_others = {
        c.fingerprint_sha256 for c in all_certs if c.fingerprint_sha256 != leaf_fp
    }
    assert actual_others == expected_others
    assert leaf_id


# ── PKCS#7 cert count cap ───────────────────────────────────────────────────


class TestUploadCertCountCap:
    """PKCS#7 with > 100 certs must be rejected."""

    def test_pkcs7_accepts_small_bundle(self, chain_triplet):
        from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

        from cert_watch.upload import ParseError, _parse_pkcs7

        der = pkcs7.serialize_certificates(
            [chain_triplet["leaf"].cert, chain_triplet["intermediate"].cert],
            Encoding.DER,
        )
        result = _parse_pkcs7("test.p7b", der)
        assert not isinstance(result, ParseError), "2 certs should be fine"
