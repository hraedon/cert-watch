from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteCertificateRepository
from cert_watch.upload import ParseError, UploadedEntry, store_uploaded, upload_certificate


def test_upload_pem_leaf(leaf_pem_file):
    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)
    assert entry.chain == []


def test_upload_der_leaf(leaf_der_file):
    entry = upload_certificate(leaf_der_file)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)


def test_upload_pem_chain(chain_pem_file):
    entry = upload_certificate(chain_pem_file)
    assert isinstance(entry, UploadedEntry)
    assert len(entry.chain) == 2  # intermediate + root


def test_upload_pfx_no_password(pfx_file_no_password):
    entry = upload_certificate(pfx_file_no_password)
    assert isinstance(entry, UploadedEntry)
    assert isinstance(entry.leaf, Certificate)
    assert len(entry.chain) == 2


def test_upload_pfx_with_password(pfx_file_with_password):
    path, pw = pfx_file_with_password
    entry = upload_certificate(path, password=pw)
    assert isinstance(entry, UploadedEntry)
    assert len(entry.chain) == 2


def test_upload_pfx_wrong_password(pfx_file_with_password):
    path, _ = pfx_file_with_password
    err = upload_certificate(path, password=b"wrong")
    assert isinstance(err, ParseError)


def test_upload_malformed(malformed_blob):
    err = upload_certificate(malformed_blob)
    assert isinstance(err, ParseError)


def test_upload_unknown_extension(tmp_path):
    p = tmp_path / "file.xyz"
    p.write_bytes(b"random")
    err = upload_certificate(p)
    assert isinstance(err, ParseError)


def test_store_uploaded_persists_chain(tmp_path, chain_pem_file):
    entry = upload_certificate(chain_pem_file)
    assert isinstance(entry, UploadedEntry)
    db = tmp_path / "cw.sqlite3"
    leaf_id = store_uploaded(entry, db)
    repo = SqliteCertificateRepository(db)
    all_certs = repo.list_all()
    assert len(all_certs) == 3
    assert any(c.fingerprint_sha256 == entry.leaf.fingerprint_sha256 for c in all_certs)
    assert leaf_id
