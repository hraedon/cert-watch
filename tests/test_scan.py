from unittest.mock import MagicMock

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import SqliteCertificateRepository
from cert_watch.scan import (
    ScanError,
    ScannedEntry,
    scan_host,
    store_scanned,
)


def _fake_ssl_socket(der_chain: list[bytes]) -> MagicMock:
    sock = MagicMock(spec=["getpeercert", "get_unverified_chain", "close"])
    sock.getpeercert.return_value = der_chain[0] if der_chain else None

    class _FakeCert:
        def __init__(self, der: bytes) -> None:
            self._der = der

        def public_bytes(self, _encoding):
            return self._der

    sock.get_unverified_chain.return_value = [_FakeCert(d) for d in der_chain]
    sock.close.return_value = None
    return sock


def test_scan_host_success(monkeypatch, chain_triplet):
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]

    def fake_open(hostname, port, timeout):
        return _fake_ssl_socket(der_chain)

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)

    result = scan_host("example.com", 443)
    assert isinstance(result, ScannedEntry)
    # AC-04: must equal parse_certificate(handshake_der)
    expected_leaf = parse_certificate(chain_triplet["leaf"].der)
    assert isinstance(expected_leaf, Certificate)
    assert result.leaf.fingerprint_sha256 == expected_leaf.fingerprint_sha256
    assert result.leaf.raw_der == expected_leaf.raw_der
    assert result.host == "example.com"
    assert result.port == 443


def test_scan_host_connection_failure(monkeypatch):
    def fake_open(hostname, port, timeout):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)
    result = scan_host("nowhere.invalid", 443)
    assert isinstance(result, ScanError)
    assert "refused" in result.error_message


def test_scan_host_timeout(monkeypatch):
    def fake_open(hostname, port, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)
    result = scan_host("slow.invalid", 443)
    assert isinstance(result, ScanError)


def test_scan_host_no_cert(monkeypatch):
    def fake_open(hostname, port, timeout):
        return _fake_ssl_socket([])

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)
    result = scan_host("noisy.invalid", 443)
    assert isinstance(result, ScanError)


def test_store_scanned_with_db_path(tmp_path, chain_triplet, monkeypatch):
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda h, p, t: _fake_ssl_socket(der_chain),
    )
    result = scan_host("example.com", 443)
    assert isinstance(result, ScannedEntry)
    db = tmp_path / "cw.sqlite3"
    leaf_id = store_scanned(result, db)
    assert leaf_id
    repo = SqliteCertificateRepository(db)
    assert len(repo.list_all()) == 2


def test_store_scanned_with_repo(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    repo = SqliteCertificateRepository(db, source="scanned")
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])
    leaf_id = store_scanned(entry, repo)
    assert leaf_id
