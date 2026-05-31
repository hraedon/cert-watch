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


def test_scan_host_success_native(monkeypatch, chain_triplet):
    """Test native Python TLS path (Python 3.13+ chain API)."""
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]

    def fake_open(hostname, port, timeout, verify=False, allow_private=False, dns_servers=()):
        return _fake_ssl_socket(der_chain)

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    result = scan_host("example.com", 443)
    assert isinstance(result, ScannedEntry)
    expected_leaf = parse_certificate(chain_triplet["leaf"].der)
    assert isinstance(expected_leaf, Certificate)
    assert result.leaf.fingerprint_sha256 == expected_leaf.fingerprint_sha256
    assert result.leaf.raw_der == expected_leaf.raw_der
    assert result.host == "example.com"
    assert result.port == 443


def test_scan_host_connection_failure_native(monkeypatch):
    """Test that connection errors are reported correctly on native path."""
    def fake_open(hostname, port, timeout, verify=False, allow_private=False, dns_servers=()):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    result = scan_host("nowhere.invalid", 443)
    assert isinstance(result, ScanError)
    assert "refused" in result.error_message


def test_scan_host_timeout_native(monkeypatch):
    def fake_open(hostname, port, timeout, verify=False, allow_private=False, dns_servers=()):
        raise TimeoutError("timed out")

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    result = scan_host("slow.invalid", 443)
    assert isinstance(result, ScanError)


def test_scan_host_no_cert_native(monkeypatch):
    def fake_open(hostname, port, timeout, verify=False, allow_private=False, dns_servers=()):
        return _fake_ssl_socket([])

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    result = scan_host("noisy.invalid", 443)
    assert isinstance(result, ScanError)


def test_scan_host_via_openssl_success(monkeypatch, chain_triplet):
    """Test that the openssl fallback path returns leaf + chain from a single connection."""
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]

    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda hostname, port, timeout, allow_private=True, dns_servers=(): (der_chain, "TLSv1.3"),
    )

    result = scan_host("example.com", 443)
    assert isinstance(result, ScannedEntry)
    expected_leaf = parse_certificate(chain_triplet["leaf"].der)
    assert isinstance(expected_leaf, Certificate)
    assert result.leaf.fingerprint_sha256 == expected_leaf.fingerprint_sha256
    assert len(result.chain) == 1


def test_scan_host_via_openssl_fallback_to_leaf_only(monkeypatch, chain_triplet):
    """Test that when openssl fails, we fall back to Python TLS for leaf-only."""
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )

    der_chain = [chain_triplet["leaf"].der]
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda h, p, t, verify=False, allow_private=True, dns_servers=():
            _fake_ssl_socket(der_chain),
    )

    result = scan_host("example.com", 443)
    assert isinstance(result, ScannedEntry)
    assert result.chain == []


def test_scan_host_via_openssl_connection_failure(monkeypatch):
    """Test that openssl fallback propagates connection errors."""
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )

    def fake_open(hostname, port, timeout, verify=False, allow_private=True, dns_servers=()):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", fake_open)

    result = scan_host("nowhere.invalid", 443)
    assert isinstance(result, ScanError)
    assert "refused" in result.error_message


def test_store_scanned_with_db_path(tmp_path, chain_triplet, monkeypatch):
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda h, p, t, verify=False, allow_private=False, dns_servers=():
            _fake_ssl_socket(der_chain),
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
    from cert_watch.database.schema import init_schema
    init_schema(db)
    repo = SqliteCertificateRepository(db, source="scanned")
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])
    leaf_id = store_scanned(entry, repo)
    assert leaf_id
