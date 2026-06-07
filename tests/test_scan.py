import subprocess
from unittest.mock import MagicMock, patch

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import SqliteCertificateRepository
from cert_watch.scan import (
    ScanError,
    ScannedEntry,
    _friendly_scan_error,
    _resolve_host,
    _scan_via_openssl,
    resolve_and_validate_host,
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


def _fake_open_ok(der_chain):
    def _open(hostname, port, timeout, **kw):
        return _fake_ssl_socket(der_chain)
    return _open


def _fake_open_err(exc):
    def _open(hostname, port, timeout, **kw):
        raise exc
    return _open


def test_scan_host_success_native(monkeypatch, chain_triplet):
    """Test native Python TLS path (Python 3.13+ chain API)."""
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]

    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection", _fake_open_ok(der_chain),
    )
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
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        _fake_open_err(ConnectionRefusedError("refused")),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    result = scan_host("nowhere.invalid", 443)
    assert isinstance(result, ScanError)
    assert "refused" in result.error_message


def test_scan_host_timeout_native(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        _fake_open_err(TimeoutError("timed out")),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    result = scan_host("slow.invalid", 443)
    assert isinstance(result, ScanError)


def test_scan_host_no_cert_native(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection", _fake_open_ok([]),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    result = scan_host("noisy.invalid", 443)
    assert isinstance(result, ScanError)


def test_scan_host_via_openssl_success(monkeypatch, chain_triplet):
    """Test that the openssl fallback path returns leaf + chain from a single connection."""
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]

    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: (der_chain, "TLSv1.3"),
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
        "cert_watch.scan._open_tls_connection", _fake_open_ok(der_chain),
    )

    result = scan_host("example.com", 443)
    assert isinstance(result, ScannedEntry)
    assert result.chain == []
    assert result.chain_incomplete is True


def test_scan_host_via_openssl_connection_failure(monkeypatch):
    """Test that openssl fallback propagates connection errors."""
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )

    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        _fake_open_err(ConnectionRefusedError("refused")),
    )

    result = scan_host("nowhere.invalid", 443)
    assert isinstance(result, ScanError)
    assert "refused" in result.error_message


def test_store_scanned_with_db_path(tmp_path, chain_triplet, monkeypatch):
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection", _fake_open_ok(der_chain),
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


# ---------- _scan_via_openssl internal branch coverage (BC-155) ----------


def _pem_block(der: bytes) -> bytes:
    """Wrap DER bytes in a PEM certificate block."""
    import base64

    b64 = base64.b64encode(der).decode("ascii")
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + b64.encode("ascii")
        + b"\n-----END CERTIFICATE-----\n"
    )


def test_openssl_dns_resolution_failure(monkeypatch):
    """OSError during DNS resolution returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("DNS failed")),
    )
    chain, proto = _scan_via_openssl("nonexistent.invalid", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_blocked_pinned_ip(monkeypatch):
    """A pinned loopback IP is blocked, returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("should not resolve")),
    )
    chain, proto = _scan_via_openssl(
        "example.com", 443, timeout=1, pinned_ip="127.0.0.1"
    )
    assert chain == []
    assert proto == ""


def test_openssl_hostname_injection_blocked(monkeypatch):
    """Hostname starting with '-' is rejected to prevent argument injection."""
    chain, proto = _scan_via_openssl("-malicious", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_timeout_expired(monkeypatch, self_signed_leaf):
    """subprocess.TimeoutExpired returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    mock_proc = MagicMock()
    mock_proc.configure_mock(
        returncode=1,
        stdout=b"",
        stderr=b"timeout",
    )
    with patch("cert_watch.scan.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["openssl"], timeout=1)
        chain, proto = _scan_via_openssl("slow.example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_file_not_found(monkeypatch):
    """FileNotFoundError (no openssl binary) returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    with patch("cert_watch.scan.subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("no openssl")
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_nonzero_return(monkeypatch):
    """Non-zero, non-one return code returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = b""
    mock_proc.stderr = b"some error"
    with patch("cert_watch.scan.subprocess.run", return_value=mock_proc):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_no_pem_in_output(monkeypatch):
    """Output with no PEM blocks returns empty chain (protocol still extracted)."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = b"Protocol  : TLSv1.3\nNo certs here\n"
    mock_proc.stderr = b""
    with patch("cert_watch.scan.subprocess.run", return_value=mock_proc):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == "TLSv1.3"


def test_openssl_invalid_base64_skipped(monkeypatch, self_signed_leaf):
    """Invalid base64 in a PEM block is skipped gracefully."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    valid_pem = _pem_block(self_signed_leaf.der)
    invalid_pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"!!!not-base64!!!"
        b"\n-----END CERTIFICATE-----\n"
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = valid_pem + invalid_pem
    mock_proc.stderr = b""
    with patch("cert_watch.scan.subprocess.run", return_value=mock_proc):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert len(chain) == 1
    assert chain[0] == self_signed_leaf.der


def test_openssl_success_with_protocol(monkeypatch, chain_triplet):
    """Full success path: chain + protocol version extracted."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    combined = _pem_block(chain_triplet["leaf"].der) + _pem_block(
        chain_triplet["intermediate"].der
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = b"Protocol  : TLSv1.2\n" + combined
    mock_proc.stderr = b"verify error"
    with patch("cert_watch.scan.subprocess.run", return_value=mock_proc):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert len(chain) == 2
    assert chain[0] == chain_triplet["leaf"].der
    assert chain[1] == chain_triplet["intermediate"].der
    assert proto == "TLSv1.2"


def test_openssl_oserror_during_run(monkeypatch):
    """OSError during subprocess.run (e.g., permission denied) returns empty."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    with patch("cert_watch.scan.subprocess.run") as mock_run:
        mock_run.side_effect = OSError("permission denied")
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


# ---------- _friendly_scan_error coverage ----------


def test_friendly_error_connection_refused():
    err = _friendly_scan_error(ConnectionRefusedError("Connection refused"))
    assert "Connection refused" in err


def test_friendly_error_timeout():
    err = _friendly_scan_error(TimeoutError("timed out"))
    assert "timed out" in err


def test_friendly_error_dns_failure():
    err = _friendly_scan_error(OSError("Name or service not known"))
    assert "resolve hostname" in err


def test_friendly_error_blocked_address():
    err = _friendly_scan_error(OSError("pinned IP 127.0.0.1 is a blocked address"))
    assert "blocked address" in err


def test_friendly_error_network_unreachable():
    err = _friendly_scan_error(OSError("Network is unreachable"))
    assert "Network unreachable" in err


def test_friendly_error_generic_oserror():
    err = _friendly_scan_error(OSError("some weird error"))
    assert "Connection failed" in err


def test_friendly_error_errno_refused(monkeypatch):
    import errno

    exc = OSError("connection error")
    exc.errno = errno.ECONNREFUSED
    err = _friendly_scan_error(exc)
    assert "Connection refused" in err


def test_friendly_error_unknown_exception():
    err = _friendly_scan_error(ValueError("bad value"))
    assert "bad value" in err


# ---------- _resolve_host coverage ----------


def test_resolve_host_all_blocked(monkeypatch):
    """When every resolved IP is blocked, OSError is raised."""
    import pytest

    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [(2, ("127.0.0.1", 443))],
    )
    with pytest.raises(OSError, match="blocked"):
        _resolve_host("loopback.example.com", 443)


def test_resolve_host_dns_failure(monkeypatch):
    """When DNS returns no results, OSError is raised."""
    import pytest

    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [],
    )
    with pytest.raises(OSError, match="DNS resolution failed"):
        _resolve_host("nonexistent.invalid", 443)


# ---------- resolve_and_validate_host coverage (BC-095 SSRF pre-check) ----------


def test_validate_host_no_dns_returns_none(monkeypatch):
    """Empty DNS result is a soft pass: (None, None), no pinned IP."""
    monkeypatch.setattr("cert_watch.scan.resolve_hostname", lambda *a, **kw: [])
    assert resolve_and_validate_host("nothing.invalid", 443) == (None, None)


def test_validate_host_all_unparseable_returns_none(monkeypatch):
    """When every entry is unparseable, validation soft-passes (None, None)."""
    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [(2, ("not-an-ip", 443))],
    )
    assert resolve_and_validate_host("garbage.invalid", 443) == (None, None)


def test_resolve_host_fallback_raises_when_no_usable_ip(monkeypatch):
    """If validation soft-passes but no IP is usable, _resolve_host raises."""
    import pytest

    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [(2, ("not-an-ip", 443))],
    )
    with pytest.raises(OSError, match="blocked addresses"):
        _resolve_host("garbage.invalid", 443)


def test_validate_host_returns_pinned_ip_for_allowed(monkeypatch):
    """First allowed public address is pinned to prevent DNS rebinding."""
    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [(2, ("93.184.216.34", 443))],
    )
    err, pinned = resolve_and_validate_host("example.com", 443)
    assert err is None
    assert pinned == "93.184.216.34"


def test_validate_host_skips_none_and_bad_ip_then_pins(monkeypatch):
    """A None sockaddr and an unparseable IP are skipped before the good one."""
    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [
            (2, (None, 443)),
            (2, ("not-an-ip", 443)),
            (2, ("93.184.216.34", 443)),
        ],
    )
    err, pinned = resolve_and_validate_host("example.com", 443)
    assert err is None
    assert pinned == "93.184.216.34"


def test_validate_host_private_blocked_when_disallowed(monkeypatch):
    """Private IP with allow_private=False yields the ALLOW_PRIVATE_IPS hint."""
    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [(2, ("10.0.0.5", 443))],
    )
    err, pinned = resolve_and_validate_host("internal.example.com", 443, allow_private=False)
    assert pinned is None
    assert "CERT_WATCH_ALLOW_PRIVATE_IPS" in err


def test_validate_host_private_outside_allowed_subnets(monkeypatch):
    """Private IP outside configured allowed subnets points at the subnet config."""
    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [(2, ("10.0.0.5", 443))],
    )
    err, pinned = resolve_and_validate_host(
        "internal.example.com",
        443,
        allow_private=False,
        allowed_subnets=("192.168.0.0/16",),
    )
    assert pinned is None
    assert "CERT_WATCH_ALLOWED_SUBNETS" in err


def test_validate_host_public_blocked_address(monkeypatch):
    """A non-private blocked address (loopback) yields a plain blocked message."""
    monkeypatch.setattr(
        "cert_watch.scan.resolve_hostname",
        lambda *a, **kw: [(2, ("127.0.0.1", 443))],
    )
    err, pinned = resolve_and_validate_host("loopback.example.com", 443, allow_private=False)
    assert pinned is None
    assert "blocked address" in err
