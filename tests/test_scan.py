import asyncio
import socket
import ssl
import sys
from unittest.mock import MagicMock, patch

import pytest

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import SqliteCertificateRepository
from cert_watch.scan import (
    ScanError,
    ScannedEntry,
    _friendly_scan_error,
    _PostureEval,
    _scan_host_once,
    _scan_host_via_openssl,
    scan_host,
    scan_host_async,
    store_scanned,
    store_scanned_async,
)
from cert_watch.scan_conn import (
    ScanOutputTooLargeError,
    _format_connect_host,
    _get_chain_der,
    _open_tls_connection,
    _probe_hsts,
    _run_openssl,
    _scan_via_openssl,
)
from cert_watch.scan_resolver import (
    _parse_allowed_subnets,
    _resolve_host,
    _resolve_with_dns,
    resolve_and_validate_host,
    resolve_hostname,
)


def _fake_ssl_socket(der_chain: list[bytes]) -> MagicMock:
    sock = MagicMock(spec=["getpeercert", "get_unverified_chain", "version", "close"])
    sock.getpeercert.return_value = der_chain[0] if der_chain else None
    sock.version.return_value = "TLSv1.3"

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
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("DNS failed")),
    )
    chain, proto = _scan_via_openssl("nonexistent.invalid", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_blocked_pinned_ip(monkeypatch):
    """A pinned loopback IP is blocked, returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
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
    """TimeoutError from the subprocess helper returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    with patch("cert_watch.scan_conn._run_openssl") as mock_run:
        mock_run.side_effect = TimeoutError("timed out")
        chain, proto = _scan_via_openssl("slow.example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_file_not_found(monkeypatch):
    """FileNotFoundError (no openssl binary) returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    with patch("cert_watch.scan_conn._run_openssl") as mock_run:
        mock_run.side_effect = FileNotFoundError("no openssl")
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_nonzero_return(monkeypatch):
    """Non-zero, non-one return code returns empty chain."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    with patch("cert_watch.scan_conn._run_openssl", return_value=(b"", b"some error", 2)):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


def test_openssl_no_pem_in_output(monkeypatch):
    """Output with no PEM blocks returns empty chain (protocol still extracted)."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    stdout = b"Protocol  : TLSv1.3\nNo certs here\n"
    with patch("cert_watch.scan_conn._run_openssl", return_value=(stdout, b"", 0)):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == "TLSv1.3"


def test_openssl_invalid_base64_skipped(monkeypatch, self_signed_leaf):
    """Invalid base64 in a PEM block is skipped gracefully."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    valid_pem = _pem_block(self_signed_leaf.der)
    invalid_pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"!!!not-base64!!!"
        b"\n-----END CERTIFICATE-----\n"
    )
    with patch(
        "cert_watch.scan_conn._run_openssl", return_value=(valid_pem + invalid_pem, b"", 0),
    ):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert len(chain) == 1
    assert chain[0] == self_signed_leaf.der


def test_openssl_success_with_protocol(monkeypatch, chain_triplet):
    """Full success path: chain + protocol version extracted."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    combined = _pem_block(chain_triplet["leaf"].der) + _pem_block(
        chain_triplet["intermediate"].der
    )
    stdout = b"Protocol  : TLSv1.2\n" + combined
    with patch(
        "cert_watch.scan_conn._run_openssl", return_value=(stdout, b"verify error", 1),
    ):
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert len(chain) == 2
    assert chain[0] == chain_triplet["leaf"].der
    assert chain[1] == chain_triplet["intermediate"].der
    assert proto == "TLSv1.2"


def test_openssl_oserror_during_run(monkeypatch):
    """OSError during subprocess execution (e.g., permission denied) returns empty."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    with patch("cert_watch.scan_conn._run_openssl") as mock_run:
        mock_run.side_effect = OSError("permission denied")
        chain, proto = _scan_via_openssl("example.com", 443, timeout=1)
    assert chain == []
    assert proto == ""


# ---------- _format_connect_host (WI-036) ----------


def test_format_connect_host_ipv4():
    assert _format_connect_host("93.184.216.34") == "93.184.216.34"


def test_format_connect_host_ipv6_loopback():
    assert _format_connect_host("::1") == "[::1]"


def test_format_connect_host_ipv6_full():
    assert _format_connect_host("2001:db8::1") == "[2001:db8::1]"


def test_format_connect_host_ipv6_mapped():
    assert _format_connect_host("::ffff:192.0.2.1") == "[::ffff:192.0.2.1]"


def test_format_connect_host_hostname():
    assert _format_connect_host("example.com") == "example.com"


def test_format_connect_host_hostname_with_dots():
    assert _format_connect_host("sub.example.com") == "sub.example.com"


# ---------- _scan_via_openssl IPv6 -connect argument (WI-036) ----------


def test_scan_via_openssl_ipv4_pinned_ip_connect_arg(monkeypatch):
    """IPv4 pinned_ip produces '-connect 93.184.216.34:443'."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("should not resolve")),
    )
    with patch("cert_watch.scan_conn._run_openssl", return_value=(b"", b"", 0)) as mock_run:
        _scan_via_openssl("example.com", 443, timeout=1, pinned_ip="93.184.216.34")
    cmd = mock_run.call_args[0][0]
    connect_idx = cmd.index("-connect")
    assert cmd[connect_idx + 1] == "93.184.216.34:443"


def test_scan_via_openssl_ipv6_pinned_ip_connect_arg(monkeypatch):
    """IPv6 pinned_ip produces '-connect [2001:db8::1]:443'."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("should not resolve")),
    )
    with patch("cert_watch.scan_conn._run_openssl", return_value=(b"", b"", 0)) as mock_run:
        _scan_via_openssl(
            "example.com", 443, timeout=1, pinned_ip="2001:db8::1",
            allow_private=True, allowed_subnets=("2001:db8::/32",),
        )
    cmd = mock_run.call_args[0][0]
    connect_idx = cmd.index("-connect")
    assert cmd[connect_idx + 1] == "[2001:db8::1]:443"


def test_scan_via_openssl_resolved_ipv6_connect_arg(monkeypatch):
    """When DNS resolves to an IPv6 address, '-connect' uses brackets."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (socket.AF_INET6, ("2001:db8::1", 443, 0, 0)),
    )
    with patch("cert_watch.scan_conn._run_openssl", return_value=(b"", b"", 0)) as mock_run:
        _scan_via_openssl(
            "example.com", 443, timeout=1,
            allow_private=True, allowed_subnets=("2001:db8::/32",),
        )
    cmd = mock_run.call_args[0][0]
    connect_idx = cmd.index("-connect")
    assert cmd[connect_idx + 1] == "[2001:db8::1]:443"


def test_scan_via_openssl_resolved_ipv4_connect_arg(monkeypatch):
    """When DNS resolves to an IPv4 address, '-connect' has no brackets."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (socket.AF_INET, ("93.184.216.34", 443)),
    )
    with patch("cert_watch.scan_conn._run_openssl", return_value=(b"", b"", 0)) as mock_run:
        _scan_via_openssl("example.com", 443, timeout=1)
    cmd = mock_run.call_args[0][0]
    connect_idx = cmd.index("-connect")
    assert cmd[connect_idx + 1] == "93.184.216.34:443"


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

    # IPv6 loopback is always blocked regardless of allow_private.
    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_hostname",
        lambda *a, **kw: [(socket.AF_INET6, ("::1", 443, 0, 0))],
    )
    with pytest.raises(OSError, match="blocked"):
        _resolve_host("loopback6.example.com", 443)


def test_resolve_host_dns_failure(monkeypatch):
    """When DNS returns no results, OSError is raised."""
    import pytest

    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_hostname",
        lambda *a, **kw: [],
    )
    with pytest.raises(OSError, match="DNS resolution failed"):
        _resolve_host("nonexistent.invalid", 443)


# ---------- resolve_and_validate_host coverage (BC-095 SSRF pre-check) ----------


def test_validate_host_no_dns_returns_none(monkeypatch):
    """Empty DNS result is a soft pass: (None, None), no pinned IP."""
    monkeypatch.setattr("cert_watch.scan_resolver.resolve_hostname", lambda *a, **kw: [])
    assert resolve_and_validate_host("nothing.invalid", 443) == (None, None)


def test_validate_host_all_unparseable_returns_none(monkeypatch):
    """When every entry is unparseable, validation soft-passes (None, None)."""
    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_hostname",
        lambda *a, **kw: [(2, ("not-an-ip", 443))],
    )
    assert resolve_and_validate_host("garbage.invalid", 443) == (None, None)


def test_resolve_host_fallback_raises_when_no_usable_ip(monkeypatch):
    """If validation soft-passes but no IP is usable, _resolve_host raises."""
    import pytest

    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_hostname",
        lambda *a, **kw: [(2, ("not-an-ip", 443))],
    )
    with pytest.raises(OSError, match="blocked addresses"):
        _resolve_host("garbage.invalid", 443)


def test_validate_host_returns_pinned_ip_for_allowed(monkeypatch):
    """First allowed public address is pinned to prevent DNS rebinding."""
    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_hostname",
        lambda *a, **kw: [(2, ("93.184.216.34", 443))],
    )
    err, pinned = resolve_and_validate_host("example.com", 443)
    assert err is None
    assert pinned == "93.184.216.34"


def test_validate_host_skips_none_and_bad_ip_then_pins(monkeypatch):
    """A None sockaddr and an unparseable IP are skipped before the good one."""
    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_hostname",
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
        "cert_watch.scan_resolver.resolve_hostname",
        lambda *a, **kw: [(2, ("10.0.0.5", 443))],
    )
    err, pinned = resolve_and_validate_host("internal.example.com", 443, allow_private=False)
    assert pinned is None
    assert "CERT_WATCH_ALLOW_PRIVATE_IPS" in err


def test_validate_host_private_outside_allowed_subnets(monkeypatch):
    """Private IP outside configured allowed subnets points at the subnet config."""
    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_hostname",
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
        "cert_watch.scan_resolver.resolve_hostname",
        lambda *a, **kw: [(2, ("127.0.0.1", 443))],
    )
    err, pinned = resolve_and_validate_host("loopback.example.com", 443, allow_private=False)
    assert pinned is None
    assert "blocked address" in err


# ---------- _probe_hsts coverage ----------


def test_probe_hsts_non_443_port():
    assert _probe_hsts("example.com", 8443) is None


def test_probe_hsts_ssl_wrap_exception_pinned_ip(monkeypatch):
    fake_sock = MagicMock()
    monkeypatch.setattr("socket.create_connection", lambda *a, **kw: fake_sock)
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda: MagicMock(wraps=lambda *a, **kw: (_ for _ in ()).throw(ssl.SSLError("ssl fail"))),
    )

    class _BadCtx:
        def wrap_socket(self, sock, **kw):
            raise ssl.SSLError("ssl fail")

    monkeypatch.setattr("ssl.create_default_context", lambda: _BadCtx())
    assert _probe_hsts("example.com", 443, pinned_ip="93.184.216.34") is None
    fake_sock.close.assert_called_once()


def test_probe_hsts_non_pinned_ip_path(monkeypatch):
    class _Conn:
        sock = None
        def request(self, *a, **kw):
            pass
        def getresponse(self):
            r = MagicMock()
            r.getheader = (
                lambda name: "max-age=31536000"
                if name == "Strict-Transport-Security"
                else None
            )
            return r
        def close(self):
            pass

    monkeypatch.setattr("http.client.HTTPSConnection", lambda *a, **kw: _Conn())
    assert _probe_hsts("example.com", 443) is True


def test_probe_hsts_generic_exception(monkeypatch):
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda: (_ for _ in ()).throw(OSError("boom")),
    )
    assert _probe_hsts("example.com", 443) is None


# ---------- _parse_allowed_subnets coverage ----------


def test_parse_allowed_subnets_invalid_entry():
    _parse_allowed_subnets.cache_clear()
    result = _parse_allowed_subnets(("192.168.0.0/16", "not-a-cidr", "10.0.0.0/8"))
    assert len(result) == 2


def test_parse_allowed_subnets_empty():
    _parse_allowed_subnets.cache_clear()
    assert _parse_allowed_subnets(()) == ()


# ---------- _resolve_with_dns coverage ----------


def test_resolve_with_dns_success(monkeypatch):
    mock_rdata_a = MagicMock()
    mock_rdata_a.address = "93.184.216.34"
    mock_rdata_aaaa = MagicMock()
    mock_rdata_aaaa.address = "2606:2800:220:1:248:1893:25c8:1946"
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = [[mock_rdata_a], [mock_rdata_aaaa]]
    monkeypatch.setattr("dns.resolver.Resolver", lambda configure=False: mock_resolver)
    results = _resolve_with_dns("example.com", 443, ("8.8.8.8",))
    assert len(results) == 2
    assert results[0][1][0] == "93.184.216.34"


def test_resolve_with_dns_exception_falls_through(monkeypatch):
    import dns.exception
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.exception.DNSException("timeout")
    monkeypatch.setattr("dns.resolver.Resolver", lambda configure=False: mock_resolver)
    assert _resolve_with_dns("example.com", 443, ("8.8.8.8",)) == []


def test_resolve_with_dns_oserror(monkeypatch):
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = OSError("network down")
    monkeypatch.setattr("dns.resolver.Resolver", lambda configure=False: mock_resolver)
    assert _resolve_with_dns("example.com", 443, ("8.8.8.8",)) == []


# ---------- resolve_hostname custom DNS path ----------


def test_resolve_hostname_custom_dns(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.scan_resolver._resolve_with_dns",
        lambda *a, **kw: [(2, ("10.0.0.1", 443))],
    )
    results = resolve_hostname("internal.corp", 443, dns_servers=("8.8.8.8",))
    assert len(results) == 1
    assert results[0][1][0] == "10.0.0.1"


def test_resolve_hostname_custom_dns_empty_falls_back(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.scan_resolver._resolve_with_dns",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    results = resolve_hostname("example.com", 443, dns_servers=("8.8.8.8",))
    assert len(results) == 1
    assert results[0][1][0] == "93.184.216.34"


# ---------- _open_tls_connection coverage ----------


def test_open_tls_connection_pinned_ip(monkeypatch, chain_triplet):
    fake_ssl_sock = _fake_ssl_socket([chain_triplet["leaf"].der])
    mock_socket = MagicMock()
    mock_socket.connect = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = fake_ssl_sock
    monkeypatch.setattr("socket.socket", lambda *a, **kw: mock_socket)
    monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
    result = _open_tls_connection("example.com", 443, 5.0, pinned_ip="93.184.216.34")
    assert result is fake_ssl_sock


def test_open_tls_connection_blocked_pinned_ip():
    import pytest
    with pytest.raises(OSError, match="blocked address"):
        _open_tls_connection(
            "example.com", 443, 5.0, pinned_ip="127.0.0.1", allow_private=False
        )


def test_open_tls_connection_resolve_path(monkeypatch, chain_triplet):
    fake_ssl_sock = _fake_ssl_socket([chain_triplet["leaf"].der])
    mock_socket = MagicMock()
    mock_socket.connect = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = fake_ssl_sock
    monkeypatch.setattr("socket.socket", lambda *a, **kw: mock_socket)
    monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    result = _open_tls_connection("example.com", 443, 5.0)
    assert result is fake_ssl_sock


def test_open_tls_connection_exception_closes_socket(monkeypatch):
    mock_socket = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.side_effect = OSError("tls fail")
    monkeypatch.setattr("socket.socket", lambda *a, **kw: mock_socket)
    monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    import pytest
    with pytest.raises(OSError, match="tls fail"):
        _open_tls_connection("example.com", 443, 5.0)
    mock_socket.close.assert_called_once()


# ---------- _get_chain_der error paths ----------


def test_get_chain_der_getter_exception(monkeypatch):
    sock = MagicMock(spec=["getpeercert", "get_unverified_chain", "close"])
    sock.getpeercert.return_value = b"\x00"
    sock.get_unverified_chain.side_effect = ssl.SSLError("chain api broke")
    result = _get_chain_der(sock)
    assert result == [b"\x00"]


def test_get_chain_der_public_bytes_attribute_error(monkeypatch):
    class _WeirdCert:
        def public_bytes(self, _enc):
            raise AttributeError("no public_bytes")
        def __bytes__(self):
            return b"\x01\x02"

    sock = MagicMock()
    sock.getpeercert.return_value = b"\x00"
    sock.get_unverified_chain.return_value = [_WeirdCert()]
    result = _get_chain_der(sock)
    assert result == [b"\x01\x02"]


# ---------- _scan_host_once error paths ----------


def test_scan_host_once_oserror_resolve(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("DNS fail")),
    )
    result = _scan_host_once("bad.invalid", 443)
    assert isinstance(result, ScanError)
    assert "DNS" in result.error_message


def test_scan_host_once_unexpected_error_propagates(monkeypatch):
    """RuntimeError (a code bug, not a TLS error) must not be swallowed."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("weird")),
    )
    with pytest.raises(RuntimeError, match="weird"):
        _scan_host_once("example.com", 443)


def test_scan_host_once_value_error_returns_scan_error(monkeypatch):
    """Non-OSError input errors from the TLS stack are still surfaced as ScanError."""
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad hostname")),
    )
    result = _scan_host_once("example.com", 443)
    assert isinstance(result, ScanError)
    assert "bad hostname" in result.error_message


def test_scan_host_once_leaf_not_certificate(monkeypatch):
    sock = MagicMock()
    sock.getpeercert.return_value = b"not-a-cert"
    sock.get_unverified_chain.return_value = []
    sock.version.return_value = "TLSv1.3"
    sock.close.return_value = None
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)
    monkeypatch.setattr("cert_watch.scan._open_tls_connection", lambda *a, **kw: sock)
    result = _scan_host_once("example.com", 443)
    assert isinstance(result, ScanError)


# ---------- _scan_host_via_openssl fallback branches ----------


def test_scan_host_via_openssl_fallback_unexpected_error_propagates(monkeypatch):
    """RuntimeError (a code bug, not a TLS error) must not be swallowed."""
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("weird")),
    )
    with pytest.raises(RuntimeError, match="weird"):
        _scan_host_via_openssl(
            "example.com", 443, timeout=5.0, allow_private=True,
            allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
        )


def test_scan_host_via_openssl_fallback_value_error_returns_scan_error(monkeypatch):
    """Non-OSError input errors in the openssl fallback path are surfaced as ScanError."""
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad hostname")),
    )
    result = _scan_host_via_openssl(
        "example.com", 443, timeout=5.0, allow_private=True,
        allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
    )
    assert isinstance(result, ScanError)
    assert "bad hostname" in result.error_message


def test_scan_host_via_openssl_fallback_no_leaf(monkeypatch):
    sock = MagicMock()
    sock.getpeercert.return_value = None
    sock.version.return_value = "TLSv1.3"
    sock.close.return_value = None
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr("cert_watch.scan._open_tls_connection", lambda *a, **kw: sock)
    result = _scan_host_via_openssl(
        "example.com", 443, timeout=5.0, allow_private=True,
        allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
    )
    assert isinstance(result, ScanError)
    assert "no certificate" in result.error_message


def test_scan_host_via_openssl_fallback_leaf_parse_fail(monkeypatch):
    sock = MagicMock()
    sock.getpeercert.return_value = b"not-a-cert"
    sock.version.return_value = "TLSv1.3"
    sock.close.return_value = None
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr("cert_watch.scan._open_tls_connection", lambda *a, **kw: sock)
    result = _scan_host_via_openssl(
        "example.com", 443, timeout=5.0, allow_private=True,
        allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
    )
    assert isinstance(result, ScanError)


# ---------- store_scanned branches ----------


def test_store_scanned_pagerduty_resolve(monkeypatch, tmp_path, self_signed_leaf):
    from cert_watch.alerts import WebhookConfig
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", "old-cert-id"),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    webhook_config = WebhookConfig(
        url="https://events.pagerduty.com/v2/enqueue",
        kind="pagerduty",
        routing_key="rk1",
    )

    mock_resolve = MagicMock(return_value=1)
    monkeypatch.setattr(
        "cert_watch.alerts.resolve_webhook_for_renewed_cert",
        mock_resolve,
    )

    leaf_id = store_scanned(entry, db, webhook_config=webhook_config)
    assert leaf_id == "leaf-id-1"
    mock_resolve.assert_called_once()


def test_store_scanned_webhook_resolve_exception(monkeypatch, tmp_path, self_signed_leaf):
    from cert_watch.alerts import WebhookConfig
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", "old-cert-id"),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    webhook_config = WebhookConfig(
        url="https://events.pagerduty.com/v2/enqueue",
        kind="pagerduty",
        routing_key="rk1",
    )
    monkeypatch.setattr(
        "cert_watch.alerts.resolve_webhook_for_renewed_cert",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("pd down")),
    )

    leaf_id = store_scanned(entry, db, webhook_config=webhook_config)
    assert leaf_id == "leaf-id-1"


def test_store_scanned_alertmanager_resolve_end_to_end(
    monkeypatch, tmp_path, self_signed_leaf,
):
    """Alertmanager resolve is called through the full scan path on renewal.

    Uses real replace_scanned so the pre-fetch-before-delete ordering is
    actually exercised (the resolve must see alerts that replace_scanned
    will delete).
    """
    import json

    from cert_watch.alerts import WebhookConfig
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema
    from cert_watch.database.cert_ops import replace_scanned

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    # First insert: use real replace_scanned to get a real cert ID
    first_leaf_id, _ = replace_scanned(
        db, hostname="x", port=443, leaf=leaf, chain=[], chain_valid=True,
    )

    # Seed a pending alert for the old cert
    alert_repo = SqliteAlertRepository(db)
    alert_repo.create(Alert(
        cert_id=first_leaf_id,
        alert_type="expiry_warning",
        status="pending",
        message="expiring",
        threshold_days=7,
        hostname="x",
        subject=leaf.subject,
    ))

    # Verify the alert exists before the second scan
    assert len(alert_repo.list_for_cert(first_leaf_id)) == 1

    # Don't mock replace_scanned — let the real code run so pre-fetch is exercised
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    webhook_config = WebhookConfig(
        url="https://am.example.com/api/v1/alerts",
        kind="alertmanager",
    )

    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        leaf_id = store_scanned(entry, db, webhook_config=webhook_config)
        # New leaf has a different ID than the first insert
        assert leaf_id != first_leaf_id

        # Exactly one resolve request was sent for the unique alert
        assert mock_urlopen.call_count == 1
        call_kwargs = mock_urlopen.call_args[1]
        payload = json.loads(call_kwargs["data"])
        assert payload["alerts"][0]["status"] == "resolved"
        assert payload["alerts"][0]["labels"]["alertname"] == "CertExpiry"
        assert payload["alerts"][0]["labels"]["host"] == "x"

        # Verify the old cert's alerts were deleted by replace_scanned
        assert len(alert_repo.list_for_cert(first_leaf_id)) == 0


def test_store_scanned_alertmanager_resolve_failure_is_fail_open(
    monkeypatch, tmp_path, self_signed_leaf,
):
    """An Alertmanager resolve failure must not block the scan pipeline."""
    from cert_watch.alerts import WebhookConfig
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema
    from cert_watch.database.cert_ops import replace_scanned

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    # First insert
    first_leaf_id, _ = replace_scanned(
        db, hostname="x", port=443, leaf=leaf, chain=[], chain_valid=True,
    )

    alert_repo = SqliteAlertRepository(db)
    alert_repo.create(Alert(
        cert_id=first_leaf_id,
        alert_type="expiry_warning",
        status="pending",
        message="expiring",
        threshold_days=7,
        hostname="x",
        subject=leaf.subject,
    ))

    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    webhook_config = WebhookConfig(
        url="https://am.example.com/api/v1/alerts",
        kind="alertmanager",
    )

    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        leaf_id = store_scanned(entry, db, webhook_config=webhook_config)
        assert leaf_id != first_leaf_id


def test_store_scanned_posture_evaluation_exception(monkeypatch, tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    # Mock store_scan_posture to raise, testing the posture stage exception path
    monkeypatch.setattr(
        "cert_watch.database.store_scan_posture",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("posture boom")),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    # Provide a posture eval so the posture stage is entered; the mock
    # on store_scan_posture will raise inside _stage_posture.
    from cert_watch.scan import _PostureEval

    leaf_id = store_scanned(entry, db, _posture_eval=_PostureEval())
    assert leaf_id == ""


def test_store_scanned_drift_alert_creation(monkeypatch, tmp_path, self_signed_leaf):
    from cert_watch.database.drift import DriftEvent
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    drift_events = [DriftEvent(field="issuer", old="OldCA", new="NewCA", severity="high")]

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift", lambda *a, **kw: drift_events
    )
    monkeypatch.setattr(
        "cert_watch.database._extract_key_algo", lambda x: "RSA"
    )
    monkeypatch.setattr(
        "cert_watch.database._extract_sig_algo", lambda x: "SHA256"
    )
    monkeypatch.setattr(
        "cert_watch.database.create_drift_alert",
        lambda *a, **kw: "alert-id",
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    leaf_id = store_scanned(entry, db)
    assert leaf_id == "leaf-id-1"


def test_store_scanned_drift_alert_creation_exception(monkeypatch, tmp_path, self_signed_leaf):
    from cert_watch.database.drift import DriftEvent
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    drift_events = [DriftEvent(field="issuer", old="OldCA", new="NewCA", severity="high")]

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr("cert_watch.database.detect_drift", lambda *a, **kw: drift_events)
    monkeypatch.setattr("cert_watch.database._extract_key_algo", lambda x: "RSA")
    monkeypatch.setattr("cert_watch.database._extract_sig_algo", lambda x: "SHA256")
    monkeypatch.setattr(
        "cert_watch.database.create_drift_alert",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("db locked")),
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    leaf_id = store_scanned(entry, db)
    assert leaf_id == ""


def test_store_scanned_drift_detection_exception(monkeypatch, tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database._extract_key_algo",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("drift import fail")),
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    leaf_id = store_scanned(entry, db)
    assert leaf_id == ""


def test_store_scanned_cert_history_exception(monkeypatch, tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("history write fail")),
    )

    leaf_id = store_scanned(entry, db)
    assert leaf_id == ""


def test_store_scanned_chain_incomplete_warning(monkeypatch, tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[], chain_incomplete=True)

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )

    leaf_id = store_scanned(entry, db)
    assert leaf_id == "leaf-id-1"


# ---------- _evaluate_and_store_posture CAA exception ----------


def test_evaluate_and_store_posture_caa_exception(monkeypatch, tmp_path, self_signed_leaf):
    from cert_watch.scan import _evaluate_and_store_posture

    db = tmp_path / "cw.sqlite3"
    from cert_watch.database.schema import init_schema
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="example.com", port=443, leaf=leaf, chain=[])

    monkeypatch.setattr(
        "cert_watch.posture.evaluate_posture",
        lambda **kw: MagicMock(grade="A", findings=[], protocol_version="TLSv1.3",
                               ocsp_stapling=False, hsts=False, must_staple=False),
    )
    monkeypatch.setattr(
        "cert_watch.database.store_scan_posture",
        MagicMock(),
    )
    monkeypatch.setattr(
        "cert_watch.caa_check.check_caa",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("dns timeout")),
    )

    grade, findings, _ = _evaluate_and_store_posture(db, "cert-id", entry)
    assert grade == "A"


def test_evaluate_and_store_posture_caa_value_error(monkeypatch, tmp_path, self_signed_leaf):
    from cert_watch.scan import _evaluate_and_store_posture

    db = tmp_path / "cw.sqlite3"
    from cert_watch.database.schema import init_schema
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="example.com", port=443, leaf=leaf, chain=[])

    monkeypatch.setattr(
        "cert_watch.posture.evaluate_posture",
        lambda **kw: MagicMock(grade="B", findings=[], protocol_version="TLSv1.2",
                               ocsp_stapling=False, hsts=False, must_staple=False),
    )
    monkeypatch.setattr(
        "cert_watch.database.store_scan_posture",
        MagicMock(),
    )
    monkeypatch.setattr(
        "cert_watch.caa_check.check_caa",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad domain")),
    )

    grade, findings, _ = _evaluate_and_store_posture(db, "cert-id", entry)
    assert grade == "B"


# ---------- async wrappers ----------


def test_scan_host_async(monkeypatch, chain_triplet):
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection", _fake_open_ok(der_chain),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)

    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(scan_host_async("example.com", 443))
    finally:
        loop.close()
    assert isinstance(result, ScannedEntry)


def test_store_scanned_async(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    from cert_watch.database.schema import init_schema
    init_schema(db)
    repo = SqliteCertificateRepository(db, source="scanned")
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(store_scanned_async(entry, repo))
    finally:
        loop.close()
    assert result


def test_store_scanned_async_acquires_write_lock(tmp_path, self_signed_leaf):
    """store_scanned_async must serialize on get_write_lock (WI-092).

    A request-handler store must not interleave with the scheduler's locked
    scan cycle. We hold the write lock from a background thread and confirm
    the async store cannot complete until the lock is released. Without the
    fix (lock inside the worker thread), the store completes immediately
    regardless of the held lock and the first assertion fails.
    """
    import threading

    from cert_watch.database.connection import get_write_lock
    from cert_watch.database.schema import init_schema

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteCertificateRepository(db, source="scanned")
    leaf = parse_certificate(self_signed_leaf.der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[])

    lock = get_write_lock()
    held = threading.Event()
    release = threading.Event()

    def _hold_lock() -> None:
        with lock:
            held.set()
            release.wait(timeout=5.0)

    holder = threading.Thread(target=_hold_lock, daemon=True)
    holder.start()
    assert held.wait(timeout=5.0), "background thread failed to acquire lock"

    async def _store() -> str:
        return await store_scanned_async(entry, repo, drift_alerts=False)

    loop = asyncio.new_event_loop()
    try:
        with pytest.raises(asyncio.TimeoutError):
            loop.run_until_complete(asyncio.wait_for(_store(), timeout=0.5))

        release.set()
        result = loop.run_until_complete(asyncio.wait_for(_store(), timeout=5.0))
    finally:
        release.set()
        loop.close()
    assert result


# ---------- additional edge-case coverage ----------


def test_open_tls_connection_verify_true(monkeypatch, chain_triplet):
    fake_ssl_sock = _fake_ssl_socket([chain_triplet["leaf"].der])
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = fake_ssl_sock
    mock_socket = MagicMock()
    mock_socket.connect = MagicMock()
    monkeypatch.setattr("socket.socket", lambda *a, **kw: mock_socket)
    monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
    _open_tls_connection("example.com", 443, 5.0, verify=True, pinned_ip="93.184.216.34")
    assert mock_ctx.check_hostname is True
    assert mock_ctx.verify_mode == ssl.CERT_REQUIRED


def test_friendly_error_oserror_timed_out_substring():
    err = _friendly_scan_error(OSError("connection timed out unexpectedly"))
    assert "timed out" in err


def test_scan_via_openssl_dash_hostname_with_valid_pinned_ip(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("should not resolve")),
    )
    chain, proto = _scan_via_openssl(
        "-malicious", 443, timeout=1, pinned_ip="93.184.216.34"
    )
    assert chain == []
    assert proto == ""


def test_scan_via_openssl_valid_pinned_ip(monkeypatch, chain_triplet):
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("should not resolve")),
    )
    combined = _pem_block(chain_triplet["leaf"].der) + _pem_block(
        chain_triplet["intermediate"].der
    )
    stdout = b"Protocol  : TLSv1.3\n" + combined
    with patch(
        "cert_watch.scan_conn._run_openssl", return_value=(stdout, b"", 0),
    ):
        chain, proto = _scan_via_openssl(
            "example.com", 443, timeout=1, pinned_ip="93.184.216.34"
        )
    assert len(chain) == 2
    assert proto == "TLSv1.3"


def test_scan_host_once_leaf_parse_error_native_path(monkeypatch):
    sock = MagicMock()
    sock.getpeercert.return_value = b"\x00\x01"
    sock.get_unverified_chain.return_value = []
    sock.version.return_value = "TLSv1.3"
    sock.close.return_value = None
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: True)
    monkeypatch.setattr("cert_watch.scan._open_tls_connection", lambda *a, **kw: sock)
    result = _scan_host_once("example.com", 443)
    assert isinstance(result, ScanError)


def test_store_scanned_with_repo_and_chain(tmp_path, self_signed_leaf, chain_triplet):
    db = tmp_path / "cw.sqlite3"
    from cert_watch.database.schema import init_schema
    init_schema(db)
    repo = SqliteCertificateRepository(db, source="scanned")
    leaf = parse_certificate(self_signed_leaf.der)
    chain_cert = parse_certificate(chain_triplet["intermediate"].der)
    entry = ScannedEntry(host="x", port=443, leaf=leaf, chain=[chain_cert])
    leaf_id = store_scanned(entry, repo)
    assert leaf_id


# ---------- verify_requested on openssl scan path ----------


def test_scan_host_via_openssl_verify_requested_true(monkeypatch, chain_triplet):
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: (der_chain, "TLSv1.3"),
    )
    monkeypatch.setattr("cert_watch.scan._probe_hsts", lambda *a, **kw: None)
    result = _scan_host_via_openssl(
        "example.com", 443, timeout=5.0, allow_private=True,
        allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
        verify=True,
    )
    assert isinstance(result, ScannedEntry)
    assert result.verify_requested is True


def test_scan_host_via_openssl_verify_requested_false(monkeypatch, chain_triplet):
    der_chain = [chain_triplet["leaf"].der, chain_triplet["intermediate"].der]
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: (der_chain, "TLSv1.3"),
    )
    monkeypatch.setattr("cert_watch.scan._probe_hsts", lambda *a, **kw: None)
    result = _scan_host_via_openssl(
        "example.com", 443, timeout=5.0, allow_private=True,
        allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
        verify=False,
    )
    assert isinstance(result, ScannedEntry)
    assert result.verify_requested is False


def test_scan_host_via_openssl_fallback_verify_requested_true(monkeypatch, chain_triplet):
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),
    )
    fake_sock = MagicMock()
    fake_sock.getpeercert.return_value = chain_triplet["leaf"].der
    fake_sock.version.return_value = "TLSv1.3"
    fake_sock.close.return_value = None
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection", lambda *a, **kw: fake_sock,
    )
    monkeypatch.setattr("cert_watch.scan._probe_hsts", lambda *a, **kw: None)
    result = _scan_host_via_openssl(
        "example.com", 443, timeout=5.0, allow_private=True,
        allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
        verify=True,
    )
    assert isinstance(result, ScannedEntry)
    assert result.verify_requested is True
    assert result.chain_incomplete is True


# ---------- HSTS probe verify parameter ----------


def test_probe_hsts_verify_true_keeps_cert_required(monkeypatch):
    captured = {}

    class _Conn:
        def request(self, *a, **kw):
            pass

        def getresponse(self):
            r = MagicMock()
            r.getheader = lambda name: None
            return r

        def close(self):
            pass

    def _capture(*a, **kw):
        captured["ctx"] = kw.get("context")
        return _Conn()

    monkeypatch.setattr("http.client.HTTPSConnection", _capture)
    _probe_hsts("example.com", 443, verify=True)
    assert captured["ctx"].check_hostname is True
    assert captured["ctx"].verify_mode == ssl.CERT_REQUIRED


def test_probe_hsts_verify_false_disables_verification(monkeypatch):
    captured = {}

    class _Conn:
        def request(self, *a, **kw):
            pass

        def getresponse(self):
            r = MagicMock()
            r.getheader = lambda name: None
            return r

        def close(self):
            pass

    def _capture(*a, **kw):
        captured["ctx"] = kw.get("context")
        return _Conn()

    monkeypatch.setattr("http.client.HTTPSConnection", _capture)
    _probe_hsts("example.com", 443, verify=False)
    assert captured["ctx"].check_hostname is False
    assert captured["ctx"].verify_mode == ssl.CERT_NONE


def test_probe_hsts_non_443_with_require_443_false(monkeypatch):
    class _Conn:
        sock = None

        def request(self, *a, **kw):
            pass

        def getresponse(self):
            r = MagicMock()
            r.getheader = (
                lambda name: "max-age=31536000"
                if name == "Strict-Transport-Security"
                else None
            )
            return r

        def close(self):
            pass

    monkeypatch.setattr("http.client.HTTPSConnection", lambda *a, **kw: _Conn())
    assert _probe_hsts("example.com", 8443, require_443=False) is True


# ---------- output cap enforcement (WI-037) ----------


def test_run_openssl_enforces_max_output_bytes():
    """When subprocess stdout exceeds the cap, ScanOutputTooLargeError is raised."""
    script = "import sys; sys.stdout.buffer.write(b'x' * 200_000)"
    with pytest.raises(ScanOutputTooLargeError):
        _run_openssl(
            [sys.executable, "-c", script],
            b"",
            max_output_bytes=10_000,
            timeout=5,
        )


def test_scan_via_openssl_propagates_output_too_large(monkeypatch):
    """_scan_via_openssl raises ScanOutputTooLargeError from the helper."""
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    with (
        patch(
            "cert_watch.scan_conn._run_openssl",
            side_effect=ScanOutputTooLargeError("output too large"),
        ),
        pytest.raises(ScanOutputTooLargeError),
    ):
        _scan_via_openssl("example.com", 443, timeout=1)


def test_scan_host_via_openssl_returns_scan_error_on_output_cap(monkeypatch, chain_triplet):
    """When the openssl output cap is exceeded the scan returns a ScanError."""
    monkeypatch.setattr("cert_watch.scan._has_native_chain_api", lambda: False)
    monkeypatch.setattr(
        "cert_watch.scan._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: (_ for _ in ()).throw(ScanOutputTooLargeError("output too large")),
    )
    result = _scan_host_via_openssl(
        "example.com", 443, timeout=5.0, allow_private=True,
        allowed_subnets=(), dns_servers=(), pinned_ip="93.184.216.34",
    )
    assert isinstance(result, ScanError)
    assert "output too large" in result.error_message


def test_run_openssl_stderr_reader_stops_at_cap():
    """_err_reader stops reading stderr once the cap is exceeded.

    It must not keep draining an arbitrarily large stderr stream just to
    discard it, which both wastes time and can mask a stdout overflow timeout
    with a plain TimeoutError.
    """
    # Write exactly the cap to stderr first, flush, then write stdout so the
    # reader can observe valid output. The final stderr byte pushes the
    # err_reader over its cap and causes it to close the pipe rather than
    # continuing to discard bytes.
    script = (
        "import sys;"
        "sys.stderr.buffer.write(b'x' * 65536);"
        "sys.stderr.buffer.flush();"
        "sys.stdout.buffer.write(b'ok');"
        "sys.stdout.buffer.flush();"
        "sys.stderr.buffer.write(b'y');"
    )
    stdout, stderr, rc = _run_openssl(
        [sys.executable, "-c", script],
        b"",
        max_output_bytes=100_000,
        timeout=5,
    )
    assert stdout == b"ok"
    assert len(stderr) == 65536
    assert stderr == b"x" * 65536
    # The child got a broken stderr pipe, so rc is unlikely to be 0; do not
    # assert a specific returncode.


# ---------- store_scanned transaction boundary (WI-084) ----------


def _scanned_entry_for(leaf: Certificate, host: str = "x", port: int = 443) -> ScannedEntry:
    return ScannedEntry(host=host, port=port, leaf=leaf, chain=[])


def test_store_scanned_rolls_back_replace_when_posture_fails(
    tmp_path, self_signed_leaf, monkeypatch,
):
    from cert_watch.database import SqliteCertificateRepository
    from cert_watch.database.schema import init_schema

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    repo = SqliteCertificateRepository(db, source="scanned")
    first_id = store_scanned(entry, db)
    assert first_id
    initial = repo.list_all()
    assert len(initial) == 1
    initial_fp = initial[0].fingerprint_sha256

    # Mock store_scan_posture to raise — this tests that the posture
    # stage failure rolls back the replace stage (cert insertion).
    monkeypatch.setattr(
        "cert_watch.database.store_scan_posture",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("posture boom")),
    )

    from cert_watch.scan import _PostureEval

    result = store_scanned(entry, db, _posture_eval=_PostureEval())
    assert result == ""
    certs = repo.list_all()
    assert len(certs) == 1
    assert certs[0].fingerprint_sha256 == initial_fp


def test_store_scanned_rolls_back_replace_and_posture_when_drift_fails(
    tmp_path, self_signed_leaf, monkeypatch,
):
    from cert_watch.database import SqliteCertificateRepository
    from cert_watch.database.schema import init_schema

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    repo = SqliteCertificateRepository(db, source="scanned")
    store_scanned(entry, db)
    initial_fp = repo.list_all()[0].fingerprint_sha256

    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("drift boom")),
    )

    result = store_scanned(entry, db)
    assert result == ""
    certs = repo.list_all()
    assert len(certs) == 1
    assert certs[0].fingerprint_sha256 == initial_fp


def test_store_scanned_rolls_back_prior_writes_when_history_fails(
    tmp_path, self_signed_leaf, monkeypatch,
):
    from cert_watch.database import SqliteCertificateRepository
    from cert_watch.database.schema import init_schema

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    repo = SqliteCertificateRepository(db, source="scanned")
    store_scanned(entry, db)
    initial_fp = repo.list_all()[0].fingerprint_sha256

    def failing_record(*args, conn=None, **kwargs):
        raise Exception("history boom")

    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        failing_record,
    )

    result = store_scanned(entry, db)
    assert result == ""
    certs = repo.list_all()
    assert len(certs) == 1
    assert certs[0].fingerprint_sha256 == initial_fp


def test_store_scanned_webhook_resolve_failure_does_not_roll_back(
    tmp_path, self_signed_leaf, monkeypatch,
):
    from cert_watch.alerts import Alert, WebhookConfig
    from cert_watch.database import SqliteAlertRepository
    from cert_watch.database.schema import init_schema

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    repo = SqliteCertificateRepository(db, source="scanned")
    first_id = store_scanned(entry, db)
    alert_repo = SqliteAlertRepository(db)
    alert_repo.create(Alert(
        cert_id=first_id,
        alert_type="expiry_warning",
        status="pending",
        message="expiring soon",
        threshold_days=7,
        hostname="x",
        subject=leaf.subject,
    ))

    monkeypatch.setattr(
        "cert_watch.alerts.resolve_webhook_for_renewed_cert",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("pagerduty down")),
    )

    webhook_config = WebhookConfig(
        url="https://events.pagerduty.com/v2/enqueue",
        kind="pagerduty",
        routing_key="rk",
    )

    second_id = store_scanned(entry, db, webhook_config=webhook_config)
    assert second_id
    assert second_id != first_id
    certs = repo.list_all()
    assert len(certs) == 1
    assert certs[0].fingerprint_sha256 == leaf.fingerprint_sha256


def test_store_scanned_returns_empty_string_on_transaction_failure(
    tmp_path, self_signed_leaf, monkeypatch,
):
    from cert_watch.database.schema import init_schema

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    first_id = store_scanned(entry, db)
    assert first_id

    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("history boom")),
    )

    result = store_scanned(entry, db)
    assert result == ""


def test_store_scanned_event_webhooks_deferred_until_commit(
    tmp_path, self_signed_leaf, monkeypatch,
):
    from unittest.mock import MagicMock

    from cert_watch.database.schema import init_schema
    from cert_watch.events import EventStreamConfig

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: "hist-id",
    )
    monkeypatch.setattr(
        "cert_watch.events.load_event_config",
        lambda *a, **kw: EventStreamConfig(webhook_url="https://example.com/hook"),
    )

    mock_pool = MagicMock()
    monkeypatch.setattr("cert_watch.events._get_pool", lambda: mock_pool)

    leaf_id = store_scanned(entry, db)
    assert leaf_id == "leaf-id-1"
    mock_pool.submit.assert_called()


def test_store_scanned_event_webhooks_not_fired_on_rollback(
    tmp_path, self_signed_leaf, monkeypatch,
):
    from unittest.mock import MagicMock

    from cert_watch.database.schema import init_schema
    from cert_watch.events import EventStreamConfig

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    monkeypatch.setattr(
        "cert_watch.scan.replace_scanned",
        lambda *a, **kw: ("leaf-id-1", None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._evaluate_posture",
        lambda *a, **kw: _PostureEval("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.scan._stage_posture",
        lambda *a, **kw: ("A", [], None),
    )
    monkeypatch.setattr(
        "cert_watch.database.detect_drift",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "cert_watch.database.record_cert_history",
        lambda *a, **kw: (_ for _ in ()).throw(Exception("history boom")),
    )
    monkeypatch.setattr(
        "cert_watch.events.load_event_config",
        lambda *a, **kw: EventStreamConfig(webhook_url="https://example.com/hook"),
    )

    mock_pool = MagicMock()
    monkeypatch.setattr("cert_watch.events._get_pool", lambda: mock_pool)

    result = store_scanned(entry, db)
    assert result == ""
    mock_pool.submit.assert_not_called()


# ---------- _stage_policy / _stage_events branch coverage ----------


def test_stage_policy_grade_changed(tmp_path, self_signed_leaf):
    from unittest.mock import patch

    from cert_watch.database.connection import _connect
    from cert_watch.database.schema import init_schema
    from cert_watch.policy import PolicySet, PolicyViolation
    from cert_watch.scan import _stage_policy

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)
    leaf_id = store_scanned(entry, db)
    assert leaf_id

    conn = _connect(db)
    ruleset = PolicySet()
    violations = [PolicyViolation(
        rule_id="test_critical", severity="critical",
        message="critical test violation", remediation="fix it",
    )]
    with patch("cert_watch.policy.evaluate_policy", return_value=violations):
        result = _stage_policy(
            db, leaf_id, entry, "A", [], None,
            conn=conn, ruleset=ruleset,
        )
    conn.commit()

    assert result == "F"
    row = conn.execute(
        "SELECT grade FROM scan_posture WHERE cert_id = ? AND grade = 'F'",
        (leaf_id,),
    ).fetchone()
    assert row is not None


def test_stage_policy_grade_unchanged_alerts_still_created(tmp_path, self_signed_leaf):
    from unittest.mock import patch

    from cert_watch.database.connection import _connect
    from cert_watch.database.schema import init_schema
    from cert_watch.policy import PolicySet, PolicyViolation
    from cert_watch.scan import _stage_policy

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)
    leaf_id = store_scanned(entry, db)
    assert leaf_id

    conn = _connect(db)
    ruleset = PolicySet()
    violations = [PolicyViolation(
        rule_id="test_warning", severity="warning",
        message="warning test violation", remediation="fix it",
        grade_affecting=False,
    )]
    with patch("cert_watch.policy.evaluate_policy", return_value=violations):
        result = _stage_policy(
            db, leaf_id, entry, "A", [], None,
            conn=conn, ruleset=ruleset,
        )
    conn.commit()

    assert result == "A"
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE cert_id = ? AND alert_type = 'policy_violation'",
        (leaf_id,),
    ).fetchone()
    assert row["n"] >= 1


def test_stage_events_posture_changed(tmp_path, self_signed_leaf):
    from cert_watch.database.connection import _connect
    from cert_watch.database.schema import init_schema
    from cert_watch.events import EventStreamConfig
    from cert_watch.scan import _stage_events

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    conn = _connect(db)
    config = EventStreamConfig(webhook_url="https://example.com/hook")
    pending = _stage_events(
        db, "test-cert-id", entry, None, "B", "A",
        conn=conn, event_config=config,
    )
    conn.commit()

    assert len(pending) == 2
    event_types = [evt.event_type for evt, _, _ in pending]
    assert "cert_added" in event_types
    assert "posture_changed" in event_types

    rows = conn.execute(
        "SELECT event_type FROM event_log WHERE event_type = 'posture_changed'"
    ).fetchall()
    assert len(rows) == 1


def test_stage_events_posture_unchanged(tmp_path, self_signed_leaf):
    from cert_watch.database.connection import _connect
    from cert_watch.database.schema import init_schema
    from cert_watch.events import EventStreamConfig
    from cert_watch.scan import _stage_events

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)

    conn = _connect(db)
    config = EventStreamConfig(webhook_url="https://example.com/hook")
    pending = _stage_events(
        db, "test-cert-id", entry, None, "A", "A",
        conn=conn, event_config=config,
    )
    conn.commit()

    assert len(pending) == 1
    assert pending[0][0].event_type == "cert_added"

    rows = conn.execute(
        "SELECT event_type FROM event_log WHERE event_type = 'posture_changed'"
    ).fetchall()
    assert len(rows) == 0


def test_stage_policy_posture_findings_suppress_policy(tmp_path, self_signed_leaf):
    """Regression (WI-014): Finding objects from posture must reach evaluate_policy.

    Before the fix, _stage_policy used typing.cast() that pretended Finding
    objects were dicts, then the list comprehension filtered with
    isinstance(f, dict) — silently dropping all Finding objects.  This meant
    posture_findings was always None and WI-014 suppression was dead.
    """
    from cert_watch.database.connection import _connect
    from cert_watch.database.schema import init_schema
    from cert_watch.policy import default_policy_set
    from cert_watch.posture import Finding
    from cert_watch.scan import _stage_policy

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)
    leaf_id = store_scanned(entry, db)
    assert leaf_id

    ruleset = default_policy_set()
    for r in ruleset.rules:
        if r.rule_id == "self_signed":
            r.enabled = True

    posture_findings = [
        Finding(check="self_signed", status="fail", message="Certificate is self-signed"),
    ]

    conn = _connect(db)
    result = _stage_policy(
        db, leaf_id, entry, "A", posture_findings, None,
        conn=conn, ruleset=ruleset,
    )
    conn.commit()

    assert result == "A"
    rows = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE cert_id = ? AND alert_type = 'policy_violation'",
        (leaf_id,),
    ).fetchone()
    assert rows["n"] == 0


def test_stage_policy_no_posture_findings_policy_fires(tmp_path, self_signed_leaf):
    """Control for WI-014: without posture findings, the policy violation fires."""
    from cert_watch.database.connection import _connect
    from cert_watch.database.schema import init_schema
    from cert_watch.policy import default_policy_set
    from cert_watch.scan import _stage_policy

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)
    leaf_id = store_scanned(entry, db)
    assert leaf_id

    ruleset = default_policy_set()
    for r in ruleset.rules:
        if r.rule_id == "self_signed":
            r.enabled = True

    conn = _connect(db)
    _stage_policy(
        db, leaf_id, entry, "A", [], None,
        conn=conn, ruleset=ruleset,
    )
    conn.commit()

    rows = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE cert_id = ? AND alert_type = 'policy_violation'",
        (leaf_id,),
    ).fetchone()
    assert rows["n"] >= 1


def test_stage_policy_dict_findings_also_suppress(tmp_path, self_signed_leaf):
    """Regression (WI-014): dict-style findings still work (backward compat)."""
    from cert_watch.database.connection import _connect
    from cert_watch.database.schema import init_schema
    from cert_watch.policy import default_policy_set
    from cert_watch.scan import _stage_policy

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = parse_certificate(self_signed_leaf.der)
    entry = _scanned_entry_for(leaf)
    leaf_id = store_scanned(entry, db)
    assert leaf_id

    ruleset = default_policy_set()
    for r in ruleset.rules:
        if r.rule_id == "self_signed":
            r.enabled = True

    dict_findings = [
        {"check": "self_signed", "status": "fail", "message": "self-signed"},
    ]

    conn = _connect(db)
    result = _stage_policy(
        db, leaf_id, entry, "A", dict_findings, None,
        conn=conn, ruleset=ruleset,
    )
    conn.commit()

    assert result == "A"
    rows = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE cert_id = ? AND alert_type = 'policy_violation'",
        (leaf_id,),
    ).fetchone()
    assert rows["n"] == 0
