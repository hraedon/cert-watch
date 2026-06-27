"""Unit tests for the SSRF-safe HTTP/SMTP client helpers.

These cover ``cert_watch.http_client.validate_smtp_host`` (BC-116 SMTP
parity) without any network access — literal-IP cases need no resolution,
and hostname cases monkeypatch ``socket.getaddrinfo``.
"""

from __future__ import annotations

import socket
import urllib.error

import pytest

from cert_watch.http_client import ssrf_safe_urlopen, validate_smtp_host

# ---------------------------------------------------------------------------
# Literal IPs (no DNS resolution needed)
# ---------------------------------------------------------------------------


def test_validate_smtp_host_loopback_blocked():
    """Loopback literal is always blocked, even with allow_private=True."""
    err = validate_smtp_host("127.0.0.1", allow_private=True)
    assert err is not None
    assert "127.0.0.1" in err


def test_https_pinned_connect_uses_2tuple_for_ipv6(monkeypatch):
    """Regression: SSRF-safe HTTPS delivery to an IPv6 host must pass a 2-tuple
    to socket.create_connection.

    The pinned-HTTPS connect() previously built a 4-tuple sockaddr for IPv6
    targets, which create_connection() rejects with "too many values to unpack",
    breaking ALL HTTPS webhook/HEC/scan delivery to IPv6 hosts. IPv4-only unit
    tests missed it; a live IPv6 lab delivery surfaced it.
    """
    ula = "fd21:1:2:3::5"  # ULA → private, allowed with allow_private=True
    real_gai = socket.getaddrinfo

    def fake_gai(host, *a, **k):
        if host == "hook.internal":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", (ula, 0, 0, 0))]
        return real_gai(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)

    captured: dict[str, object] = {}

    # OSError so urllib's do_open wraps it into URLError (deterministic to assert).
    class _Stop(OSError):
        pass

    def fake_create_connection(address, *a, **k):
        captured["address"] = address
        raise _Stop()  # stop before real network I/O

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    # The guard must ALLOW the private IPv6 host and reach the connect path.
    with pytest.raises(urllib.error.URLError):
        ssrf_safe_urlopen(
            "https://hook.internal/hook", data=b"{}", timeout=5, allow_private=True
        )

    assert "address" in captured, "create_connection never reached (guard blocked the host?)"
    addr = captured["address"]
    assert isinstance(addr, tuple) and len(addr) == 2, f"expected 2-tuple, got {addr!r}"
    assert addr[0] == ula


def test_validate_smtp_host_ipv6_loopback_blocked():
    """IPv6 loopback literal is always blocked."""
    err = validate_smtp_host("::1", allow_private=True)
    assert err is not None


def test_validate_smtp_host_metadata_blocked():
    """Cloud metadata endpoint (169.254.169.254) is always blocked."""
    err = validate_smtp_host("169.254.169.254", allow_private=True)
    assert err is not None


def test_validate_smtp_host_private_allowed_by_default():
    """Private IP allowed when allow_private=True (the SMTP default)."""
    err = validate_smtp_host("10.0.0.5", allow_private=True)
    assert err is None


def test_validate_smtp_host_private_blocked_when_disallowed():
    """Private IP blocked when allow_private=False."""
    err = validate_smtp_host("192.168.1.1", allow_private=False)
    assert err is not None


def test_validate_smtp_host_public_allowed():
    """Public IP allowed regardless of allow_private."""
    assert validate_smtp_host("8.8.8.8", allow_private=False) is None
    assert validate_smtp_host("8.8.8.8", allow_private=True) is None


# ---------------------------------------------------------------------------
# Hostname resolution (monkeypatched getaddrinfo)
# ---------------------------------------------------------------------------


def _patch_resolve(monkeypatch, mapping: dict[str, str]):
    """Redirect socket.getaddrinfo so *mapping* hostnames resolve to IPs."""
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host in mapping:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (mapping[host], 0))
            ]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_validate_smtp_host_resolves_private_allowed(monkeypatch):
    """Private hostname allowed when allow_private=True."""
    _patch_resolve(monkeypatch, {"relay.internal": "10.0.0.5"})
    assert validate_smtp_host("relay.internal", allow_private=True) is None


def test_validate_smtp_host_resolves_private_blocked_when_disallowed(monkeypatch):
    """Private hostname blocked when allow_private=False."""
    _patch_resolve(monkeypatch, {"relay.internal": "10.0.0.5"})
    err = validate_smtp_host("relay.internal", allow_private=False)
    assert err is not None
    assert "10.0.0.5" in err


def test_validate_smtp_host_resolves_loopback_blocked(monkeypatch):
    """Hostname resolving to loopback is always blocked."""
    _patch_resolve(monkeypatch, {"bad.example": "127.0.0.1"})
    err = validate_smtp_host("bad.example", allow_private=True)
    assert err is not None
    assert "127.0.0.1" in err


def test_validate_smtp_host_resolution_failure_is_not_a_block():
    """A hostname that cannot resolve is NOT blocked — smtplib fails naturally.

    This preserves the common test pattern of mocking smtplib against fake
    hostnames, and matches the threat model (no blocked IP is reachable when
    resolution fails).
    """
    err = validate_smtp_host("nonexistent.invalid.example", allow_private=True)
    assert err is None


def test_validate_smtp_host_allowed_subnets_permits_private(monkeypatch):
    """A private IP inside allowed_subnets is permitted even when allow_private=False."""
    _patch_resolve(monkeypatch, {"relay.internal": "10.0.0.5"})
    err = validate_smtp_host(
        "relay.internal",
        allow_private=False,
        allowed_subnets=("10.0.0.0/8",),
    )
    assert err is None


def test_validate_smtp_host_allowed_subnets_blocks_outside(monkeypatch):
    """A private IP outside allowed_subnets is blocked when allow_private=False."""
    _patch_resolve(monkeypatch, {"relay.internal": "172.16.0.5"})
    err = validate_smtp_host(
        "relay.internal",
        allow_private=False,
        allowed_subnets=("10.0.0.0/8",),
    )
    assert err is not None
