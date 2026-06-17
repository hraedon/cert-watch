"""Unit tests for the SSRF-safe HTTP/SMTP client helpers.

These cover ``cert_watch.http_client.validate_smtp_host`` (BC-116 SMTP
parity) without any network access — literal-IP cases need no resolution,
and hostname cases monkeypatch ``socket.getaddrinfo``.
"""

from __future__ import annotations

import socket

from cert_watch.http_client import validate_smtp_host

# ---------------------------------------------------------------------------
# Literal IPs (no DNS resolution needed)
# ---------------------------------------------------------------------------


def test_validate_smtp_host_loopback_blocked():
    """Loopback literal is always blocked, even with allow_private=True."""
    err = validate_smtp_host("127.0.0.1", allow_private=True)
    assert err is not None
    assert "127.0.0.1" in err


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
