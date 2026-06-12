"""Integration tests for the scan hostname resolver.

These tests exercise ``cert_watch.scan_resolver`` using real hostname resolution
where possible. The security model blocks 127.0.0.0/8 unconditionally
(``_ALWAYS_BLOCKED_NETWORKS``), so ``localhost`` (which resolves to 127.0.0.1)
is always rejected. Private-IP tests use a fake hostname that resolves to a
non-loopback private address (e.g. 10.0.0.5).
"""

from __future__ import annotations

import socket

import pytest

from cert_watch.scan_resolver import _resolve_host, resolve_and_validate_host

LOCALHOST_PORT = 443


# ---------------------------------------------------------------------------
# localhost → 127.0.0.1 is ALWAYS blocked
# ---------------------------------------------------------------------------


def test_resolve_host_localhost_always_blocked():
    """127.0.0.0/8 is in _ALWAYS_BLOCKED_NETWORKS; localhost is always refused."""
    with pytest.raises(OSError, match="blocked"):
        _resolve_host("localhost", LOCALHOST_PORT, allow_private=True)


def test_resolve_and_validate_localhost_always_blocked():
    """resolve_and_validate_host also refuses localhost regardless of flags."""
    err, pinned = resolve_and_validate_host("localhost", LOCALHOST_PORT, allow_private=True)
    assert pinned is None
    assert err is not None
    assert "blocked" in err


# ---------------------------------------------------------------------------
# Private-IP tests using a fake hostname (non-loopback)
# ---------------------------------------------------------------------------


def test_resolve_host_private_allowed_with_allow_private(monkeypatch):
    """A non-loopback private IP is allowed when allow_private=True."""
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "private.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    family, sockaddr = _resolve_host("private.example", LOCALHOST_PORT, allow_private=True)
    assert sockaddr[0] == "10.0.0.5"


def test_resolve_and_validate_private_allowed_with_allow_private(monkeypatch):
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "private.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    err, pinned = resolve_and_validate_host("private.example", LOCALHOST_PORT, allow_private=True)
    assert err is None
    assert pinned == "10.0.0.5"


def test_resolve_host_private_blocked_without_allow_private(monkeypatch):
    """A non-loopback private IP is blocked when allow_private=False."""
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "private.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(OSError, match="blocked"):
        _resolve_host("private.example", LOCALHOST_PORT, allow_private=False)


def test_resolve_and_validate_private_blocked_without_allow_private(monkeypatch):
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "private.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    err, pinned = resolve_and_validate_host("private.example", LOCALHOST_PORT, allow_private=False)
    assert pinned is None
    assert err is not None
    assert "blocked" in err


def test_resolve_private_allowed_by_subnet_override(monkeypatch):
    """An explicit allowlist can permit non-loopback private IPs."""
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "private.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    family, sockaddr = _resolve_host(
        "private.example",
        LOCALHOST_PORT,
        allow_private=False,
        allowed_subnets=("10.0.0.0/8",),
    )
    assert sockaddr[0] == "10.0.0.5"

    err, pinned = resolve_and_validate_host(
        "private.example",
        LOCALHOST_PORT,
        allow_private=False,
        allowed_subnets=("10.0.0.0/8",),
    )
    assert err is None
    assert pinned == "10.0.0.5"


def test_resolve_private_blocked_by_wrong_subnet(monkeypatch):
    """A private IP outside the configured allowed_subnets is still blocked."""
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "private.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(OSError, match="CERT_WATCH_ALLOWED_SUBNETS"):
        _resolve_host(
            "private.example",
            LOCALHOST_PORT,
            allow_private=False,
            allowed_subnets=("192.168.0.0/16",),
        )


# ---------------------------------------------------------------------------
# Unresolvable hostnames
# ---------------------------------------------------------------------------


def test_resolve_host_unresolvable():
    with pytest.raises(OSError, match="DNS resolution failed"):
        _resolve_host("this-host-should-not-resolve.invalid", LOCALHOST_PORT)


def test_resolve_and_validate_unresolvable():
    err, pinned = resolve_and_validate_host(
        "this-host-should-not-resolve.invalid", LOCALHOST_PORT
    )
    assert err is None
    assert pinned is None
