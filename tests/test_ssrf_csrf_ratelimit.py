"""Tests for SSRF mitigation, CSRF token validation, and per-IP rate limiting."""

from __future__ import annotations

import importlib
import ipaddress
import json
import socket
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# ── SSRF: scan._is_blocked_ip ──────────────────────────────────────────────

def test_is_blocked_ip_loopback():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("127.0.0.1"))


def test_is_blocked_ip_private_10():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("10.0.0.1"), allow_private=False)


def test_is_blocked_ip_private_172():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("172.16.0.1"), allow_private=False)


def test_is_blocked_ip_private_192():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("192.168.1.1"), allow_private=False)


def test_is_blocked_ip_link_local():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("169.254.1.1"))


def test_is_blocked_ip_this_host():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("0.0.0.0"))


def test_is_blocked_ip_ipv6_loopback():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("::1"))


def test_is_blocked_ip_ipv6_mapped_loopback():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("::ffff:127.0.0.1"))


def test_is_blocked_ip_ipv6_mapped_private():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("::ffff:10.0.0.1"), allow_private=False)


def test_is_blocked_ip_ipv6_unspecified():
    from cert_watch.scan import _is_blocked_ip
    assert _is_blocked_ip(ipaddress.ip_address("::"))


def test_is_not_blocked_public():
    from cert_watch.scan import _is_blocked_ip
    assert not _is_blocked_ip(ipaddress.ip_address("93.184.216.34"))


def test_is_not_blocked_ipv6_public():
    from cert_watch.scan import _is_blocked_ip
    assert not _is_blocked_ip(ipaddress.ip_address("2606:4700::1"))


# ── SSRF: scan._resolve_host rejects blocked hosts ─────────────────────────

def test_resolve_host_blocks_loopback(monkeypatch):
    from cert_watch.scan import _resolve_host
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, 1, 0, "", ("127.0.0.1", 443)),
    ])
    with pytest.raises(OSError, match="blocked"):
        _resolve_host("evil.local", 443)


def test_resolve_host_blocks_ipv6_mapped_loopback(monkeypatch):
    from cert_watch.scan import _resolve_host
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET6, 1, 0, "", ("::ffff:127.0.0.1", 443, 0, 0)),
    ])
    with pytest.raises(OSError, match="blocked"):
        _resolve_host("evil6.local", 443)


def test_resolve_host_allows_public(monkeypatch):
    from cert_watch.scan import _resolve_host
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, 1, 0, "", ("93.184.216.34", 443)),
    ])
    family, sockaddr = _resolve_host("example.com", 443)
    assert sockaddr[0] == "93.184.216.34"


def test_resolve_host_skips_blocked_uses_next(monkeypatch):
    from cert_watch.scan import _resolve_host
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, 1, 0, "", ("127.0.0.1", 443)),
        (socket.AF_INET, 1, 0, "", ("93.184.216.34", 443)),
    ])
    family, sockaddr = _resolve_host("mixed.example.com", 443)
    assert sockaddr[0] == "93.184.216.34"


def test_resolve_host_dns_failure(monkeypatch):
    from cert_watch.scan import _resolve_host

    def _raise(*a, **kw):
        raise socket.gaierror("fail")

    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    with pytest.raises(OSError, match="DNS resolution failed"):
        _resolve_host("nonexistent.invalid", 443)


# ── SSRF: app._is_blocked_host (UX pre-check) ──────────────────────────────

def test_app_is_blocked_host_private(monkeypatch):
    from cert_watch.routes.hosts import _is_blocked_host_check as _is_blocked_host
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, 1, 0, "", ("10.0.0.1", None)),
    ])
    assert _is_blocked_host("internal.corp", allow_private=False)[0] is not None


def test_app_is_blocked_host_public(monkeypatch):
    from cert_watch.routes.hosts import _is_blocked_host_check as _is_blocked_host
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, 1, 0, "", ("93.184.216.34", None)),
    ])
    assert _is_blocked_host("example.com")[0] is None


def test_app_is_blocked_host_unresolvable(monkeypatch):
    from cert_watch.routes.hosts import _is_blocked_host_check as _is_blocked_host

    def _raise(*a, **kw):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    assert _is_blocked_host("nonexistent.invalid")[0] is None


# ── CSRF: token validation ─────────────────────────────────────────────────

def test_csrf_make_validate_roundtrip():
    from cert_watch.middleware import make_csrf_token, validate_csrf_token
    sid = "test-session-123"
    token = make_csrf_token(sid)
    assert validate_csrf_token(token, sid)


def test_csrf_rejects_wrong_session():
    from cert_watch.middleware import make_csrf_token, validate_csrf_token
    token = make_csrf_token("session-a")
    assert not validate_csrf_token(token, "session-b")


def test_csrf_rejects_tampered_token():
    from cert_watch.middleware import make_csrf_token, validate_csrf_token
    token = make_csrf_token("s1")
    parts = token.split(":")
    # Tamper with the signature
    parts[-1] = "tampered"
    assert not validate_csrf_token(":".join(parts), "s1")


def test_csrf_rejects_malformed_token():
    from cert_watch.middleware import validate_csrf_token
    assert not validate_csrf_token("bad-token", "s1")
    assert not validate_csrf_token("", "s1")


# ── CSRF: hidden field accepted in POST ────────────────────────────────────

def test_csrf_hidden_field_accepted(tmp_path, monkeypatch):
    """POST with _csrf_token in form body should pass CSRF check."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_CSRF_DISABLED", raising=False)
    from cert_watch import config as _config
    importlib.reload(_config)
    from cert_watch import app as app_mod
    importlib.reload(app_mod)

    with TestClient(app_mod.app) as client:
        r = client.get("/")
        assert r.status_code == 200
        sid_cookie = r.cookies.get("cw_sid")
        assert sid_cookie

    from cert_watch.middleware import make_csrf_token
    token = make_csrf_token(sid_cookie)

    from cert_watch.scan import ScanError
    async def fake_scan_error(*a, **kw):
        return ScanError(hostname="x", port=443, error_message="test")
    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_error)

    with TestClient(app_mod.app, cookies={"cw_sid": sid_cookie}) as client:
        r = client.post("/hosts", data={
            "hostname": "test.example.com",
            "_csrf_token": token,
        }, follow_redirects=False)
    assert r.status_code == 303
    assert "csrf" not in (r.headers.get("location", "").lower())


def test_csrf_missing_token_rejected(tmp_path, monkeypatch):
    """POST without CSRF token should be rejected when CSRF is enabled."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_CSRF_DISABLED", raising=False)
    from cert_watch import config as _config
    importlib.reload(_config)
    from cert_watch import app as app_mod
    importlib.reload(app_mod)

    with TestClient(app_mod.app, cookies={"cw_sid": "fake-session"}) as client:
        r = client.post("/hosts", data={
            "hostname": "test.example.com",
        }, follow_redirects=False)
    assert r.status_code == 303
    assert "csrf" in r.headers.get("location", "").lower()


# ── Rate limiting: per-IP keys ─────────────────────────────────────────────

def test_rate_limit_allows_first_request():
    from cert_watch.middleware import check_rate_limit
    key = f"test_rl:{time.time()}"
    assert check_rate_limit(key, 2, 60)
    assert check_rate_limit(key, 2, 60)
    assert not check_rate_limit(key, 2, 60)


def test_rate_limit_per_ip_isolation():
    from cert_watch.middleware import check_rate_limit
    key_a = f"test_rl_ip_a:{time.time()}"
    key_b = f"test_rl_ip_b:{time.time()}"
    check_rate_limit(key_a, 1, 60)
    assert not check_rate_limit(key_a, 1, 60)
    assert check_rate_limit(key_b, 1, 60)


# ── Cross-worker SQLite-backed rate limiting (BC-049) ────────────────────

def test_cross_worker_rate_limit_shared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two workers sharing the same SQLite DB enforce a shared limit."""
    from cert_watch.database.schema import init_schema
    from cert_watch.middleware import _init_rate_db, check_rate_limit

    db = tmp_path / "rate_limits.sqlite3"
    init_schema(db)
    _init_rate_db(db)

    # Monkeypatch away the in-memory fallback cache so we always hit SQLite
    monkeypatch.setattr("cert_watch.middleware._rate_cache", {})

    key = f"cross_worker:{time.time()}"

    # Worker A consumes both allowed requests
    assert check_rate_limit(key, 2, 60)
    assert check_rate_limit(key, 2, 60)

    # Worker B (same DB) should be blocked
    assert not check_rate_limit(key, 2, 60)

    # Verify the DB row exists with two timestamps
    with sqlite3.connect(str(db)) as conn:
        row = conn.execute(
            "SELECT timestamps FROM rate_limits WHERE key = ?", (key,)
        ).fetchone()
    assert row is not None
    assert len(json.loads(row[0])) == 2


def test_rate_limit_init_schema_called_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """init_schema is only invoked once across multiple check_rate_limit calls."""
    from cert_watch.database.schema import init_schema
    from cert_watch.middleware import _init_rate_db, check_rate_limit

    call_count = 0
    original_init = init_schema

    def counting_init(db_path: Path | str) -> None:
        nonlocal call_count
        call_count += 1
        original_init(db_path)

    monkeypatch.setattr("cert_watch.database.schema.init_schema", counting_init)

    db = tmp_path / "rate_limits.sqlite3"
    _init_rate_db(db)
    monkeypatch.setattr("cert_watch.middleware._rate_db_initialized", False)

    key = f"init_once:{time.time()}"
    assert check_rate_limit(key, 2, 60)
    assert check_rate_limit(key, 2, 60)
    assert call_count == 1
