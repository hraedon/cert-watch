"""Coverage tests for middleware.py branches.

Plan 024 Slice 3 — rate-limit, CSRF, CSP nonce, trusted-proxy, metrics gate.
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime

from fastapi.testclient import TestClient

# ---------- CSP nonce ----------


def test_csp_nonce_in_response(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("content-security-policy", "")
    assert "nonce-" in csp
    assert "script-src" in csp


# ---------- Security headers ----------


def test_security_headers(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


# ---------- Rate limiting ----------


def test_rate_limit_in_memory_fallback(monkeypatch, tmp_path):
    """Test in-memory rate limit fallback when no DB is configured."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    import cert_watch.middleware as mw

    importlib.reload(mw)
    mw._rate_db_path = None
    mw._rate_cache.clear()
    assert mw.check_rate_limit("test:key", 2, 60) is True
    assert mw.check_rate_limit("test:key", 2, 60) is True
    assert mw.check_rate_limit("test:key", 2, 60) is False
    mw._rate_cache.clear()


def test_rate_limit_db_path(monkeypatch, tmp_path):
    """Test SQLite-backed rate limiting."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    import cert_watch.middleware as mw

    importlib.reload(mw)
    db_path = tmp_path / "rate.sqlite3"
    mw._init_rate_db(db_path)
    mw._rate_db_initialized = False
    mw._rate_cache.clear()
    assert mw.check_rate_limit("test:db", 2, 60) is True
    assert mw.check_rate_limit("test:db", 2, 60) is True
    assert mw.check_rate_limit("test:db", 2, 60) is False
    mw._rate_cache.clear()
    mw._rate_db_path = None
    mw._rate_db_initialized = False


def test_rate_limit_db_error_fallback(monkeypatch, tmp_path):
    """Test fallback to in-memory when DB errors."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    import cert_watch.middleware as mw

    importlib.reload(mw)
    mw._rate_db_path = tmp_path / "nonexistent" / "dir" / "rate.sqlite3"
    mw._rate_db_initialized = False
    mw._rate_cache.clear()
    assert mw.check_rate_limit("test:fallback", 2, 60) is True
    mw._rate_cache.clear()
    mw._rate_db_path = None
    mw._rate_db_initialized = False


def test_rate_limit_cache_hit(monkeypatch, tmp_path):
    """Test that cache is used within TTL."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    import cert_watch.middleware as mw

    importlib.reload(mw)
    db_path = tmp_path / "rate.sqlite3"
    mw._init_rate_db(db_path)
    mw._rate_db_initialized = False
    mw._rate_cache.clear()
    # First request populates cache
    assert mw.check_rate_limit("test:cache", 5, 60) is True
    # Second request should use cache
    assert mw.check_rate_limit("test:cache", 5, 60) is True
    mw._rate_cache.clear()
    mw._rate_db_path = None
    mw._rate_db_initialized = False


def test_get_rate_remaining(monkeypatch, tmp_path):
    """Test get_rate_remaining returns correct values."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    import cert_watch.middleware as mw

    importlib.reload(mw)
    mw._rate_db_path = None
    mw._rate_cache.clear()
    remaining, retry_after = mw.get_rate_remaining("test:remaining", 5, 60)
    assert remaining == 5
    assert retry_after >= 0  # 60 when empty (default=now gives full window)
    mw._rate_cache.clear()


# ---------- CSRF ----------


def test_csrf_token_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    import cert_watch.middleware as mw

    importlib.reload(mw)
    mw.set_csrf_secret("test-secret")
    token = mw.make_csrf_token("session123")
    assert mw.validate_csrf_token(token, "session123") is True
    assert mw.validate_csrf_token(token, "wrong_session") is False
    assert mw.validate_csrf_token("invalid", "session123") is False
    assert mw.validate_csrf_token("a:b", "session123") is False


def test_csrf_token_expired(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    import cert_watch.middleware as mw

    importlib.reload(mw)
    secret = "test-secret-expired"
    mw.set_csrf_secret(secret)
    # Create an expired token by manipulating timestamp
    import hashlib
    import hmac as hmac_mod

    old_ts = int(datetime.now(UTC).timestamp()) - 40000  # ~11 hours ago, past 8h TTL
    payload = f"session:{old_ts}"
    sig = hmac_mod.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    expired_token = f"{payload}:{sig}"
    assert mw.validate_csrf_token(expired_token, "session") is False


# ---------- Trusted proxy ----------


def test_extract_client_ip_no_proxy(monkeypatch):
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_TRUST_PROXY", False)
    req = MagicMock()
    req.client.host = "10.0.0.1"
    assert mw._extract_client_ip(req) == "10.0.0.1"


def test_extract_client_ip_no_client(monkeypatch):
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_TRUST_PROXY", False)
    req = MagicMock()
    req.client = None
    assert mw._extract_client_ip(req) == "unknown"


def test_extract_client_ip_xff(monkeypatch):
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_TRUST_PROXY", True)
    monkeypatch.setattr(mw, "_TRUSTED_PROXIES", frozenset())
    req = MagicMock()
    req.client.host = "10.0.0.1"
    req.headers = {"x-forwarded-for": "203.0.113.1, 10.0.0.1"}
    # BC-029 C: when TRUSTED_PROXIES is empty, use the rightmost (proxy) entry
    assert mw._extract_client_ip(req) == "10.0.0.1"


def test_extract_client_ip_xff_trusted_proxy(monkeypatch):
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_TRUST_PROXY", True)
    monkeypatch.setattr(mw, "_TRUSTED_PROXIES", frozenset(["10.0.0.1"]))
    req = MagicMock()
    req.client.host = "10.0.0.1"
    req.headers = {"x-forwarded-for": "203.0.113.1, 10.0.0.1"}
    assert mw._extract_client_ip(req) == "203.0.113.1"


def test_extract_client_ip_real_ip(monkeypatch):
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_TRUST_PROXY", True)
    monkeypatch.setattr(mw, "_TRUSTED_PROXIES", frozenset())
    req = MagicMock()
    req.client.host = "10.0.0.1"
    req.headers = {"x-real-ip": "203.0.113.2"}
    assert mw._extract_client_ip(req) == "203.0.113.2"


def test_extract_client_ip_fallback(monkeypatch):
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_TRUST_PROXY", True)
    monkeypatch.setattr(mw, "_TRUSTED_PROXIES", frozenset())
    req = MagicMock()
    req.client.host = "10.0.0.1"
    req.headers = {}
    assert mw._extract_client_ip(req) == "10.0.0.1"


def test_extract_client_ip_xff_empty(monkeypatch):
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_TRUST_PROXY", True)
    monkeypatch.setattr(mw, "_TRUSTED_PROXIES", frozenset())
    req = MagicMock()
    req.client = None
    req.headers = {"x-forwarded-for": ""}
    assert mw._extract_client_ip(req) == "unknown"


# ---------- Metrics token ----------


def test_metrics_token_gate(reload_app, monkeypatch):
    app_mod = reload_app()
    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_METRICS_TOKEN", "my-secret")
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 401

    with TestClient(app_mod.app) as client:
        r = client.get("/metrics", headers={"Authorization": "Bearer my-secret"})
    assert r.status_code == 200


def test_metrics_token_wrong_bearer(reload_app, monkeypatch):
    app_mod = reload_app()
    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_METRICS_TOKEN", "my-secret")
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


# ---------- CSRF on form POST ----------


def test_csrf_rejected_when_missing(monkeypatch, tmp_path):
    """When CSRF is enabled, a request without token should be rejected."""
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "0")
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    import asyncio
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    req = MagicMock()
    req.headers = {}
    req.cookies = {"cw_sid": "test-sid"}
    req.scope = {}
    req.app.state.security = None

    async def fake_form():
        return {}

    req.form = fake_form
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(mw.check_csrf(req))
    finally:
        loop.close()
    assert result is not None  # "missing CSRF token"


# ---------- Session ID ----------


def test_get_session_id_from_cookie():
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    req = MagicMock()
    req.cookies = {"cw_sid": "abc123"}
    req.scope = {}
    assert mw.get_session_id(req) == "abc123"


def test_get_session_id_from_scope():
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    req = MagicMock()
    req.cookies = {}
    req.scope = {"session_id": "scope_id"}
    assert mw.get_session_id(req) == "scope_id"


def test_get_session_id_generated():
    from unittest.mock import MagicMock

    import cert_watch.middleware as mw

    req = MagicMock()
    req.cookies = {}
    req.scope = {}
    sid = mw.get_session_id(req)
    assert len(sid) == 32  # hex of 16 bytes
