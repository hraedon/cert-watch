"""Tests for FastAPI dependency functions require_auth and require_write."""

from __future__ import annotations

import pytest
from fastapi import Request
from fastapi.exceptions import HTTPException

from cert_watch.auth import NoAuthProvider, create_session
from cert_watch.middleware import require_auth, require_write


@pytest.fixture(autouse=True)
def _enable_csrf(monkeypatch):
    """conftest.py globally disables CSRF via CERT_WATCH_CSRF_DISABLED=1.

    These tests exercise CSRF validation, so we re-enable it.
    """
    monkeypatch.delenv("CERT_WATCH_CSRF_DISABLED", raising=False)
    yield


class _FakeApp:
    def __init__(self, auth_provider=None):
        self.state = type("State", (), {"auth_provider": auth_provider})()


class _FakeClient:
    host = "127.0.0.1"


def _make_request(auth_provider=None, cookies=None, headers=None) -> Request:
    """Build a minimal FastAPI Request for dependency tests."""
    hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        hdrs.append((b"cookie", cookie_str.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/test",
        "headers": hdrs,
        "app": _FakeApp(auth_provider),
        "client": ("127.0.0.1", 12345),
        "query_string": b"",
    }
    return Request(scope)


# ── require_auth ─────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_require_auth_no_auth_provider():
    """When auth_provider is None, require_auth returns '' (open)."""
    request = _make_request(auth_provider=None)
    result = await require_auth(request)
    assert result == ""


@pytest.mark.anyio
async def test_require_auth_no_auth_provider_instance():
    """When auth_provider is NoAuthProvider, require_auth returns '' (open)."""
    request = _make_request(auth_provider=NoAuthProvider())
    result = await require_auth(request)
    assert result == ""


@pytest.mark.anyio
async def test_require_auth_valid_session():
    """When auth is enabled and session cookie is valid, return username."""
    from cert_watch.auth import SESSION_COOKIE

    token = create_session("alice")
    request = _make_request(auth_provider=NoAuthProvider(), cookies={SESSION_COOKIE: token})
    # NoAuthProvider is still configured, so it should return "" without
    # validating the session. To test real auth, we need a provider that is
    # NOT NoAuthProvider.
    # We mock a provider with a validate_session that checks the token.
    class _MockProvider:
        pass

    provider = _MockProvider()
    request = _make_request(auth_provider=provider, cookies={SESSION_COOKIE: token})
    result = await require_auth(request)
    assert result == "alice"


@pytest.mark.anyio
async def test_require_auth_invalid_session():
    """When auth is enabled and session cookie is invalid, raise 401."""
    from cert_watch.auth import SESSION_COOKIE

    class _MockProvider:
        pass

    provider = _MockProvider()
    request = _make_request(auth_provider=provider, cookies={SESSION_COOKIE: "bad-token"})
    with pytest.raises(HTTPException) as exc_info:
        await require_auth(request)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "unauthenticated"


@pytest.mark.anyio
async def test_require_auth_missing_session():
    """When auth is enabled and no session cookie exists, raise 401."""
    class _MockProvider:
        pass

    provider = _MockProvider()
    request = _make_request(auth_provider=provider)
    with pytest.raises(HTTPException) as exc_info:
        await require_auth(request)
    assert exc_info.value.status_code == 401


# ── require_write ──────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_require_write_no_auth():
    """When auth is off, require_write returns '' without checking CSRF."""
    request = _make_request(auth_provider=None)
    result = await require_write(request)
    assert result == ""


@pytest.mark.anyio
async def test_require_write_csrf_missing():
    """When auth is on and CSRF token is missing, raise 403."""
    from cert_watch.auth import SESSION_COOKIE

    class _MockProvider:
        pass

    token = create_session("alice")
    provider = _MockProvider()
    request = _make_request(auth_provider=provider, cookies={SESSION_COOKIE: token})
    with pytest.raises(HTTPException) as exc_info:
        await require_write(request)
    assert exc_info.value.status_code == 403
    assert "missing CSRF token" in exc_info.value.detail


@pytest.mark.anyio
async def test_require_write_csrf_invalid():
    """When auth is on and CSRF token is invalid, raise 403."""
    from cert_watch.auth import SESSION_COOKIE

    class _MockProvider:
        pass

    token = create_session("alice")
    provider = _MockProvider()
    request = _make_request(
        auth_provider=provider,
        cookies={SESSION_COOKIE: token, "cw_sid": "session-123"},
        headers={"x-csrf-token": "tampered"},
    )
    try:
        await require_write(request)
        raise AssertionError("should have raised")
    except HTTPException as exc:
        assert exc.status_code == 403
        assert "invalid or expired CSRF token" in exc.detail


@pytest.mark.anyio
async def test_require_write_valid():
    """When auth is on and CSRF is valid, return username."""
    from cert_watch.auth import SESSION_COOKIE
    from cert_watch.middleware import make_csrf_token

    class _MockProvider:
        pass

    token = create_session("alice")
    provider = _MockProvider()
    sid = "session-abc"
    csrf = make_csrf_token(sid)
    request = _make_request(
        auth_provider=provider,
        cookies={SESSION_COOKIE: token, "cw_sid": sid},
        headers={"x-csrf-token": csrf},
    )
    result = await require_write(request)
    assert result == "alice"


# ── BC-086: write_users enforcement ──────────────────────────────────────


@pytest.mark.anyio
async def test_may_write_no_write_users_configured(monkeypatch, tmp_path):
    """When write_users is empty, all authenticated users can write."""
    from cert_watch.config import Settings
    from cert_watch.middleware import _may_write

    class _Provider:
        pass

    settings = Settings(db_path=tmp_path / "db.sqlite3", data_dir=tmp_path, write_users=())
    app = type("App", (), {
        "state": type("State", (), {
            "auth_provider": _Provider(),
            "settings": settings,
        })(),
    })()
    request = _make_request(auth_provider=_Provider())
    request.scope["app"] = app
    request.scope["auth_user"] = "viewer"
    assert _may_write(request, "viewer") is True


@pytest.mark.anyio
async def test_may_write_user_in_write_list(monkeypatch, tmp_path):
    """User in write_users list can write."""
    from cert_watch.config import Settings
    from cert_watch.middleware import _may_write

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3", data_dir=tmp_path, write_users=("writer1", "writer2")
    )
    app = type("App", (), {
        "state": type("State", (), {
            "auth_provider": _Provider(),
            "settings": settings,
        })(),
    })()
    request = _make_request(auth_provider=_Provider())
    request.scope["app"] = app
    request.scope["auth_user"] = "writer1"
    assert _may_write(request, "writer1") is True


@pytest.mark.anyio
async def test_may_write_user_not_in_list(monkeypatch, tmp_path):
    """User NOT in write_users and NOT in admin_users cannot write."""
    from cert_watch.config import Settings
    from cert_watch.middleware import _may_write

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        write_users=("writer1", "writer2"),
        admin_users=("admin1",),
    )
    app = type("App", (), {
        "state": type("State", (), {
            "auth_provider": _Provider(),
            "settings": settings,
        })(),
    })()
    request = _make_request(auth_provider=_Provider())
    request.scope["app"] = app
    request.scope["auth_user"] = "viewer"
    assert _may_write(request, "viewer") is False


@pytest.mark.anyio
async def test_may_write_admin_always_can_write(monkeypatch, tmp_path):
    """Admin users can write even if not explicitly in write_users."""
    from cert_watch.config import Settings
    from cert_watch.middleware import _may_write

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        write_users=("writer1",),
        admin_users=("admin1",),
    )
    app = type("App", (), {
        "state": type("State", (), {
            "auth_provider": _Provider(),
            "settings": settings,
        })(),
    })()
    request = _make_request(auth_provider=_Provider())
    request.scope["app"] = app
    request.scope["auth_user"] = "admin1"
    assert _may_write(request, "admin1") is True


@pytest.mark.anyio
async def test_may_write_no_auth_provider(monkeypatch):
    """When auth is disabled, _may_write returns True."""
    from cert_watch.middleware import _may_write

    request = _make_request(auth_provider=NoAuthProvider())
    assert _may_write(request, "anyone") is True


@pytest.mark.anyio
async def test_require_write_readonly_user_403(monkeypatch, tmp_path):
    """When write_users is set and user is not in it, require_write raises 403."""
    from cert_watch.auth import SESSION_COOKIE
    from cert_watch.config import Settings

    class _Provider:
        pass

    token = create_session("viewer")
    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        write_users=("writer1",),
        admin_users=("admin1",),
    )
    app = type("App", (), {
        "state": type("State", (), {
            "auth_provider": _Provider(),
            "settings": settings,
        })(),
    })()
    provider = _Provider()
    request = _make_request(
        auth_provider=provider,
        cookies={SESSION_COOKIE: token},
    )
    request.scope["app"] = app
    request.scope["auth_user"] = "viewer"
    with pytest.raises(HTTPException) as exc_info:
        await require_write(request)
    assert exc_info.value.status_code == 403
    assert "read-only user" in exc_info.value.detail
