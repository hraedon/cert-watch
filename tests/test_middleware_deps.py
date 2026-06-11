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
    csrf = make_csrf_token(token)
    request = _make_request(
        auth_provider=provider,
        cookies={SESSION_COOKIE: token},
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


# ── Plan 035 RBAC: write enforcement must be consistent across API + forms ──
#
# Regression guard for the split-enforcement bug: when a role map is active,
# require_write (API) honoured it but require_write_form (HTML form POSTs:
# add-host, upload, delete) did not — it fell through to _may_write, which
# returns True when write_users is empty (the expected config under RBAC), so
# a viewer could mutate via the form routes. Both paths now share _write_denied.


def _app_with_role_map(tmp_path):
    """Build a fake app whose settings carry a (truthy) role map."""
    from cert_watch.config import Settings

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={"operator": {"groups": ["g-ops"]}},
    )
    app = type("App", (), {
        "state": type("State", (), {
            "auth_provider": _Provider(),
            "settings": settings,
        })(),
    })()
    return app, _Provider


def test_write_denied_rbac_matrix(tmp_path):
    """_write_denied: under a role map, the AuthContext decides; otherwise legacy."""
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.middleware import _write_denied

    app, Provider = _app_with_role_map(tmp_path)
    request = _make_request(auth_provider=Provider())
    request.scope["app"] = app

    request.state.auth_context = AuthContext.from_roles("bob", ["viewer"])
    assert _write_denied(request, "bob") is True

    request.state.auth_context = AuthContext.from_roles("alice", ["operator"])
    assert _write_denied(request, "alice") is False

    request.state.auth_context = AuthContext.from_roles("carol", ["admin"])
    assert _write_denied(request, "carol") is False


@pytest.mark.anyio
async def test_require_write_form_rbac_viewer_denied(tmp_path):
    """The bug: a viewer must be blocked at the form-POST routes, not just the API."""
    from fastapi.responses import RedirectResponse

    from cert_watch.auth.rbac import AuthContext
    from cert_watch.middleware import require_write_form

    app, Provider = _app_with_role_map(tmp_path)
    request = _make_request(auth_provider=Provider())
    request.scope["app"] = app
    request.scope["auth_user"] = "viewer"
    request.state.auth_context = AuthContext.from_roles("viewer", ["viewer"])

    result = await require_write_form(request)
    assert isinstance(result, RedirectResponse)
    assert result.status_code == 303
    assert "read-only" in result.headers["location"]


@pytest.mark.anyio
async def test_require_write_form_rbac_operator_allowed(tmp_path):
    """An operator passes the write gate at a form-POST route (CSRF still enforced)."""
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.middleware import make_csrf_token, require_write_form

    app, Provider = _app_with_role_map(tmp_path)
    session_token = create_session("alice")
    request = _make_request(
        auth_provider=Provider(),
        cookies={SESSION_COOKIE: session_token},
        headers={"x-csrf-token": make_csrf_token(session_token)},
    )
    request.scope["app"] = app
    request.scope["auth_user"] = "alice"
    request.state.auth_context = AuthContext.from_roles("alice", ["operator"])

    # None == allowed (write gate + CSRF both pass)
    assert await require_write_form(request) is None


@pytest.mark.anyio
async def test_require_write_rbac_viewer_denied(tmp_path):
    """The API path stays consistent: a viewer is rejected with 403."""
    from cert_watch.auth import SESSION_COOKIE, create_session

    app, Provider = _app_with_role_map(tmp_path)
    # require_auth rebuilds the AuthContext from the role map; with no groups
    # plumbed through the session, the user resolves to viewer.
    request = _make_request(
        auth_provider=Provider(),
        cookies={SESSION_COOKIE: create_session("viewer")},
    )
    request.scope["app"] = app
    with pytest.raises(HTTPException) as exc_info:
        await require_write(request)
    assert exc_info.value.status_code == 403
    assert "read-only user" in exc_info.value.detail


@pytest.mark.anyio
async def test_require_write_rbac_operator_allowed(tmp_path):
    """BC-145: when the session token carries IdP groups that match the role map,
    the user is resolved to operator and write is allowed."""
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.middleware import make_csrf_token

    app, Provider = _app_with_role_map(tmp_path)
    session_token = create_session("alice", groups=["g-ops"])
    request = _make_request(
        auth_provider=Provider(),
        cookies={SESSION_COOKIE: session_token},
        headers={"x-csrf-token": make_csrf_token(session_token)},
    )
    request.scope["app"] = app
    # require_auth + require_write should succeed without raising
    username = await require_write(request)
    assert username == "alice"
    assert request.state.auth_context.may_write() is True
    assert request.state.auth_context.roles == ["operator"]


# ── BC-145: auth_middleware must set auth_context for form-POST routes ───


@pytest.mark.anyio
async def test_auth_middleware_sets_auth_context_for_rbac(tmp_path):
    """auth_middleware sets request.state.auth_context so that form-POST routes
    (which use require_write_form, not require_auth) enforce RBAC.
    """
    from fastapi.responses import PlainTextResponse

    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.middleware import auth_middleware

    app, Provider = _app_with_role_map(tmp_path)
    token = create_session("alice", groups=["g-ops"])
    request = _make_request(
        auth_provider=Provider(),
        cookies={SESSION_COOKIE: token},
    )
    request.scope["app"] = app
    request.scope["path"] = "/hosts"

    async def _call_next(request):
        return PlainTextResponse("ok")

    response = await auth_middleware(request, _call_next)
    assert response.status_code == 200
    assert request.state.auth_context.roles == ["operator"]
    assert request.state.auth_context.may_write() is True


@pytest.mark.anyio
async def test_auth_middleware_sets_auth_context_viewer(tmp_path):
    """auth_middleware sets auth_context for a viewer (no matching groups)."""
    from fastapi.responses import PlainTextResponse

    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.middleware import auth_middleware

    app, Provider = _app_with_role_map(tmp_path)
    token = create_session("bob", groups=["unrelated-group"])
    request = _make_request(
        auth_provider=Provider(),
        cookies={SESSION_COOKIE: token},
    )
    request.scope["app"] = app
    request.scope["path"] = "/hosts"

    async def _call_next(request):
        return PlainTextResponse("ok")

    response = await auth_middleware(request, _call_next)
    assert response.status_code == 200
    assert request.state.auth_context.roles == ["viewer"]
    assert request.state.auth_context.may_write() is False


@pytest.mark.anyio
async def test_auth_middleware_no_role_map_no_auth_context(tmp_path):
    """When no role_map is configured, auth_middleware does not need to set
    auth_context because the legacy _may_write path handles it.
    """
    from fastapi.responses import PlainTextResponse

    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings
    from cert_watch.middleware import auth_middleware

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
    )
    app = type("App", (), {
        "state": type("State", (), {
            "auth_provider": _Provider(),
            "settings": settings,
        })(),
    })()
    token = create_session("alice")
    request = _make_request(
        auth_provider=_Provider(),
        cookies={SESSION_COOKIE: token},
    )
    request.scope["app"] = app
    request.scope["path"] = "/hosts"

    async def _call_next(request):
        return PlainTextResponse("ok")

    response = await auth_middleware(request, _call_next)
    assert response.status_code == 200
    # Even without a role map, auth_middleware now sets auth_context so that
    # all downstream code (templates, form helpers) has a single source of truth.
    assert request.state.auth_context is not None
    assert request.state.auth_context.may_write() is True


# ── require_admin_form / require_admin_write_form ────────────────────────
#
# These mirror require_auth / require_write for form-POST handlers that
# return RedirectResponse on failure (settings tabs, role/user CRUD).
# They replace the manual ``_require_admin`` + ``check_csrf`` boilerplate
# that used to live in routes/settings.py.


class _AppWithAdmin:
    """Fake app with a configurable role map and admin_users list."""

    def __init__(self, role_map=None, admin_users=None):
        from cert_watch.config import Settings

        class _Provider:
            pass

        self.state = type("State", (), {
            "auth_provider": _Provider(),
            "settings": Settings(
                db_path="/tmp/_unused.sqlite3",
                data_dir="/tmp",
                role_map=role_map or {},
                admin_users=admin_users or [],
            ),
        })()


def _admin_request(
    path: str,
    *,
    auth_provider=None,
    cookies=None,
    headers=None,
    username: str | None = None,
    groups=None,
    roles=None,
):
    """Build a Request whose scope includes a real session cookie + RBAC groups.

    The form helpers key off ``request.scope['auth_user']`` (set by the
    auth_middleware pipeline in production); we set it explicitly here so
    the unit test doesn't need the full middleware stack.
    """
    from cert_watch.auth import SESSION_COOKIE, create_session

    if auth_provider is not None and username is not None:
        token = create_session(username, groups=groups or [], roles=roles or [])
        cookies = {**(cookies or {}), SESSION_COOKIE: token}
    request = _make_request(
        auth_provider=auth_provider,
        cookies=cookies,
        headers=headers,
    )
    request.scope["path"] = path
    if username is not None:
        request.scope["auth_user"] = username
    return request


@pytest.mark.anyio
async def test_require_admin_form_no_auth_returns_none():
    """No auth configured → no admin check, returns None."""
    from cert_watch.middleware import require_admin_form

    request = _admin_request("/settings/roles", auth_provider=NoAuthProvider())
    assert require_admin_form(request) is None


@pytest.mark.anyio
async def test_require_admin_form_no_session_redirects_to_login(tmp_path):
    """Auth configured but no user → 303 to /login."""
    from fastapi.responses import RedirectResponse

    from cert_watch.middleware import require_admin_form

    class _Provider:
        pass

    app = type("App", (), {"state": type("State", (), {"auth_provider": _Provider()})()})()
    request = _admin_request("/settings/roles", auth_provider=_Provider())
    request.scope["app"] = app
    response = require_admin_form(request)
    assert isinstance(response, RedirectResponse)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.anyio
async def test_require_admin_form_non_admin_redirects_with_error(tmp_path):
    """An authenticated non-admin is bounced back to the page with ?error=admin+required."""
    from fastapi.responses import RedirectResponse

    from cert_watch.config import Settings
    from cert_watch.middleware import require_admin_form

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={"admin": {"groups": ["g-admins"]}},
    )
    app = type("App", (), {
        "state": type("State", (), {"auth_provider": _Provider(), "settings": settings})(),
    })()
    # User has no admin group → not an admin
    request = _admin_request(
        "/settings/roles",
        auth_provider=_Provider(),
        username="bob",
        groups=["g-others"],
    )
    request.scope["app"] = app
    response = require_admin_form(request)
    assert isinstance(response, RedirectResponse)
    assert response.status_code == 303
    assert "error=admin" in response.headers["location"]
    assert response.headers["location"].startswith("/settings")


@pytest.mark.anyio
async def test_require_admin_form_rbac_admin_allowed(tmp_path):
    """RBAC admin (admin group match) → None."""
    from cert_watch.config import Settings
    from cert_watch.middleware import require_admin_form

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={"admin": {"groups": ["g-admins"]}},
    )
    app = type("App", (), {
        "state": type("State", (), {"auth_provider": _Provider(), "settings": settings})(),
    })()
    request = _admin_request(
        "/settings/roles",
        auth_provider=_Provider(),
        username="alice",
        groups=["g-admins"],
    )
    request.scope["app"] = app
    # Manually attach AuthContext (the auth_middleware pipeline would normally
    # do this — for the form helper we simulate the post-pipeline state).
    from cert_watch.auth.rbac import AuthContext

    request.state.auth_context = AuthContext.from_roles("alice", ["admin"])
    assert require_admin_form(request) is None


@pytest.mark.anyio
async def test_require_admin_form_legacy_admin_users_fallback(tmp_path):
    """No role map + user in admin_users → allowed (RBAC-off backward compat)."""
    from cert_watch.config import Settings
    from cert_watch.middleware import require_admin_form

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        admin_users=("alice",),
    )
    app = type("App", (), {
        "state": type("State", (), {"auth_provider": _Provider(), "settings": settings})(),
    })()
    request = _admin_request(
        "/settings/roles",
        auth_provider=_Provider(),
        username="alice",
    )
    request.scope["app"] = app
    assert require_admin_form(request) is None


@pytest.mark.anyio
async def test_require_admin_write_form_csrf_failure(tmp_path):
    """require_admin_write_form catches CSRF failures too (admin + write + CSRF)."""
    from fastapi.responses import RedirectResponse

    from cert_watch.config import Settings
    from cert_watch.middleware import require_admin_write_form

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        admin_users=("alice",),
    )
    app = type("App", (), {
        "state": type("State", (), {"auth_provider": _Provider(), "settings": settings})(),
    })()
    request = _admin_request(
        "/settings/roles",
        auth_provider=_Provider(),
        username="alice",
        # No CSRF token → expect CSRF failure (CSRF is re-enabled in this test file)
    )
    request.scope["app"] = app
    response = await require_admin_write_form(request)
    assert isinstance(response, RedirectResponse)
    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert "csrf" in response.headers["location"].lower() or "CSRF" in response.headers["location"]


@pytest.mark.anyio
async def test_require_admin_write_form_all_pass(tmp_path):
    """All three checks pass → returns None."""
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings
    from cert_watch.middleware import make_csrf_token, require_admin_write_form

    class _Provider:
        pass

    settings = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        admin_users=("alice",),
    )
    app = type("App", (), {
        "state": type("State", (), {"auth_provider": _Provider(), "settings": settings})(),
    })()
    session_token = create_session("alice")
    request = _make_request(
        auth_provider=_Provider(),
        cookies={SESSION_COOKIE: session_token},
        headers={"x-csrf-token": make_csrf_token(session_token)},
    )
    request.scope["path"] = "/settings/roles"
    request.scope["auth_user"] = "alice"
    request.scope["app"] = app
    assert await require_admin_write_form(request) is None


# ── get_auth_context: is_admin ─────────────────────────────────────────────


def test_get_auth_context_admin_is_admin_true(tmp_path):
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.middleware import get_auth_context

    request = _make_request()
    request.scope["auth_user"] = "alice"
    request.state.auth_context = AuthContext.from_roles("alice", ["admin"])
    ctx = get_auth_context(request)
    assert ctx["is_admin"] is True


def test_get_auth_context_viewer_is_admin_false(tmp_path):
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.middleware import get_auth_context

    request = _make_request()
    request.scope["auth_user"] = "bob"
    request.state.auth_context = AuthContext.from_roles("bob", ["viewer"])
    ctx = get_auth_context(request)
    assert ctx["is_admin"] is False


def test_get_auth_context_operator_is_admin_false(tmp_path):
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.middleware import get_auth_context

    request = _make_request()
    request.scope["auth_user"] = "ops"
    request.state.auth_context = AuthContext.from_roles("ops", ["operator"])
    ctx = get_auth_context(request)
    assert ctx["is_admin"] is False


def test_get_auth_context_no_auth_context_is_admin_true(tmp_path):
    from cert_watch.middleware import get_auth_context

    request = _make_request()
    request.scope["auth_user"] = ""
    ctx = get_auth_context(request)
    assert ctx["is_admin"] is True

