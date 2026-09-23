"""#59: an account created through ``POST /settings/users`` can log in.

``Settings.build_auth_provider()`` must hand the database path to the
local-admin provider, otherwise the ``users`` table is never consulted and
every account an admin creates falls through to the break-glass comparison
and is rejected.  These tests drive the real routes end to end: the admin logs
in through ``POST /login``, creates a role and a user through the settings
forms, and the new user then logs in through ``POST /login``.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from cert_watch.auth import SESSION_COOKIE, _scrypt_hash, decode_session
from cert_watch.auth.rbac import build_auth_context
from cert_watch.database import (
    SqliteRoleRepository,
    SqliteUserRepository,
    init_schema,
    kv_set,
)


def _seed_local_admin(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", _scrypt_hash("testpassword", n=2**4, r=1, p=1))
    kv_set(db, "setup_complete", "1")
    return db


def _no_secure_cookies(monkeypatch):
    import cert_watch.middleware as mw
    import cert_watch.routes.auth as auth_routes

    monkeypatch.setattr(mw, "_COOKIE_SECURE", False)
    monkeypatch.setattr(auth_routes, "_COOKIE_SECURE", False)


def _login(client, login_csrf, username, password):
    client.cookies.delete(SESSION_COOKIE)
    token = login_csrf(client)
    return client.post(
        "/login",
        data={"username": username, "password": password, "_csrf_token": token},
        follow_redirects=False,
    )


def test_user_created_in_settings_can_log_in_with_role_tier(
    reload_app, tmp_path, monkeypatch, login_csrf
):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    db = _seed_local_admin(tmp_path)
    _no_secure_cookies(monkeypatch)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = _login(client, login_csrf, "admin", "testpassword")
        assert r.status_code == 303 and r.headers["location"] == "/"

        r = client.post(
            "/settings/roles",
            data={"name": "ops", "email": "ops@example.com", "permission_tier": "operator"},
            follow_redirects=False,
        )
        assert "error" not in r.headers["location"], r.headers["location"]
        page = client.get("/settings/users").text
        ops_id = re.search(r'<option value="([^"]+)">ops</option>', page).group(1)
        r = client.post(
            "/settings/users",
            data={
                "username": "jsmith", "password": "password123",
                "email": "j@example.com", "role_id": ops_id,
            },
            follow_redirects=False,
        )
        assert "error" not in r.headers["location"], r.headers["location"]

        r = _login(client, login_csrf, "jsmith", "password123")
        assert r.status_code == 303
        assert r.headers["location"] == "/", r.headers["location"]
        # The jar keeps the RFC 6265 quoting a colon-bearing value gets.
        raw = client.cookies.get(SESSION_COOKIE).strip('"')
        info = decode_session(raw, client.app.state.security)
        assert info is not None and info.username == "jsmith"
        # No role map is configured: the local account's own role decides.
        ctx = build_auth_context(
            info.username, info.groups, info.roles, {},
            role_repo=SqliteRoleRepository(db), user_repo=SqliteUserRepository(db),
        )
        assert ctx.tier == "operator"
        assert ctx.may_write() and not ctx.is_admin

        # The session is live and carries the operator tier, not admin.
        assert client.get("/", follow_redirects=False).status_code == 200
        r = client.get("/settings/users", follow_redirects=False)
        assert r.status_code == 303 and "/login" not in r.headers["location"]


def test_settings_build_auth_provider_passes_db_path(tmp_path, monkeypatch):
    """Every production construction path goes through this method."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    _seed_local_admin(tmp_path)
    from cert_watch.config import Settings

    base = Settings.from_env()
    s = Settings.from_env_with_kv(base.db_path)
    provider = s.build_auth_provider()
    assert getattr(provider, "db_path", None) == str(s.db_path)
