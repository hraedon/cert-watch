"""Local accounts' roles are authoritative; the UI role map takes effect.

Follow-up to #59. Once accounts created in Settings → Users can log in, their
assigned role must decide what they can do even with no
``CERT_WATCH_ROLE_MAP`` -- the empty-role-map "everyone gets full access"
backward-compat is for directory (LDAP/OAuth) users only. A local account with
no role, or whose role was deleted, is a viewer. The break-glass admin stays
admin, including once a role map exists. The role mapping saved from
Settings → Roles is applied at runtime.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth import SESSION_COOKIE, _scrypt_hash
from cert_watch.auth.protocol import AuthProvider, AuthResult
from cert_watch.database import (
    Role,
    SqliteHostRepository,
    SqliteRoleRepository,
    SqliteUserRepository,
    User,
    init_schema,
    kv_get,
    kv_set,
)


def _hash(pw: str) -> str:
    return _scrypt_hash(pw, n=2**4, r=1, p=1)


def _seed(tmp_path: Path) -> Path:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", _hash("testpassword"))
    kv_set(db, "setup_complete", "1")
    return db


def _add_user(db: Path, username: str, *, tier: str | None, scope: str = "") -> str | None:
    role_id = None
    if tier is not None:
        role_id = SqliteRoleRepository(db).add(
            Role(name=f"{username}-role", permission_tier=tier, scope_tag=scope)
        )
    SqliteUserRepository(db).add(
        User(username=username, email="", password_hash=_hash("password123"), role_id=role_id)
    )
    return role_id


@pytest.fixture
def env(tmp_path, monkeypatch):
    import cert_watch.middleware as mw
    import cert_watch.routes.auth as auth_routes

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.delenv("CERT_WATCH_ROLE_MAP", raising=False)
    monkeypatch.setattr(mw, "_COOKIE_SECURE", False)
    monkeypatch.setattr(auth_routes, "_COOKIE_SECURE", False)
    return _seed(tmp_path)


def _app(provider: AuthProvider | None = None):
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    return create_app(auth_provider=provider, settings=Settings.from_env())


def _login(client, login_csrf, username, password="password123"):
    client.cookies.delete(SESSION_COOKIE)
    r = client.post(
        "/login",
        data={"username": username, "password": password, "_csrf_token": login_csrf(client)},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/", r.headers["location"]


def _create_role(client, name: str):
    return client.post(
        "/settings/roles", data={"name": name, "permission_tier": "admin"},
        follow_redirects=False,
    )


def _post_notes(client, host_id: str):
    return client.post(
        f"/hosts/{host_id}/notes", data={"notes": "touched"}, follow_redirects=False,
    )


def _notes(db: Path, host_id: str) -> str:
    return SqliteHostRepository(db).get(host_id).notes


# ---------- local roles are authoritative with no role map ----------


def test_viewer_local_user_cannot_admin_or_write(env, login_csrf):
    _add_user(env, "vic", tier="viewer")
    host_id = SqliteHostRepository(env).add("a.example.com", 443)
    with TestClient(_app()) as client:
        _login(client, login_csrf, "vic")
        r = _create_role(client, "sneaky")
        assert "error" in r.headers["location"]
        assert SqliteRoleRepository(env).get_by_name("sneaky") is None
        assert client.get("/settings/users", follow_redirects=False).status_code == 303
        r = _post_notes(client, host_id)
        assert "error" in r.headers["location"]
    assert _notes(env, host_id) == ""


def test_scoped_operator_local_user_writes_only_in_scope(env, login_csrf):
    _add_user(env, "olga", tier="operator", scope="payments")
    hosts = SqliteHostRepository(env)
    mine = hosts.add("pay.example.com", 443, tags="payments")
    theirs = hosts.add("hr.example.com", 443, tags="hr")
    with TestClient(_app()) as client:
        _login(client, login_csrf, "olga")
        assert _post_notes(client, mine).headers["location"] == "/"
        assert "error" in _post_notes(client, theirs).headers["location"]
        assert "error" in _create_role(client, "sneaky").headers["location"]
    assert _notes(env, mine) == "touched"
    assert _notes(env, theirs) == ""


def test_unscoped_admin_role_local_user_is_admin(env, login_csrf):
    _add_user(env, "ada", tier="admin")
    with TestClient(_app()) as client:
        _login(client, login_csrf, "ada")
        assert "saved" in _create_role(client, "made-by-ada").headers["location"]


def test_local_user_without_role_is_viewer(env, login_csrf):
    _add_user(env, "nobody", tier=None)
    host_id = SqliteHostRepository(env).add("a.example.com", 443)
    with TestClient(_app()) as client:
        _login(client, login_csrf, "nobody")
        assert client.get("/", follow_redirects=False).status_code == 200
        assert "error" in _post_notes(client, host_id).headers["location"]
        assert "error" in _create_role(client, "sneaky").headers["location"]


def test_local_user_whose_role_was_deleted_is_viewer(env, login_csrf):
    role_id = _add_user(env, "orphan", tier="admin")
    host_id = SqliteHostRepository(env).add("a.example.com", 443)
    with TestClient(_app()) as client:
        _login(client, login_csrf, "orphan")
        assert "saved" in _create_role(client, "while-admin").headers["location"]
        SqliteRoleRepository(env).delete(role_id)  # takes effect on the live session
        assert "error" in _create_role(client, "after-delete").headers["location"]
        assert "error" in _post_notes(client, host_id).headers["location"]


def test_break_glass_admin_stays_admin(env, login_csrf):
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        assert "saved" in _create_role(client, "ops").headers["location"]


def test_break_glass_admin_stays_admin_under_a_role_map(env, login_csrf, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_ROLE_MAP", json.dumps({"viewer": {"groups": ["g"]}}))
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        assert "saved" in _create_role(client, "ops").headers["location"]


def test_reserved_session_claims_cannot_come_from_an_idp():
    from cert_watch.auth.rbac import BREAK_GLASS_CLAIM, LOCAL_USER_CLAIM, claims_for_session

    role_map = {"admin": {"roles": [BREAK_GLASS_CLAIM, LOCAL_USER_CLAIM]}}
    _groups, roles = claims_for_session([], [BREAK_GLASS_CLAIM, LOCAL_USER_CLAIM], role_map)
    assert roles == []


def test_directory_user_named_like_local_user_does_not_inherit_its_role(env):
    """Local-role resolution keys on how the session was minted, not the name."""
    from cert_watch.auth.rbac import build_auth_context

    _add_user(env, "shared", tier="admin")
    ctx = build_auth_context(
        "shared", [], [], {"viewer": {"groups": ["g"]}},
        role_repo=SqliteRoleRepository(env), user_repo=SqliteUserRepository(env),
    )
    assert not ctx.is_admin


# ---------- the Settings → Roles mapping takes effect ----------


class _DirectoryProvider(AuthProvider):
    """Stand-in for LDAP: accepts any password for a fixed set of users."""

    def authenticate(self, username: str, password: str) -> AuthResult:
        return AuthResult(success=True, username=username, groups=["cn=ops"], roles=[])

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="n/a")

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return AuthResult(success=False, error="n/a")

    @property
    def provider_name(self) -> str:
        return "ldap"

    @property
    def supports_form_login(self) -> bool:
        return True


def test_ui_role_mapping_changes_directory_user_tier(env, login_csrf):
    ops_id = SqliteRoleRepository(env).add(Role(name="ops", permission_tier="operator"))
    admin_id = SqliteRoleRepository(env).add(Role(name="admins", permission_tier="admin"))
    with TestClient(_app(_DirectoryProvider())) as client:
        # No role map anywhere: directory users keep full access (backward compat).
        _login(client, login_csrf, "boss", "x")
        r = client.post(
            "/settings/ldap-role-map",
            data={
                f"role_map_{ops_id}": "cn=ops", f"role_users_{ops_id}": "",
                f"role_map_{admin_id}": "", f"role_users_{admin_id}": "boss",
            },
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"], r.headers["location"]
        assert json.loads(kv_get(env, "ldap_role_map"))["ops"]["groups"] == ["cn=ops"]

        # The mapping is live: "dirk" (group cn=ops) is an operator, not admin.
        _login(client, login_csrf, "dirk", "x")
        assert "error" in _create_role(client, "by-dirk").headers["location"]
        host_id = SqliteHostRepository(env).add("a.example.com", 443)
        assert _post_notes(client, host_id).headers["location"] == "/"

        # "boss", mapped individually to the admin role, is still admin.
        _login(client, login_csrf, "boss", "x")
        assert "saved" in _create_role(client, "by-boss").headers["location"]


def test_env_role_map_wins_per_role_over_ui_mapping(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ROLE_MAP", json.dumps({"ops": {"groups": ["env-ops"]}}))
    db = _seed(tmp_path)
    kv_set(db, "ldap_role_map", json.dumps({
        "ops": {"groups": ["ui-ops"]}, "admins": {"users": ["boss"]},
    }))
    from cert_watch.config import Settings

    s = Settings.from_env_with_kv(db)
    assert s.role_map["ops"] == {"groups": ["env-ops"]}
    assert s.role_map["admins"] == {"users": ["boss"]}
