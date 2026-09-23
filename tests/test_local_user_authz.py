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

    base = Settings.from_env()
    settings = Settings.from_env_with_kv(base.db_path)
    return create_app(auth_provider=provider, settings=settings)


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
        assert json.loads(kv_get(env, "ldap_role_map"))[ops_id]["groups"] == ["cn=ops"]

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
    roles = SqliteRoleRepository(db)
    ops_id = roles.add(Role(name="ops", permission_tier="operator"))
    admins_id = roles.add(Role(name="admins", permission_tier="admin"))
    kv_set(db, "ldap_role_map", json.dumps({
        ops_id: {"groups": ["ui-ops"]}, admins_id: {"users": ["boss"]},
    }))
    from cert_watch.config import Settings

    s = Settings.from_env_with_kv(db)
    assert s.role_map["ops"] == {"groups": ["env-ops"]}
    assert s.role_map["admins"] == {"groups": [], "users": ["boss"], "role_id": admins_id}


# ---------- PR #78 review: B1 -- a stale UI mapping must grant nothing ----------


def _save_mapping(client, role_id: str, groups: str = "", users: str = ""):
    r = client.post(
        "/settings/ldap-role-map",
        data={f"role_map_{role_id}": groups, f"role_users_{role_id}": users},
        follow_redirects=False,
    )
    assert "saved" in r.headers["location"], r.headers["location"]


def _mapped_env(env):
    """A scoped viewer role literally named "admin" mapped to IT-Admins, plus an
    unrelated mapping so the role map stays non-empty once "admin" goes."""
    roles = SqliteRoleRepository(env)
    admin_named = roles.add(Role(name="admin", permission_tier="viewer", scope_tag="x"))
    staff = roles.add(Role(name="staff", permission_tier="viewer"))
    return admin_named, staff


def _composite(db: Path):
    from cert_watch.auth import LocalAdminProvider, _CompositeProvider

    local = LocalAdminProvider("admin", _hash("testpassword"), db_path=str(db))
    return _CompositeProvider(local, _DirectoryProvider())


def _it_admin_is_admin(client, login_csrf) -> bool:
    _login(client, login_csrf, "itguy", "x")  # _DirectoryProvider: groups=["cn=ops"]
    return "saved" in _create_role(client, "probe-by-itguy").headers["location"]


def test_deleting_a_mapped_role_does_not_grant_admin(env, login_csrf):
    admin_named, staff = _mapped_env(env)
    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")  # break-glass
        _save_mapping(client, admin_named, groups="cn=ops")
        _save_mapping(client, staff, groups="cn=staff")
        assert not _it_admin_is_admin(client, login_csrf)  # scoped viewer

        _login(client, login_csrf, "admin", "testpassword")
        r = client.post(f"/settings/roles/{admin_named}/delete", follow_redirects=False)
        assert "saved" in r.headers["location"]
        assert not _it_admin_is_admin(client, login_csrf)
    stored = json.loads(kv_get(env, "ldap_role_map"))
    assert admin_named not in stored and "admin" not in stored


def test_renaming_a_mapped_role_does_not_grant_admin(env, login_csrf):
    admin_named, staff = _mapped_env(env)
    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")
        _save_mapping(client, admin_named, groups="cn=ops")
        _save_mapping(client, staff, groups="cn=staff")
        r = client.post(
            f"/settings/roles/{admin_named}",
            data={"name": "payments-team", "permission_tier": "viewer", "scope_tag": "x"},
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"]
        assert not _it_admin_is_admin(client, login_csrf)
        # The mapping followed the rename: itguy now holds payments-team.
        assert client.get("/settings/users", follow_redirects=False).status_code == 303


def test_stale_ui_mapping_key_grants_nothing(tmp_path, monkeypatch):
    """A UI entry naming no existing role (e.g. a legacy name-keyed entry for a
    deleted role) is dropped -- no fall back to the built-in admin tier."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_ROLE_MAP", raising=False)
    db = _seed(tmp_path)
    staff = SqliteRoleRepository(db).add(Role(name="staff", permission_tier="viewer"))
    kv_set(db, "ldap_role_map", json.dumps({
        "admin": {"groups": ["cn=ops"]},          # legacy key, no such role
        "no-such-id": {"groups": ["cn=ops"]},     # id of a deleted role
        staff: {"groups": ["cn=staff"]},
    }))
    from cert_watch.config import Settings

    s = Settings.from_env_with_kv(db)
    assert set(s.role_map) == {"staff"}


def test_ui_entry_for_a_deleted_role_grants_nothing_even_before_rebuild(env):
    """Settings are cached; a mapping whose role vanished must still grant nothing."""
    from cert_watch.auth.rbac import build_auth_context

    role_map = {
        "admin": {"groups": ["cn=ops"], "role_id": "deleted-role-id"},
        "staff": {"groups": ["cn=staff"]},
    }
    ctx = build_auth_context(
        "itguy", ["cn=ops"], [], role_map, role_repo=SqliteRoleRepository(env),
    )
    assert not ctx.is_admin and not ctx.may_write()


# ---------- PR #78 review: N1 -- an oversized session keeps its marker ----------


def test_oversized_session_never_drops_the_local_marker():
    from cert_watch.auth import decode_session
    from cert_watch.auth.rbac import LOCAL_USER_CLAIM
    from cert_watch.auth.session import create_session

    token = create_session(
        "vic", version=1, groups=["g" * 50] * 60, roles=[LOCAL_USER_CLAIM],
        email="e" * 5000 + "@example.com",
    )
    info = decode_session(token)
    assert info is not None and LOCAL_USER_CLAIM in info.roles


def test_viewer_with_oversized_email_does_not_get_full_access(env, login_csrf):
    SqliteUserRepository(env).add(User(
        username="bigmail", email="e" * 5000 + "@example.com",
        password_hash=_hash("password123"), role_id=None,
    ))
    with TestClient(_app()) as client:
        _login(client, login_csrf, "bigmail")
        assert "error" in _create_role(client, "sneaky").headers["location"]


@pytest.mark.parametrize("field,value", [
    ("username", "u" * 129), ("email", "e" * 250 + "@example.com"),
])
def test_settings_users_caps_username_and_email(env, login_csrf, field, value):
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        data = {"username": "ok", "password": "password123", "email": "a@example.com"}
        data[field] = value
        r = client.post("/settings/users", data=data, follow_redirects=False)
        assert "error" in r.headers["location"]
    assert SqliteUserRepository(env).list_all() == []


# ---------- PR #78 review: N2 -- break-glass cannot be shadowed ----------


def test_local_user_named_like_break_glass_does_not_shadow_it(env, login_csrf):
    SqliteUserRepository(env).add(User(
        username="admin", email="", password_hash=_hash("other-password"), role_id=None,
    ))
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        assert "saved" in _create_role(client, "still-break-glass").headers["location"]


@pytest.mark.parametrize("name", ["admin", "ADMIN", " Admin "])
def test_settings_users_rejects_break_glass_username(env, login_csrf, name):
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        r = client.post(
            "/settings/users",
            data={"username": name, "password": "password123", "email": ""},
            follow_redirects=False,
        )
        assert "error" in r.headers["location"]
        SqliteUserRepository(env).add(User(
            username="bob", email="", password_hash=_hash("password123"), role_id=None,
        ))
        uid = SqliteUserRepository(env).get_by_username("bob").id
        r = client.post(
            f"/settings/users/{uid}", data={"username": name, "email": ""},
            follow_redirects=False,
        )
        assert "error" in r.headers["location"]
    assert SqliteUserRepository(env).get_by_username("bob") is not None


# ---------- PR #78 review 2: S1 -- pre-upgrade session tokens are rejected ----------


def _pre_pr_token(client, payload: str) -> str:
    """A token exactly as the pre-PR create_session minted it: the HMAC is over
    the bare payload."""
    import hashlib
    import hmac as _hmac

    key = client.app.state.security.signing_key.encode()
    return f"{payload}:{_hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()[:64]}"


def _signed_out_with(client, token: str) -> bool:
    client.cookies.set(SESSION_COOKIE, token)
    r = client.get("/browse", follow_redirects=False)
    return r.status_code == 303 and r.headers["location"] == "/login"


@pytest.mark.parametrize("username", ["vic", "admin", "dirk"])
def test_pre_upgrade_unmarked_session_is_signed_out(env, username):
    """Local user, break-glass admin and directory user alike: 4-part token."""
    import time as _t

    _add_user(env, "vic", tier="viewer")
    with TestClient(_app(_composite(env))) as client:
        payload = f"{username}:1:{int(_t.time())}:0123456789abcdef"
        assert _signed_out_with(client, _pre_pr_token(client, payload))


def test_pre_upgrade_token_claiming_break_glass_is_signed_out(env):
    import time as _t

    from cert_watch.auth.rbac import BREAK_GLASS_CLAIM
    from cert_watch.auth.session import _encode_list

    with TestClient(_app(_composite(env))) as client:
        payload = (
            f"dirk:1:{int(_t.time())}:0123456789abcdef:"
            f":{_encode_list([BREAK_GLASS_CLAIM])}"
        )
        assert _signed_out_with(client, _pre_pr_token(client, payload))


def test_freshly_minted_session_is_accepted(env, login_csrf):
    """Control for the S1 tests: a normal login still works."""
    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")
        assert client.get("/browse", follow_redirects=False).status_code == 200


# ---------- PR #78 review 2: S2 -- a renamed user's cookie cannot be rebound ----------


def test_renamed_user_cookie_does_not_bind_to_a_recreated_username(env, login_csrf):
    _add_user(env, "alice", tier="viewer")
    admin_role = SqliteRoleRepository(env).add(Role(name="admins", permission_tier="admin"))
    with TestClient(_app()) as client:
        _login(client, login_csrf, "alice")
        alice_cookie = client.cookies.get(SESSION_COOKIE)

        _login(client, login_csrf, "admin", "testpassword")
        uid = SqliteUserRepository(env).get_by_username("alice").id
        r = client.post(
            f"/settings/users/{uid}", data={"username": "alice-old", "email": ""},
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"]
        r = client.post(
            "/settings/users",
            data={"username": "alice", "password": "password123", "email": "",
                  "role_id": admin_role},
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"]

        client.cookies.delete(SESSION_COOKIE)
        assert _signed_out_with(client, alice_cookie.strip('"'))


def test_renamed_user_old_cookie_is_revoked(env, login_csrf):
    _add_user(env, "alice", tier="viewer")
    with TestClient(_app()) as client:
        _login(client, login_csrf, "alice")
        alice_cookie = client.cookies.get(SESSION_COOKIE)
        _login(client, login_csrf, "admin", "testpassword")
        uid = SqliteUserRepository(env).get_by_username("alice").id
        client.post(
            f"/settings/users/{uid}", data={"username": "alice-old", "email": ""},
            follow_redirects=False,
        )
        client.cookies.delete(SESSION_COOKIE)
        assert _signed_out_with(client, alice_cookie.strip('"'))


# ---------- PR #78 re-verification: B-1 -- a DB error never empties the role map ----------


def test_role_map_db_error_during_rebuild_keeps_last_good_settings(env, login_csrf, monkeypatch):
    import sqlite3

    staff = SqliteRoleRepository(env).add(Role(name="ops", permission_tier="viewer"))
    app = _app(_composite(env))
    with TestClient(app, raise_server_exceptions=False) as client:
        _login(client, login_csrf, "admin", "testpassword")
        _save_mapping(client, staff, groups="cn=ops")

        def locked(self):
            raise sqlite3.OperationalError("database is locked")

        with monkeypatch.context() as m:
            m.setattr(SqliteRoleRepository, "list_all", locked)
            client.post("/settings/smtp", data={}, follow_redirects=False)
        assert app.state.settings.role_map, "a failed rebuild replaced the role map"
        assert not _it_admin_is_admin(client, login_csrf)  # dirk/itguy: mapped viewer


def test_startup_role_map_failure_fails_closed(env, monkeypatch):
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    def boom(*_a, **_k):
        raise OSError("disk I/O error")

    monkeypatch.setattr(Settings, "from_env_with_kv", classmethod(boom))
    app = create_app()
    with TestClient(app):
        assert app.state.settings.role_map, "startup fell back to an empty role map"


# ---------- N-1: once mapping is configured, an empty map is least privilege ----------


def test_deleting_the_last_mapped_role_does_not_restore_full_access(env, login_csrf):
    ops = SqliteRoleRepository(env).add(Role(name="ops", permission_tier="viewer"))
    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")
        _save_mapping(client, ops, groups="cn=ops")
        r = client.post(f"/settings/roles/{ops}/delete", follow_redirects=False)
        assert "saved" in r.headers["location"]
        assert not _it_admin_is_admin(client, login_csrf)
        host_id = SqliteHostRepository(env).add("a.example.com", 443)
        assert "error" in _post_notes(client, host_id).headers["location"]


def test_clearing_the_last_mapping_does_not_restore_full_access(env, login_csrf):
    ops = SqliteRoleRepository(env).add(Role(name="ops", permission_tier="viewer"))
    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")
        _save_mapping(client, ops, groups="cn=ops")
        _save_mapping(client, ops)  # both fields cleared
        assert not _it_admin_is_admin(client, login_csrf)


def test_existing_nonempty_ui_map_counts_as_configured(tmp_path, monkeypatch):
    """Upgrade path: a map saved by an earlier release sets the sticky flag."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_ROLE_MAP", raising=False)
    db = _seed(tmp_path)
    kv_set(db, "ldap_role_map", json.dumps({"gone-role": {"groups": ["cn=x"]}}))
    from cert_watch.auth.rbac import build_auth_context
    from cert_watch.config import Settings

    s = Settings.from_env_with_kv(db)
    ctx = build_auth_context("dirk", ["cn=x"], [], s.role_map, SqliteRoleRepository(db))
    assert not ctx.is_admin and not ctx.may_write()


def test_never_configured_install_keeps_legacy_full_access(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_ROLE_MAP", raising=False)
    db = _seed(tmp_path)
    from cert_watch.config import Settings

    assert Settings.from_env_with_kv(db).role_map == {}


def test_roles_page_warns_before_deleting_the_last_mapping(env, login_csrf):
    ops = SqliteRoleRepository(env).add(Role(name="ops", permission_tier="viewer"))
    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")
        _save_mapping(client, ops, groups="cn=ops")
        page = client.get("/settings/roles").text
    assert "last IdP mapping" in page


# ---------- N-2: legacy name-keyed entries are normalised, never adopted ----------


def test_legacy_name_key_is_not_adopted_by_a_recreated_role(env, login_csrf):
    roles = SqliteRoleRepository(env)
    old = roles.add(Role(name="admin", permission_tier="viewer", scope_tag="x"))
    roles.add(Role(name="staff", permission_tier="viewer"))
    # As stored by a pre-PR release: keyed by role NAME.
    kv_set(env, "ldap_role_map", json.dumps({
        "admin": {"groups": [], "users": ["helpdesk"]},
        "staff": {"groups": ["cn=staff"], "users": []},
    }))
    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")
        r = client.post(
            f"/settings/roles/{old}",
            data={"name": "helpdesk-team", "permission_tier": "viewer", "scope_tag": "x"},
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"]
        r = client.post(
            "/settings/roles", data={"name": "admin", "permission_tier": "admin"},
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"]
        client.post("/settings/smtp", data={}, follow_redirects=False)  # any rebuild
        _login(client, login_csrf, "helpdesk", "x")
        assert "error" in _create_role(client, "by-helpdesk").headers["location"]
    stored = json.loads(kv_get(env, "ldap_role_map"))
    assert "admin" not in stored and "staff" not in stored  # no name keys remain


def test_name_keys_are_ignored_once_normalised(tmp_path, monkeypatch):
    from cert_watch.auth.rbac import load_ui_role_map, normalize_ui_role_map

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    db = _seed(tmp_path)
    ops = SqliteRoleRepository(db).add(Role(name="ops"))
    kv_set(db, "ldap_role_map", json.dumps({
        "ops": {"groups": ["cn=ops"]}, "ghost": {"groups": ["cn=g"]},
    }))
    normalize_ui_role_map(db)
    assert json.loads(kv_get(db, "ldap_role_map")) == {
        ops: {"groups": ["cn=ops"], "users": []},
    }
    # A name key written later (e.g. by hand) is not honoured.
    kv_set(db, "ldap_role_map", json.dumps({"ops": {"groups": ["cn=ops"]}}))
    assert load_ui_role_map(db) == {}


# ---------- N-3: session and OAuth-state MACs are domain-separated ----------


def test_session_token_is_not_a_valid_oauth_state():
    import hashlib
    import hmac as _hmac
    import time as _t

    from cert_watch.auth.session import _key, _verify_state, create_session

    assert _verify_state(create_session("alice", version=1)) is None
    payload = f"alice:1:{int(_t.time())}:0123456789abcdef"  # pre-1.0 session shape
    mac = _hmac.new(_key(None).encode(), payload.encode(), hashlib.sha256).hexdigest()[:64]
    legacy = f"{payload}:{mac}"
    assert _verify_state(legacy) is None


def test_oauth_state_is_not_a_valid_session_token():
    from cert_watch.auth.session import _sign_state, _verify_state, decode_session

    state = _sign_state("alice:1:1790000000", nonce="0123456789abcdef")
    assert _verify_state(state) is not None  # control: it is a valid state
    assert decode_session(state) is None


# ---------- Sol re-verification: no instant where a new identity meets an old cookie ----------


def _residual_cookie(client, db: Path, username: str) -> str:
    """A current-format local-user cookie for *username* at its current
    session version -- e.g. left over from a renamed or deleted account."""
    from cert_watch.auth.rbac import LOCAL_USER_CLAIM
    from cert_watch.auth.session import create_session
    from cert_watch.database import get_session_version

    version = get_session_version(str(db), username)
    return create_session(
        username, client.app.state.security, version=version, roles=[LOCAL_USER_CLAIM],
    )


def _probe_in_write(monkeypatch, method: str, client, db: Path, token: str, seen: list):
    """Run the real repository write, then -- before the route continues --
    check whether *token* still validates. Deterministic interleaving."""
    from cert_watch.auth.session import validate_session

    real = getattr(SqliteUserRepository, method)

    def probed(self, *args, **kwargs):
        result = real(self, *args, **kwargs)
        seen.append(validate_session(token, client.app.state.security, db_path=str(db)))
        return result

    monkeypatch.setattr(SqliteUserRepository, method, probed)


def test_create_user_never_exposes_new_row_to_a_residual_cookie(env, login_csrf, monkeypatch):
    admin_role = SqliteRoleRepository(env).add(Role(name="admins", permission_tier="admin"))
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        stale = _residual_cookie(client, env, "alice")
        seen: list = []
        _probe_in_write(monkeypatch, "add", client, env, stale, seen)
        r = client.post(
            "/settings/users",
            data={"username": "alice", "password": "password123", "email": "",
                  "role_id": admin_role},
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"]
    assert seen == [None], "old cookie validated against the freshly inserted account"


def test_rename_never_exposes_new_name_to_a_residual_cookie(env, login_csrf, monkeypatch):
    _add_user(env, "carol", tier="admin")
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        stale = _residual_cookie(client, env, "bob")
        seen: list = []
        _probe_in_write(monkeypatch, "update", client, env, stale, seen)
        uid = SqliteUserRepository(env).get_by_username("carol").id
        r = client.post(
            f"/settings/users/{uid}", data={"username": "bob", "email": ""},
            follow_redirects=False,
        )
        assert "saved" in r.headers["location"]
    assert seen == [None], "old 'bob' cookie validated against the renamed account"


def test_delete_revokes_before_the_row_goes(env, login_csrf, monkeypatch):
    _add_user(env, "dave", tier="admin")
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        live = _residual_cookie(client, env, "dave")
        seen: list = []
        _probe_in_write(monkeypatch, "delete", client, env, live, seen)
        uid = SqliteUserRepository(env).get_by_username("dave").id
        client.post(f"/settings/users/{uid}/delete", follow_redirects=False)
    assert seen == [None]


# ---------- final batch ----------


def test_delete_revokes_again_after_the_row_goes(env, login_csrf, monkeypatch):
    """A login that read its version between the first bump and the delete
    must not keep a cookie for the vanished account."""
    from cert_watch.auth.session import validate_session

    _add_user(env, "erin", tier="viewer")
    with TestClient(_app()) as client:
        _login(client, login_csrf, "admin", "testpassword")
        real = SqliteUserRepository.delete
        minted: list[str] = []

        def delete_after_racing_login(self, user_id):
            minted.append(_residual_cookie(client, env, "erin"))  # post-bump version
            return real(self, user_id)

        monkeypatch.setattr(SqliteUserRepository, "delete", delete_after_racing_login)
        uid = SqliteUserRepository(env).get_by_username("erin").id
        client.post(f"/settings/users/{uid}/delete", follow_redirects=False)
        assert validate_session(
            minted[0], client.app.state.security, db_path=str(env),
        ) is None


@pytest.mark.parametrize("stored", ["{not json", "[1, 2]", '"text"'])
def test_malformed_stored_role_map_fails_closed(tmp_path, monkeypatch, stored):
    from cert_watch.auth.rbac import build_auth_context
    from cert_watch.config import Settings

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_ROLE_MAP", raising=False)
    db = _seed(tmp_path)
    kv_set(db, "ldap_role_map", stored)
    s = Settings.from_env_with_kv(db)
    ctx = build_auth_context("dirk", ["cn=ops"], [], s.role_map, SqliteRoleRepository(db))
    assert not ctx.is_admin and not ctx.may_write()


def test_stored_empty_object_without_flag_keeps_legacy(tmp_path, monkeypatch):
    from cert_watch.config import Settings

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_ROLE_MAP", raising=False)
    db = _seed(tmp_path)
    kv_set(db, "ldap_role_map", "{}")
    assert Settings.from_env_with_kv(db).role_map == {}


def test_concurrent_mapping_saves_do_not_lose_an_edit(env, login_csrf, monkeypatch):
    import threading

    import cert_watch.auth.rbac as rbac
    from cert_watch.database import get_write_lock

    roles = SqliteRoleRepository(env)
    mine = roles.add(Role(name="mine", permission_tier="viewer"))
    theirs = roles.add(Role(name="theirs", permission_tier="viewer"))
    real_load = rbac.load_ui_role_map
    other: list[threading.Thread] = []

    def other_admin_saves():
        with get_write_lock():  # a concurrent save's read-modify-write
            data = json.loads(kv_get(env, "ldap_role_map") or "{}")
            data[theirs] = {"groups": ["cn=theirs"], "users": []}
            kv_set(env, "ldap_role_map", json.dumps(data))

    def load_then_race(db_path):
        result = real_load(db_path)
        if not other:
            t = threading.Thread(target=other_admin_saves)
            other.append(t)
            t.start()
            t.join(0.3)  # blocks here only if our save holds the lock
        return result

    with TestClient(_app(_composite(env))) as client:
        _login(client, login_csrf, "admin", "testpassword")
        monkeypatch.setattr(rbac, "load_ui_role_map", load_then_race)
        _save_mapping(client, mine, groups="cn=mine")
        other[0].join(5)
    stored = json.loads(kv_get(env, "ldap_role_map"))
    assert set(stored) == {mine, theirs}
