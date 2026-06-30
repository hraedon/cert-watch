"""Tests for users and roles (Plan 040)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth import LocalAdminProvider, _scrypt_hash
from cert_watch.database import (
    Role,
    SqliteRoleRepository,
    SqliteUserRepository,
    User,
    init_schema,
)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "test.db"
    init_schema(path)
    return path


# ---------- Role repository ----------


class TestRoleRepository:
    def test_add_and_get(self, db):
        repo = SqliteRoleRepository(db)
        role = Role(name="operators", email="ops@example.com", description="Ops team")
        role_id = repo.add(role)
        fetched = repo.get(role_id)
        assert fetched is not None
        assert fetched.name == "operators"
        assert fetched.email == "ops@example.com"
        assert fetched.description == "Ops team"

    def test_get_by_name(self, db):
        repo = SqliteRoleRepository(db)
        repo.add(Role(name="admins", email="admins@example.com"))
        fetched = repo.get_by_name("admins")
        assert fetched is not None
        assert fetched.name == "admins"

    def test_list_all(self, db):
        repo = SqliteRoleRepository(db)
        repo.add(Role(name="a", email="a@example.com"))
        repo.add(Role(name="b", email="b@example.com"))
        assert len(repo.list_all()) == 2

    def test_update(self, db):
        repo = SqliteRoleRepository(db)
        role_id = repo.add(Role(name="old", email="old@example.com"))
        role = repo.get(role_id)
        role.name = "new"
        role.email = "new@example.com"
        repo.update(role)
        fetched = repo.get(role_id)
        assert fetched.name == "new"
        assert fetched.email == "new@example.com"

    def test_delete(self, db):
        repo = SqliteRoleRepository(db)
        role_id = repo.add(Role(name="tmp", email="tmp@example.com"))
        repo.delete(role_id)
        assert repo.get(role_id) is None


# ---------- User repository ----------


class TestUserRepository:
    def test_add_and_get(self, db):
        role_repo = SqliteRoleRepository(db)
        role_id = role_repo.add(Role(name="ops", email="ops@example.com"))

        user_repo = SqliteUserRepository(db)
        user = User(
            username="jsmith",
            email="jsmith@example.com",
            password_hash="h",
            role_id=role_id,
        )
        user_id = user_repo.add(user)
        fetched = user_repo.get(user_id)
        assert fetched is not None
        assert fetched.username == "jsmith"
        assert fetched.email == "jsmith@example.com"
        assert fetched.role_id == role_id

    def test_get_by_username(self, db):
        user_repo = SqliteUserRepository(db)
        user_repo.add(User(
            username="alice", email="a@example.com", password_hash="h", role_id=None,
        ))
        fetched = user_repo.get_by_username("alice")
        assert fetched is not None
        assert fetched.username == "alice"

    def test_list_all(self, db):
        user_repo = SqliteUserRepository(db)
        user_repo.add(User(
            username="u1", email="u1@example.com", password_hash="h", role_id=None,
        ))
        user_repo.add(User(
            username="u2", email="u2@example.com", password_hash="h", role_id=None,
        ))
        assert len(user_repo.list_all()) == 2

    def test_update(self, db):
        role_repo = SqliteRoleRepository(db)
        role_id = role_repo.add(Role(name="ops", email="ops@example.com"))
        user_repo = SqliteUserRepository(db)
        user_id = user_repo.add(User(
            username="old", email="old@example.com", password_hash="h", role_id=role_id,
        ))
        user = user_repo.get(user_id)
        user.username = "new"
        user_repo.update(user)
        assert user_repo.get(user_id).username == "new"

    def test_delete(self, db):
        user_repo = SqliteUserRepository(db)
        user_id = user_repo.add(User(
            username="tmp", email="tmp@example.com", password_hash="h", role_id=None,
        ))
        user_repo.delete(user_id)
        assert user_repo.get(user_id) is None


# ---------- Local admin provider with DB users ----------


class TestLocalAdminProviderDB:
    def test_authenticate_db_user_success(self, db):
        role_repo = SqliteRoleRepository(db)
        role_id = role_repo.add(Role(name="operators", email="ops@example.com"))

        user_repo = SqliteUserRepository(db)
        pw_hash = _scrypt_hash("password123", n=2**4, r=1, p=1)
        user_repo.add(
            User(
                username="jsmith",
                email="jsmith@example.com",
                password_hash=pw_hash,
                role_id=role_id,
            )
        )

        provider = LocalAdminProvider("admin", "h", db_path=str(db))
        result = provider.authenticate("jsmith", "password123")
        assert result.success is True
        assert result.username == "jsmith"
        assert result.email == "jsmith@example.com"
        assert result.roles == ["operators"]

    def test_authenticate_db_user_wrong_password(self, db):
        user_repo = SqliteUserRepository(db)
        pw_hash = _scrypt_hash("password123", n=2**4, r=1, p=1)
        user_repo.add(
            User(
                username="jsmith",
                email="jsmith@example.com",
                password_hash=pw_hash,
                role_id=None,
            )
        )

        provider = LocalAdminProvider("admin", "h", db_path=str(db))
        result = provider.authenticate("jsmith", "wrong")
        assert result.success is False
        assert "invalid" in result.error.lower()

    def test_fallback_to_legacy_admin(self, db):
        h = _scrypt_hash("adminpass", n=2**4, r=1, p=1)
        provider = LocalAdminProvider("admin", h, db_path=str(db))
        result = provider.authenticate("admin", "adminpass")
        assert result.success is True
        assert result.username == "admin"
        assert result.groups == ["admins"]
        assert result.roles == ["admin"]


# ---------- Session token with email ----------


class TestSessionEmail:
    def test_create_and_decode_with_email(self):
        from cert_watch.auth.session import create_session, decode_session

        token = create_session("alice", email="alice@example.com")
        info = decode_session(token)
        assert info is not None
        assert info.email == "alice@example.com"

    def test_backward_compat_no_email(self):
        from cert_watch.auth.session import decode_session

        # Old-format token without email
        old_token = "alice:1:1234567890:abc123"
        # Need to sign it properly
        from cert_watch.auth.session import _sign_session
        signed = _sign_session(old_token)
        info = decode_session(signed)
        assert info is not None
        assert info.email == ""


# ---------- Settings routes (basic) ----------


class TestSettingsRoutes:
    def test_roles_page_loads(self, reload_app, monkeypatch, tmp_path):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/settings/roles")
        # No auth provider → open access (backward compat)
        assert r.status_code == 200
        assert "Roles" in r.text

    def test_users_page_loads(self, reload_app, monkeypatch, tmp_path):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/settings/users")
        assert r.status_code == 200
        assert "Users" in r.text

    def test_update_user_changes_role(self, reload_app, monkeypatch, tmp_path):
        import re

        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            client.post("/settings/roles", data={"name": "ops", "email": "ops@x.com"},
                        follow_redirects=False)
            client.post("/settings/roles", data={"name": "secops", "email": "sec@x.com"},
                        follow_redirects=False)
            page = client.get("/settings/users").text
            ops_id = re.search(r'<option value="([^"]+)">ops</option>', page).group(1)
            secops_id = re.search(r'<option value="([^"]+)">secops</option>', page).group(1)
            client.post("/settings/users", data={
                "username": "jsmith", "password": "password123",
                "email": "j@x.com", "role_id": ops_id,
            }, follow_redirects=False)
            page = client.get("/settings/users").text
            uid = re.search(r'/settings/users/([0-9a-f-]{36})"', page).group(1)
            # Edit: move jsmith from ops -> secops, no new password.
            r = client.post(f"/settings/users/{uid}", data={
                "username": "jsmith", "email": "j@x.com", "role_id": secops_id,
            }, follow_redirects=False)
            assert r.status_code == 303
            assert "saved=1" in r.headers["location"]

        from cert_watch.config import Settings
        from cert_watch.database import SqliteUserRepository
        users = SqliteUserRepository(Settings.from_env().db_path).list_all()
        jsmith = next(u for u in users if u.username == "jsmith")
        assert jsmith.role_id == secops_id

    def test_update_user_error_paths(self, reload_app, monkeypatch, tmp_path):
        import re

        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            # Create a role so user creation/update satisfies the role_id FK.
            client.post("/settings/roles", data={"name": "ops", "email": "ops@x.com"},
                        follow_redirects=False)
            role_id = re.search(
                r'<option value="([^"]+)">ops</option>',
                client.get("/settings/users").text,
            ).group(1)

            # Unknown (well-formed) user id -> not found.
            r = client.post("/settings/users/00000000-0000-0000-0000-000000000000",
                            data={"username": "x"}, follow_redirects=False)
            assert r.status_code == 303
            assert "not+found" in r.headers["location"]

            client.post("/settings/users", data={
                "username": "jsmith", "password": "password123", "email": "j@x.com",
                "role_id": role_id,
            }, follow_redirects=False)
            uid = re.search(
                r'/settings/users/([0-9a-f-]{36})"', client.get("/settings/users").text
            ).group(1)

            # Missing username -> error.
            r = client.post(f"/settings/users/{uid}", data={"username": "  "},
                            follow_redirects=False)
            assert "username+required" in r.headers["location"]

            # Too-short new password -> error.
            r = client.post(f"/settings/users/{uid}",
                            data={"username": "jsmith", "password": "short"},
                            follow_redirects=False)
            assert "at+least+8" in r.headers["location"]

            # Valid new password -> hash changes.
            r = client.post(f"/settings/users/{uid}",
                            data={"username": "jsmith", "password": "newpassword123",
                                  "role_id": role_id},
                            follow_redirects=False)
            assert "saved=1" in r.headers["location"]

        from cert_watch.config import Settings
        from cert_watch.database import SqliteUserRepository
        u = next(
            x for x in SqliteUserRepository(Settings.from_env().db_path).list_all()
            if x.username == "jsmith"
        )
        # A scrypt hash was stored (not the plaintext).
        assert u.password_hash and "newpassword123" not in u.password_hash
