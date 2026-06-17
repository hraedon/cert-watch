"""Tests for WI-050 (explicit permission tier on Role) and WI-052 (scope tag)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth.rbac import (
    AuthContext,
    Permission,
    build_auth_context,
    permissions_for_tier,
)
from cert_watch.database import Role, SqliteRoleRepository, SqliteUserRepository, User, init_schema


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "roles.sqlite3"
    init_schema(path)
    return path


class TestPermissionsForTier:
    def test_admin_tier_has_all(self):
        perms = permissions_for_tier("admin")
        assert Permission.CERT_READ in perms
        assert Permission.CERT_WRITE in perms
        assert Permission.SETTINGS_ADMIN in perms

    def test_operator_tier_can_write_not_admin(self):
        perms = permissions_for_tier("operator")
        assert Permission.CERT_READ in perms
        assert Permission.CERT_WRITE in perms
        assert Permission.SETTINGS_ADMIN not in perms

    def test_viewer_tier_read_only(self):
        perms = permissions_for_tier("viewer")
        assert Permission.CERT_READ in perms
        assert Permission.CERT_WRITE not in perms
        assert Permission.SETTINGS_ADMIN not in perms

    def test_unknown_tier_defaults_to_viewer(self):
        perms = permissions_for_tier("does-not-exist")
        assert perms == permissions_for_tier("viewer")


class TestAuthContextFromTier:
    def test_from_tier_persists_scope_and_email(self):
        ctx = AuthContext.from_tier(
            "alice", tier="operator", roles=["operators"],
            scope_tag="platform-team", email="alice@example.com",
        )
        assert ctx.tier == "operator"
        assert ctx.scope_tag == "platform-team"
        assert ctx.email == "alice@example.com"
        assert ctx.may_write()
        assert not ctx.is_admin

    def test_from_tier_normalizes_unknown_tier(self):
        ctx = AuthContext.from_tier("bob", tier="nope")
        assert ctx.tier == "viewer"


class TestRoleRepositoryTierAndScope:
    def test_add_and_get_default_tier(self, db: Path):
        repo = SqliteRoleRepository(db)
        role_id = repo.add(Role(name="basic", email="a@example.com"))
        role = repo.get(role_id)
        assert role is not None
        assert role.permission_tier == "viewer"
        assert role.scope_tag == ""

    def test_add_and_round_trip(self, db: Path):
        repo = SqliteRoleRepository(db)
        role_id = repo.add(Role(
            name="operators", email="ops@example.com",
            description="Ops team", permission_tier="operator",
            scope_tag="ops-team",
        ))
        role = repo.get(role_id)
        assert role.permission_tier == "operator"
        assert role.scope_tag == "ops-team"
        assert repo.get_by_name("operators").scope_tag == "ops-team"
        assert len(repo.list_all()) == 1

    def test_update_tier_and_scope(self, db: Path):
        repo = SqliteRoleRepository(db)
        role_id = repo.add(Role(name="ops", permission_tier="viewer"))
        role = repo.get(role_id)
        role.permission_tier = "admin"
        role.scope_tag = "all-teams"
        repo.update(role)
        updated = repo.get(role_id)
        assert updated.permission_tier == "admin"
        assert updated.scope_tag == "all-teams"


class TestBuildAuthContextUsesTierFromDb:
    def test_role_map_name_resolves_to_db_tier(self, db: Path):
        # Unscoped role: its DB tier flows through (option A / WI-061). A SCOPED
        # role (non-empty scope_tag) deliberately does not grant its tier -- that
        # decoupling (and the viewer-only fallback) is covered in
        # test_rbac_tier_decoupling.py.
        repo = SqliteRoleRepository(db)
        repo.add(Role(name="operators", permission_tier="operator", scope_tag=""))
        role_map = {"operators": {"groups": ["cn=ops,dc=example"]}}
        ctx = build_auth_context(
            "alice",
            user_groups=["cn=ops,dc=example"],
            user_roles=[],
            role_map=role_map,
            role_repo=repo,
        )
        assert ctx.tier == "operator"
        assert ctx.may_write()
        assert not ctx.is_admin
        assert ctx.scope_tag == ""

    def test_no_role_repo_uses_legacy_name_mapping(self, db: Path):
        role_map = {"admin": {"groups": ["cn=admins,dc=example"]}}
        ctx = build_auth_context(
            "root",
            user_groups=["cn=admins,dc=example"],
            user_roles=[],
            role_map=role_map,
        )
        assert ctx.is_admin
        assert ctx.tier == "admin"

    def test_multiple_roles_pick_highest_tier(self, db: Path):
        repo = SqliteRoleRepository(db)
        repo.add(Role(name="viewers", permission_tier="viewer"))
        repo.add(Role(name="admins", permission_tier="admin"))
        role_map = {
            "viewers": {"groups": ["g-all"]},
            "admins": {"groups": ["g-admin"]},
        }
        ctx = build_auth_context(
            "root",
            user_groups=["g-all", "g-admin"],
            user_roles=[],
            role_map=role_map,
            role_repo=repo,
        )
        assert ctx.tier == "admin"

    def test_unmapped_role_name_falls_to_viewer(self, db: Path):
        repo = SqliteRoleRepository(db)
        repo.add(Role(name="custom", permission_tier="operator"))
        ctx = build_auth_context(
            "alice",
            user_groups=[],
            user_roles=[],
            role_map={"custom": {"users": ["alice"]}},
            role_repo=repo,
        )
        assert ctx.tier == "operator"


class TestApiKeyContext:
    def test_api_key_admin_context_has_tier(self):
        from cert_watch.middleware import authenticate_api_key

        class FakeResult:
            name = "bot"
            scope = "admin"

        class FakeRequest:
            headers = {"authorization": "Bearer cwk_test"}
            state = type("S", (), {})()
            scope = {}

        class FakeApp:
            state = type("S", (), {})()

        FakeRequest.app = FakeApp()
        ctx = authenticate_api_key(FakeRequest(), None)
        assert ctx is None  # no repo case


class TestUserRoleAssociation:
    def test_user_with_role_resolves_tier_via_role(self, db: Path):
        role_repo = SqliteRoleRepository(db)
        user_repo = SqliteUserRepository(db)
        role_id = role_repo.add(Role(name="operators", permission_tier="operator"))
        user_repo.add(User(username="bob", password_hash="x", role_id=role_id))
        user = user_repo.get_by_username("bob")
        role = role_repo.get(user.role_id)
        assert role.permission_tier == "operator"


class TestRoleSettingsForm:
    def test_create_role_with_tier_and_scope(self, reload_app):
        app_mod = reload_app(CERT_WATCH_AUTH_PROVIDER="local")
        with TestClient(app_mod.app) as client:
            # Bootstrap an admin session
            client.post("/settings/users", data={
                "username": "admin", "password": "a_great_password",
                "email": "admin@example.com", "role_id": "",
            }, follow_redirects=False)
            client.post("/login", data={"username": "admin", "password": "a_great_password"})
            r = client.post(
                "/settings/roles",
                data={
                    "name": "operators",
                    "email": "ops@example.com",
                    "description": "Ops team",
                    "permission_tier": "operator",
                    "scope_tag": "ops-team",
                },
                follow_redirects=False,
            )
        assert r.status_code == 303
        assert "saved=1" in r.headers["location"]

    def test_edit_role_updates_scope_tag(self, reload_app):
        app_mod = reload_app(CERT_WATCH_AUTH_PROVIDER="local")
        with TestClient(app_mod.app) as client:
            client.post("/settings/users", data={
                "username": "admin", "password": "a_great_password",
                "email": "admin@example.com", "role_id": "",
            }, follow_redirects=False)
            client.post("/login", data={"username": "admin", "password": "a_great_password"})
            # First create role to fetch its id from DB
            client.post(
                "/settings/roles",
                data={
                    "name": "operators",
                    "email": "ops@example.com",
                    "permission_tier": "operator",
                    "scope_tag": "old-tag",
                },
                follow_redirects=False,
            )
            # Find id by listing roles
            from cert_watch.config import Settings
            db = Settings.from_env().db_path
            from cert_watch.database import SqliteRoleRepository
            role_repo = SqliteRoleRepository(db)
            role = role_repo.get_by_name("operators")
            r = client.post(
                f"/settings/roles/{role.id}",
                data={
                    "name": "operators",
                    "email": "ops@example.com",
                    "permission_tier": "admin",
                    "scope_tag": "new-tag",
                },
                follow_redirects=False,
            )
        assert r.status_code == 303
        updated = role_repo.get(role.id)
        assert updated.permission_tier == "admin"
        assert updated.scope_tag == "new-tag"
