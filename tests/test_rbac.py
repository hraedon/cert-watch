"""Tests for Plan 035 RBAC module."""
from cert_watch.auth.rbac import (
    ROLE_OPERATOR,
    AuthContext,
    Permission,
    build_auth_context,
    permissions_for_roles,
    resolve_roles,
)


class TestPermission:
    def test_values(self):
        assert Permission.CERT_READ.value == "cert:read"
        assert Permission.CERT_WRITE.value == "cert:write"
        assert Permission.SETTINGS_ADMIN.value == "settings:admin"

    def test_permission_is_str(self):
        assert isinstance(Permission.CERT_READ, str)


class TestAuthContext:
    def test_admin_has_all_perms(self):
        ctx = AuthContext.from_roles("alice", ["admin"])
        assert ctx.has_permission(Permission.CERT_READ)
        assert ctx.may_write()
        assert ctx.is_admin

    def test_viewer_cannot_write(self):
        ctx = AuthContext.from_roles("bob", ["viewer"])
        assert not ctx.may_write()
        assert not ctx.is_admin

    def test_operator_can_write(self):
        ctx = AuthContext.from_roles("ops", [ROLE_OPERATOR])
        assert ctx.may_write()
        assert not ctx.is_admin

    def test_full_access(self):
        ctx = AuthContext.full_access("root")
        assert ctx.may_write()
        assert ctx.is_admin

    def test_permissions_for_roles(self):
        p = permissions_for_roles(["admin"])
        assert Permission.CERT_WRITE in p
        p2 = permissions_for_roles(["viewer"])
        assert Permission.CERT_READ in p2
        assert Permission.CERT_WRITE not in p2


class TestResolveRoles:
    def test_no_map_gives_admin(self):
        roles = resolve_roles([], [], {})
        assert roles == ["admin"]

    def test_group_match(self):
        role_map = {"admin": {"groups": ["cn=admins,ou=groups,dc=example"]}}
        result = resolve_roles(
            ["cn=admins,ou=groups,dc=example"], [], role_map
        )
        assert "admin" in result

    def test_no_match_falls_to_viewer(self):
        role_map = {"admin": {"groups": ["non-matching-group"]}}
        result = resolve_roles([], [], role_map)
        assert result == ["viewer"]

    def test_role_match(self):
        role_map = {"admin": {"roles": ["superuser"]}}
        result = resolve_roles([], ["superuser"], role_map)
        assert "admin" in result

    def test_user_match(self):
        # An IdP user named directly in a role's users list is granted that role
        # even with no group/role match (case-insensitive).
        role_map = {"operator": {"groups": [], "users": ["alice@example.com"]}}
        assert "operator" in resolve_roles([], [], role_map, username="ALICE@example.com")

    def test_user_no_match_falls_to_viewer(self):
        role_map = {"operator": {"users": ["alice@example.com"]}}
        assert resolve_roles([], [], role_map, username="bob@example.com") == ["viewer"]

    def test_union_of_roles(self):
        role_map = {
            "admin": {"groups": ["g1"]},
            "viewer": {"groups": ["g1"]},
        }
        result = resolve_roles(["g1"], [], role_map)
        assert "admin" in result
        assert "viewer" in result


class TestBuildAuthContext:
    def test_no_role_map_gives_full_access(self):
        ctx = build_auth_context("bob", [], [], {})
        assert ctx.may_write()

    def test_with_role_map(self):
        ctx = build_auth_context(
            "bob",
            user_groups=["cn=admins,ou=groups,dc=example,dc=com"],
            user_roles=[],
            role_map={"admin": {"groups": ["cn=admins,ou=groups,dc=example,dc=com"]}},
        )
        assert ctx.is_admin

    def test_no_match_falls_to_viewer(self):
        role_map = {"admin": {"groups": ["non-matching"]}}
        ctx = build_auth_context("bob", [], [], role_map)
        assert not ctx.may_write()


class TestPermissionsForRoles:
    def test_unknown_role_gives_no_perms(self):
        result = permissions_for_roles(["non-existent"])
        assert len(result) == 0

    def test_admin_gets_all(self):
        perms = permissions_for_roles(["admin"])
        assert Permission.CERT_WRITE in perms
        assert Permission.SETTINGS_ADMIN in perms
