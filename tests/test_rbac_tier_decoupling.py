"""Tests for WI-061 tier decoupling — scoped roles cannot elevate the permission tier.

The effective tier is the highest tier among the user's UNSCOPED (global) roles.
A user holding ONLY scoped roles defaults to ``viewer``.  Scope tags from ALL
roles (scoped + unscoped) are unioned for visibility/alerts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cert_watch.auth.rbac import (
    _resolve_tier_and_scope,
    build_auth_context,
)
from cert_watch.database import Role, SqliteRoleRepository, init_schema

# ---------- _resolve_tier_and_scope unit tests ----------


class TestResolveTierAndScope:
    """Direct tests of the tier/scope resolution logic."""

    def test_unscoped_admin_plus_scoped_role(self):
        """(a) unscoped admin + scoped role → tier=admin, scope=the scoped tags."""
        role_tiers = {
            "admin": ("admin", ""),
            "epic-team": ("operator", "epic"),
        }
        tier, scope = _resolve_tier_and_scope(["admin", "epic-team"], role_tiers)
        assert tier == "admin"
        assert scope == "epic"

    def test_two_scoped_roles_no_unscoped(self):
        """(b) two scoped roles, no unscoped → tier=viewer, scope=union."""
        role_tiers = {
            "epic-team": ("admin", "epic"),
            "infra-team": ("operator", "infra, monitoring"),
        }
        tier, scope = _resolve_tier_and_scope(["epic-team", "infra-team"], role_tiers)
        assert tier == "viewer"
        # parse_tags/format_tags normalize and de-dupe (case-insensitively);
        # order is first-seen, not sorted, so compare as a set.
        assert set(scope.split(",")) == {"epic", "infra", "monitoring"}

    def test_unscoped_operator_only(self):
        """(c) unscoped operator only → tier=operator, scope empty (full visibility)."""
        role_tiers = {
            "ops": ("operator", ""),
        }
        tier, scope = _resolve_tier_and_scope(["ops"], role_tiers)
        assert tier == "operator"
        assert scope == ""

    def test_footgun_regression_scoped_operator_does_not_elevate(self):
        """(d) viewer + scoped operator → tier=viewer (NOT operator).

        This is the core footgun fix: adding a scoped operator role for
        visibility does NOT elevate a viewer to operator.
        """
        role_tiers = {
            "viewer": ("viewer", ""),
            "epic-team": ("operator", "epic"),
        }
        tier, scope = _resolve_tier_and_scope(["viewer", "epic-team"], role_tiers)
        assert tier == "viewer"
        assert scope == "epic"

    def test_multi_tag_scope_parsed_correctly(self):
        """A single role with comma-separated scope tags is parsed into individual tags."""
        role_tiers = {
            "team": ("viewer", "epic, infra, monitoring"),
        }
        tier, scope = _resolve_tier_and_scope(["team"], role_tiers)
        assert tier == "viewer"
        assert set(scope.split(",")) == {"epic", "infra", "monitoring"}

    def test_empty_role_list_defaults_to_viewer(self):
        tier, scope = _resolve_tier_and_scope([], {})
        assert tier == "viewer"
        assert scope == ""

    def test_unscoped_admin_overrides_scoped_admin(self):
        """An unscoped admin role sets tier=admin even if a scoped admin also exists."""
        role_tiers = {
            "global-admin": ("admin", ""),
            "scoped-admin": ("admin", "restricted"),
        }
        tier, scope = _resolve_tier_and_scope(["global-admin", "scoped-admin"], role_tiers)
        assert tier == "admin"
        assert scope == "restricted"


# ---------- build_auth_context integration tests ----------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    init_schema(db)
    return db


class TestBuildAuthContextTierDecoupling:
    """Integration tests through build_auth_context with a real role repo."""

    def _make_role_map(self, *role_names: str) -> dict:
        return {name: {"groups": [f"g-{name}"]} for name in role_names}

    def test_unscoped_admin_plus_scoped_operator(self, db_path: Path):
        repo = SqliteRoleRepository(db_path)
        repo.add(Role(name="global-admin", permission_tier="admin", scope_tag=""))
        repo.add(Role(name="epic-team", permission_tier="operator", scope_tag="epic"))

        ctx = build_auth_context(
            "alice",
            user_groups=["g-global-admin", "g-epic-team"],
            user_roles=[],
            role_map=self._make_role_map("global-admin", "epic-team"),
            role_repo=repo,
        )
        assert ctx.tier == "admin"
        assert ctx.is_admin
        assert "epic" in ctx.scope_tag

    def test_only_scoped_roles_defaults_to_viewer(self, db_path: Path):
        repo = SqliteRoleRepository(db_path)
        repo.add(Role(name="epic-team", permission_tier="admin", scope_tag="epic"))
        repo.add(Role(name="infra-team", permission_tier="operator", scope_tag="infra"))

        ctx = build_auth_context(
            "bob",
            user_groups=["g-epic-team", "g-infra-team"],
            user_roles=[],
            role_map=self._make_role_map("epic-team", "infra-team"),
            role_repo=repo,
        )
        assert ctx.tier == "viewer"
        assert not ctx.may_write()
        assert not ctx.is_admin
        assert set(ctx.scope_tag.split(",")) == {"epic", "infra"}

    def test_unscoped_operator_full_visibility(self, db_path: Path):
        repo = SqliteRoleRepository(db_path)
        repo.add(Role(name="ops", permission_tier="operator", scope_tag=""))

        ctx = build_auth_context(
            "carol",
            user_groups=["g-ops"],
            user_roles=[],
            role_map=self._make_role_map("ops"),
            role_repo=repo,
        )
        assert ctx.tier == "operator"
        assert ctx.may_write()
        assert ctx.scope_tag == ""

    def test_footgun_regression_via_build_auth_context(self, db_path: Path):
        """Adding a scoped operator role to a viewer does NOT elevate to operator."""
        repo = SqliteRoleRepository(db_path)
        repo.add(Role(name="viewer", permission_tier="viewer", scope_tag=""))
        repo.add(Role(name="epic-team", permission_tier="operator", scope_tag="epic"))

        ctx = build_auth_context(
            "dave",
            user_groups=["g-viewer", "g-epic-team"],
            user_roles=[],
            role_map=self._make_role_map("viewer", "epic-team"),
            role_repo=repo,
        )
        assert ctx.tier == "viewer"
        assert not ctx.may_write()
        assert "epic" in ctx.scope_tag
