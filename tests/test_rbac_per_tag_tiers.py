"""Per-tag permission tiers (Plan 053 / WI-064).

The mixed-tier matrix: a user may be operator for tag A and viewer for
tag B. Write capability follows the resource's effective tags
(max-over-intersecting, decision D2) while the WI-061 global-tier
invariant holds (scoped roles never raise the global tier).
"""

from __future__ import annotations

import pytest

from cert_watch.auth.rbac import (
    AuthContext,
    _resolve_tier_and_scope,
    build_auth_context,
)
from cert_watch.database import init_schema
from cert_watch.database.users_roles import Role, SqliteRoleRepository


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "test.sqlite3"
    init_schema(path)
    return path


# ---------- AuthContext.may_write_tags / may_write_any ----------


class TestMayWriteTags:
    def _ctx(self, tier="viewer", tag_tiers=None):
        return AuthContext.from_tier(
            "alice", tier=tier, scope_tag=",".join((tag_tiers or {}).keys()),
            tag_tiers=tag_tiers or {},
        )

    def test_global_operator_writes_any_tags(self):
        ctx = self._ctx(tier="operator")
        assert ctx.may_write_tags({"prod"}) is True
        assert ctx.may_write_tags(set()) is True
        assert ctx.may_write_any() is True

    def test_tag_operator_writes_only_its_tag(self):
        ctx = self._ctx(tag_tiers={"prod": "operator", "edge": "viewer"})
        assert ctx.tier == "viewer"  # WI-061: global tier untouched
        assert ctx.may_write_tags({"prod"}) is True
        assert ctx.may_write_tags({"edge"}) is False
        assert ctx.may_write_any() is True

    def test_mixed_tags_use_max_over_intersecting(self):
        """D2: a cert tagged {prod, edge} is writable by a prod-operator."""
        ctx = self._ctx(tag_tiers={"prod": "operator", "edge": "viewer"})
        assert ctx.may_write_tags({"prod", "edge"}) is True

    def test_all_viewer_tags_cannot_write(self):
        ctx = self._ctx(tag_tiers={"prod": "viewer", "edge": "viewer"})
        assert ctx.may_write_tags({"prod", "edge"}) is False
        assert ctx.may_write_any() is False

    def test_unrelated_tags_cannot_write(self):
        ctx = self._ctx(tag_tiers={"prod": "operator"})
        assert ctx.may_write_tags({"staging"}) is False

    def test_empty_tag_tiers_falls_back_to_global(self):
        assert self._ctx(tier="viewer").may_write_tags({"prod"}) is False
        assert self._ctx(tier="operator").may_write_tags({"prod"}) is True


# ---------- _resolve_tier_and_scope builds tag_tiers ----------


class TestResolveTagTiers:
    def test_scoped_role_tier_applies_per_tag(self):
        role_tiers = {"prod-ops": ("operator", "prod", {})}
        tier, scope, tag_tiers = _resolve_tier_and_scope(["prod-ops"], role_tiers)
        assert tier == "viewer"  # WI-061 invariant
        assert tag_tiers == {"prod": "operator"}

    def test_override_row_beats_role_default(self):
        role_tiers = {"mixed": ("viewer", "prod, edge", {"prod": "operator"})}
        _tier, _scope, tag_tiers = _resolve_tier_and_scope(["mixed"], role_tiers)
        assert tag_tiers == {"prod": "operator", "edge": "viewer"}

    def test_max_across_roles_per_tag(self):
        role_tiers = {
            "a": ("viewer", "prod", {}),
            "b": ("operator", "prod", {}),
        }
        _tier, _scope, tag_tiers = _resolve_tier_and_scope(["a", "b"], role_tiers)
        assert tag_tiers == {"prod": "operator"}

    def test_unscoped_roles_do_not_pollute_tag_tiers(self):
        role_tiers = {"admin": ("admin", "", {})}
        tier, _scope, tag_tiers = _resolve_tier_and_scope(["admin"], role_tiers)
        assert tier == "admin"
        assert tag_tiers == {}


# ---------- repository round-trip + build_auth_context integration ----------


class TestEndToEnd:
    def test_repo_round_trip(self, db):
        repo = SqliteRoleRepository(db)
        rid = repo.add(Role(name="prod-ops", permission_tier="operator", scope_tag="prod, edge"))
        repo.set_tag_tiers(rid, {"edge": "viewer"})
        assert repo.list_tag_tiers(rid) == {"edge": "viewer"}
        assert repo.all_tag_tiers() == {rid: {"edge": "viewer"}}
        repo.set_tag_tiers(rid, {})
        assert repo.list_tag_tiers(rid) == {}

    def test_build_auth_context_carries_tag_tiers(self, db):
        repo = SqliteRoleRepository(db)
        rid = repo.add(Role(name="prod-ops", permission_tier="operator", scope_tag="prod, edge"))
        repo.set_tag_tiers(rid, {"edge": "viewer"})
        ctx = build_auth_context(
            "alice",
            user_groups=["g-prod"],
            user_roles=[],
            role_map={"prod-ops": {"groups": ["g-prod"]}},
            role_repo=repo,
        )
        assert ctx.tier == "viewer"  # WI-061: scoped role never raises tier
        assert ctx.may_write() is False
        assert ctx.may_write_tags({"prod"}) is True   # role default: operator
        assert ctx.may_write_tags({"edge"}) is False  # override row: viewer
        assert ctx.may_write_any() is True

    def test_role_delete_cascades_tag_tiers(self, db):
        repo = SqliteRoleRepository(db)
        rid = repo.add(Role(name="t", permission_tier="viewer", scope_tag="x"))
        repo.set_tag_tiers(rid, {"x": "operator"})
        repo.delete(rid)
        assert repo.all_tag_tiers() == {}


# ---------- enforcement seam: scope_write_denied ----------


class TestScopeWriteSeam:
    class _Req:
        """Minimal request stand-in carrying only state.auth_context."""

        def __init__(self, ctx):
            class _State:
                pass

            self.state = _State()
            self.state.auth_context = ctx

    @pytest.fixture
    def host_and_cert(self, db):
        from cert_watch.database import SqliteHostRepository

        host_repo = SqliteHostRepository(db)
        return host_repo.add("prod1.test", 443, tags="prod")

    def test_tag_operator_may_write_in_scope_host(self, db, host_and_cert):
        from cert_watch.routes._scoped import scope_write_denied

        ctx = AuthContext.from_tier(
            "alice", tier="viewer", scope_tag="prod",
            tag_tiers={"prod": "operator"},
        )
        assert scope_write_denied(self._Req(ctx), db, host_id=host_and_cert) is None

    def test_tag_viewer_denied_in_scope_host(self, db, host_and_cert):
        """Visible but read-only: the Plan 053 enforcement line."""
        from cert_watch.routes._scoped import scope_write_denied

        ctx = AuthContext.from_tier(
            "alice", tier="viewer", scope_tag="prod",
            tag_tiers={"prod": "viewer"},
        )
        denied = scope_write_denied(self._Req(ctx), db, host_id=host_and_cert)
        assert denied is not None
        assert "read-only" in denied

    def test_out_of_scope_still_denied(self, db, host_and_cert):
        from cert_watch.routes._scoped import scope_write_denied

        ctx = AuthContext.from_tier(
            "alice", tier="viewer", scope_tag="edge",
            tag_tiers={"edge": "operator"},
        )
        denied = scope_write_denied(self._Req(ctx), db, host_id=host_and_cert)
        assert denied is not None
        assert "outside your team scope" in denied
