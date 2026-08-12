"""Role-Based Access Control for cert-watch (Plan 035).

When no role map is configured, all authenticated users get full access
(backward compat).  When CERT_WATCH_ROLE_MAP (JSON) is set, users
are mapped to roles (admin / operator / viewer) based on IdP groups/roles,
and permissions are derived from the ROLE_PERMISSIONS table.

The central concept is the ``AuthContext`` — a per-request object that
carries the resolved roles and permissions for the current user.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cert_watch.database.users_roles import SqliteRoleRepository


# Valid RBAC tiers.  The team-role name is now decoupled from the permission
# set; every role resolves to one of these tiers.
PERMISSION_TIERS = frozenset({"admin", "operator", "viewer"})

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

class Permission(StrEnum):
    """Fine-grained permission tokens."""

    CERT_READ = "cert:read"
    CERT_WRITE = "cert:write"
    SETTINGS_ADMIN = "settings:admin"


# ---------------------------------------------------------------------------
# Roles and their permission sets
# ---------------------------------------------------------------------------

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    ROLE_ADMIN: frozenset(Permission),
    ROLE_OPERATOR: frozenset({Permission.CERT_READ, Permission.CERT_WRITE}),
    ROLE_VIEWER: frozenset({Permission.CERT_READ}),
}


def permissions_for_tier(tier: str) -> frozenset[Permission]:
    """Return the permission set for a permission tier (admin/operator/viewer)."""
    return ROLE_PERMISSIONS.get(tier, ROLE_PERMISSIONS[ROLE_VIEWER])


def permissions_for_roles(role_names: list[str]) -> frozenset[Permission]:
    """Return the union of permissions for legacy role names.

    Kept for backward compatibility with code that still resolves by name
    (e.g. API-key scope mapping). New code should prefer
    :func:`permissions_for_tier`.
    """
    result: set[Permission] = set()
    for name in role_names:
        result |= ROLE_PERMISSIONS.get(name, frozenset())
    return frozenset(result)


# ---------------------------------------------------------------------------
# Role resolution: IdP groups/roles → cert-watch roles
# ---------------------------------------------------------------------------

def resolve_roles(
    user_groups: list[str],
    user_roles: list[str],
    role_map: dict[str, dict[str, Any]],
    username: str = "",
) -> list[str]:
    """Map IdP groups/roles to cert-watch role names.

    *role_map* maps ``{role_name: {"groups": [...], "roles": [...], "users": [...]}``.
    A user receives the union of all matching roles — by group membership, IdP
    role, or by being named individually in ``users`` (matched case-insensitively
    against *username*, which lets an IdP user with no suitable group be mapped
    directly).  Falls back to ``["viewer"]`` if nothing matches.
    """
    if not role_map:
        return [ROLE_ADMIN]  # no map → full access (backward compat)

    uname = username.casefold()
    matched: set[str] = set()
    for role_name, mapping in role_map.items():
        allowed_groups = mapping.get("groups", [])
        allowed_roles = mapping.get("roles", [])
        allowed_users = mapping.get("users", [])
        group_match = any(g in user_groups for g in allowed_groups) if allowed_groups else False
        role_match = any(r in user_roles for r in allowed_roles) if allowed_roles else False
        user_match = (
            any(u.casefold() == uname for u in allowed_users)
            if (allowed_users and uname)
            else False
        )
        if group_match or role_match or user_match:
            matched.add(role_name)

    return list(matched) if matched else [ROLE_VIEWER]


def claims_for_session(
    user_groups: list[str] | None,
    user_roles: list[str] | None,
    role_map: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Reduce IdP claims to only those the role map references, for the cookie.

    The session cookie carries the user's groups/roles so RBAC can resolve roles
    on every request (BC-145). But an AD user's full ``memberOf`` list can be
    dozens of long DNs — easily enough to push the ``cw_auth`` cookie past the
    browser's ~4 KB per-cookie limit, at which point the browser silently drops
    the cookie and the user is stuck in a post-login redirect loop.

    Only the groups/roles named in *role_map* ever affect resolution (see
    :func:`resolve_roles`), so storing just those is **behaviour-preserving**
    while keeping the cookie small. With no role map configured, no claims are
    stored at all (the full-access path needs none).
    """
    if not role_map:
        return [], []
    relevant_groups: set[str] = set()
    relevant_roles: set[str] = set()
    for mapping in role_map.values():
        relevant_groups.update(mapping.get("groups", []))
        relevant_roles.update(mapping.get("roles", []))
    groups = [g for g in (user_groups or []) if g in relevant_groups]
    roles = [r for r in (user_roles or []) if r in relevant_roles]
    return groups, roles


# ---------------------------------------------------------------------------
# AuthContext
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    """Per-request authorization context.

    Carries the resolved roles, the effective permission tier, and the
    derived permission set. Stored on ``request.state.auth_context`` by the
    middleware. When a user's role has a *scope_tag*, list access is limited
    to hosts/certificates whose effective tags include that tag (WI-051).
    """

    username: str
    roles: list[str] = field(default_factory=list)
    permissions: frozenset[Permission] = frozenset()
    tier: str = ""
    scope_tag: str = ""
    email: str = ""
    # Per-tag permission tiers (Plan 053 / WI-064): {tag: tier}. A scoped
    # role contributes its tier *for its tags* here instead of raising the
    # global tier — so "operator for prod, viewer for edge" is expressible.
    tag_tiers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_roles(cls, username: str, roles: list[str]) -> AuthContext:
        perms = permissions_for_roles(roles)
        tier = roles[0] if roles else ""
        return cls(username=username, roles=roles, permissions=perms, tier=tier)

    @classmethod
    def from_tier(
        cls,
        username: str,
        tier: str,
        roles: list[str] | None = None,
        scope_tag: str = "",
        email: str = "",
        tag_tiers: dict[str, str] | None = None,
    ) -> AuthContext:
        """Build a context from the explicit permission tier (WI-050)."""
        tier = tier if tier in PERMISSION_TIERS else ROLE_VIEWER
        return cls(
            username=username,
            roles=roles or [tier],
            permissions=permissions_for_tier(tier),
            tier=tier,
            scope_tag=scope_tag,
            email=email,
            tag_tiers=dict(tag_tiers or {}),
        )

    @classmethod
    def full_access(cls, username: str) -> AuthContext:
        """No role map configured → grant all permissions."""
        return cls(
            username=username,
            roles=[ROLE_ADMIN],
            permissions=frozenset(Permission),
            tier=ROLE_ADMIN,
        )

    def has_permission(self, perm: Permission) -> bool:
        return perm in self.permissions

    def may_write(self) -> bool:
        return Permission.CERT_WRITE in self.permissions

    def may_write_any(self) -> bool:
        """True if the user can write *somewhere* — globally, or on at
        least one tag (Plan 053). Gate-level check; the per-resource
        decision is :meth:`may_write_tags` at the scope seam."""
        if self.may_write():
            return True
        order = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}
        return any(order.get(t, 0) >= 1 for t in self.tag_tiers.values())

    def may_write_tags(
        self, resource_tags: set[str] | frozenset[str] | tuple[str, ...] | list[str]
    ) -> bool:
        """Per-resource write check (Plan 053, decision D2).

        True when the global tier already grants writes, or when ANY of the
        resource's effective tags carries a per-tag tier >= operator
        (max-over-intersecting-tags — aligns write capability with the
        union-based visibility model).
        """
        if self.may_write():
            return True
        order = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}
        return any(
            order.get(self.tag_tiers.get(t, ROLE_VIEWER), 0) >= 1
            for t in resource_tags
        )

    @property
    def is_admin(self) -> bool:
        return Permission.SETTINGS_ADMIN in self.permissions


# ---------------------------------------------------------------------------
# Role map parsing and context builder
# ---------------------------------------------------------------------------


def _role_tiers_from_map(
    role_map: dict[str, dict[str, Any]],
    role_repo: SqliteRoleRepository | None,
) -> dict[str, tuple[str, str, dict[str, str]]]:
    """Return {role_name: (permission_tier, scope_tag, tag_tier_overrides)}.

    Falls back to the legacy name-based tier when no Role row exists, so
    configurations that pre-date WI-050 keep working. The third element is
    the role's per-tag tier overrides from ``role_tag_tiers`` (Plan 053);
    an empty dict means every scope tag inherits ``permission_tier``.
    """
    result: dict[str, tuple[str, str, dict[str, str]]] = {}
    db_roles: dict[str, tuple[str, str, dict[str, str]]] = {}
    if role_repo is not None:
        try:
            overrides = role_repo.all_tag_tiers()
            for role in role_repo.list_all():
                db_roles[role.name] = (
                    role.permission_tier,
                    role.scope_tag,
                    overrides.get(role.id, {}),
                )
        except (OSError, sqlite3.Error):
            pass
    for role_name in role_map:
        if role_name in db_roles:
            result[role_name] = db_roles[role_name]
        elif role_name in ROLE_PERMISSIONS:
            result[role_name] = (role_name, "", {})
    return result


def _resolve_tier_and_scope(
    resolved_role_names: list[str],
    role_tiers: dict[str, tuple[str, str, dict[str, str]]],
) -> tuple[str, str, dict[str, str]]:
    """Pick the effective tier, union scope tags, and per-tag tiers.

    Tier decoupling (WI-061): a role with a non-empty ``scope_tag`` is
    *scoped* — it contributes its tags to visibility and alert routing,
    NEVER to the effective GLOBAL permission tier.  The effective tier is
    the highest tier among the user's UNSCOPED (global) roles.  A user
    holding ONLY scoped roles defaults to ``viewer`` (least privilege).

    Per-tag tiers (Plan 053 / WI-064): a scoped role's tier now applies
    *within its tags*. For each of the role's scope tags, the tag's tier is
    the role's ``role_tag_tiers`` override for that tag if present, else the
    role's default ``permission_tier``. Across roles, each tag takes the
    max tier any role grants it.

    Scope tags from ALL roles (scoped + unscoped) are unioned into the
    effective scope.  An empty scope string means full visibility (no
    filtering) — the existing contract.
    """
    from cert_watch.tags import format_tags, parse_tags

    order = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}
    chosen_tier = ROLE_VIEWER
    scope_tags: set[str] = set()
    tag_tiers: dict[str, str] = {}
    for name in resolved_role_names:
        tier, scope, overrides = role_tiers.get(name, (ROLE_VIEWER, "", {}))
        role_scope_tags = parse_tags(scope)
        # Union ALL roles' tags (scoped + unscoped) for visibility/alerts.
        scope_tags.update(role_scope_tags)
        if scope:
            # Scoped role: its tier applies per-tag, never globally. Every
            # scope tag gets an explicit entry (viewer included) so the UI
            # can show the full per-tag picture.
            for tag in role_scope_tags:
                tag_tier = overrides.get(tag, tier)
                if tag not in tag_tiers or order.get(tag_tier, 0) > order.get(
                    tag_tiers[tag], 0
                ):
                    tag_tiers[tag] = tag_tier
        # Only unscoped roles (empty scope_tag) contribute to the tier.
        elif order.get(tier, 0) > order.get(chosen_tier, 0):
            chosen_tier = tier
    return chosen_tier, format_tags(scope_tags), tag_tiers


def build_auth_context(
    username: str,
    user_groups: list[str],
    user_roles: list[str],
    role_map: dict[str, dict[str, Any]],
    role_repo: SqliteRoleRepository | None = None,
) -> AuthContext:
    """Build an AuthContext by resolving IdP groups/roles to cert-watch roles.

    If *role_map* is empty, returns a full-access context (backward compat).

    When *role_repo* is supplied, the permission tier and scope tag are read
    from the Role row (WI-050). Otherwise the legacy role-name → permission
    mapping is used.
    """
    if not role_map:
        return AuthContext.full_access(username)

    resolved = resolve_roles(user_groups, user_roles, role_map, username=username)
    role_tiers = _role_tiers_from_map(role_map, role_repo)
    tier, scope, tag_tiers = _resolve_tier_and_scope(resolved, role_tiers)
    return AuthContext.from_tier(
        username=username,
        tier=tier,
        roles=resolved,
        scope_tag=scope,
        tag_tiers=tag_tiers,
    )
