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
from typing import TYPE_CHECKING

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
    role_map: dict[str, dict],
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
    role_map: dict,
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

    @property
    def is_admin(self) -> bool:
        return Permission.SETTINGS_ADMIN in self.permissions


# ---------------------------------------------------------------------------
# Role map parsing and context builder
# ---------------------------------------------------------------------------


def _role_tiers_from_map(
    role_map: dict,
    role_repo: SqliteRoleRepository | None,
) -> dict[str, tuple[str, str]]:
    """Return {role_name: (permission_tier, scope_tag)} for mapped role names.

    Falls back to the legacy name-based tier when no Role row exists, so
    configurations that pre-date WI-050 keep working.
    """
    result: dict[str, tuple[str, str]] = {}
    db_roles: dict[str, tuple[str, str]] = {}
    if role_repo is not None:
        try:
            for role in role_repo.list_all():
                db_roles[role.name] = (role.permission_tier, role.scope_tag)
        except (OSError, sqlite3.Error):
            pass
    for role_name in role_map:
        if role_name in db_roles:
            result[role_name] = db_roles[role_name]
        elif role_name in ROLE_PERMISSIONS:
            result[role_name] = (role_name, "")
    return result


def _resolve_tier_and_scope(
    resolved_role_names: list[str],
    role_tiers: dict[str, tuple[str, str]],
) -> tuple[str, str]:
    """Pick the highest-privilege tier and union scope tags from resolved roles."""
    order = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}
    chosen_tier = ROLE_VIEWER
    scope_tags: set[str] = set()
    for name in resolved_role_names:
        tier, scope = role_tiers.get(name, (ROLE_VIEWER, ""))
        if order.get(tier, 0) > order.get(chosen_tier, 0):
            chosen_tier = tier
        if scope:
            scope_tags.add(scope)
    return chosen_tier, ",".join(sorted(scope_tags))


def build_auth_context(
    username: str,
    user_groups: list[str],
    user_roles: list[str],
    role_map: dict,
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
    tier, scope = _resolve_tier_and_scope(resolved, role_tiers)
    return AuthContext.from_tier(
        username=username,
        tier=tier,
        roles=resolved,
        scope_tag=scope,
    )
