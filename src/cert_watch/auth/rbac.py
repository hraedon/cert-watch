"""Role-Based Access Control for cert-watch (Plan 035).

When no role map is configured, all authenticated users get full access
(backward compat).  When CERT_WATCH_ROLE_MAP (JSON) is set, users
are mapped to roles (admin / operator / viewer) based on IdP groups/roles,
and permissions are derived from the ROLE_PERMISSIONS table.

The central concept is the ``AuthContext`` — a per-request object that
carries the resolved roles and permissions for the current user.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

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


def permissions_for_roles(role_names: list[str]) -> frozenset[Permission]:
    """Return the union of permissions for the given role names."""
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
) -> list[str]:
    """Map IdP groups/roles to cert-watch role names.

    *role_map* maps ``{role_name: {"groups": [...], "roles": [...]}``.
    A user receives the union of all matching roles.
    Falls back to ``["viewer"]`` if nothing matches.
    """
    if not role_map:
        return [ROLE_ADMIN]  # no map → full access (backward compat)

    matched: set[str] = set()
    for role_name, mapping in role_map.items():
        allowed_groups = mapping.get("groups", [])
        allowed_roles = mapping.get("roles", [])
        group_match = any(g in user_groups for g in allowed_groups) if allowed_groups else False
        role_match = any(r in user_roles for r in allowed_roles) if allowed_roles else False
        if group_match or role_match:
            matched.add(role_name)

    return list(matched) if matched else [ROLE_VIEWER]


# ---------------------------------------------------------------------------
# AuthContext
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    """Per-request authorization context.

    Carries the resolved roles and the derived permission set. Stored on
    ``request.state.auth_context`` by the middleware.
    """

    username: str
    roles: list[str] = field(default_factory=list)
    permissions: frozenset[Permission] = frozenset()

    @classmethod
    def from_roles(cls, username: str, roles: list[str]) -> AuthContext:
        perms = permissions_for_roles(roles)
        return cls(username=username, roles=roles, permissions=perms)

    @classmethod
    def full_access(cls, username: str) -> AuthContext:
        """No role map configured → grant all permissions."""
        return cls(username=username, roles=[ROLE_ADMIN], permissions=frozenset(Permission))

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


def build_auth_context(
    username: str,
    user_groups: list[str],
    user_roles: list[str],
    role_map: dict,
) -> AuthContext:
    """Build an AuthContext by resolving IdP groups/roles to cert-watch roles.

    If *role_map* is empty, returns a full-access context (backward compat).
    """
    if not role_map:
        return AuthContext.full_access(username)

    roles = resolve_roles(user_groups, user_roles, role_map)
    return AuthContext.from_roles(username, roles)
