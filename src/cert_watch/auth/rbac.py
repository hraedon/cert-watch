"""Role-Based Access Control for cert-watch (Plan 035).

When no role map is configured, all authenticated *directory* (LDAP/OAuth)
users get full access (backward compat).  When a role map is set (the
CERT_WATCH_ROLE_MAP JSON merged with the Settings → Roles mapping), directory
users are mapped to roles (admin / operator / viewer) based on IdP
groups/roles, and permissions are derived from the ROLE_PERMISSIONS table.

Local accounts never depend on the role map: a session minted by the users
table resolves from that user's assigned role on every request (no role, or a
deleted role, means viewer), and the break-glass admin is always admin. Which
of the three a session is travels as a reserved claim that IdP claims can
never carry (see :func:`claims_for_session`).

The central concept is the ``AuthContext`` — a per-request object that
carries the resolved roles and permissions for the current user.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

logger = logging.getLogger("cert_watch.auth.rbac")

if TYPE_CHECKING:
    from cert_watch.database.users_roles import SqliteRoleRepository, SqliteUserRepository


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
_TIER_ORDER = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}

# Reserved session claims (stored in the session's roles list) naming how the
# session was minted. The "cw:" prefix is stripped from IdP claims before they
# reach the cookie, so only the login route can set them.
RESERVED_CLAIM_PREFIX = "cw:"
LOCAL_USER_CLAIM = "cw:local-user"
BREAK_GLASS_CLAIM = "cw:break-glass"

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    ROLE_ADMIN: frozenset(Permission),
    ROLE_OPERATOR: frozenset({Permission.CERT_READ, Permission.CERT_WRITE}),
    ROLE_VIEWER: frozenset({Permission.CERT_READ}),
}


def _highest_tag_tiers(tag_tiers: dict[str, str]) -> dict[str, str]:
    """Case-fold tag keys and retain the highest tier for each logical tag."""
    folded: dict[str, str] = {}
    for tag, tier in tag_tiers.items():
        key = tag.casefold()
        if key not in folded or _TIER_ORDER.get(tier, 0) > _TIER_ORDER.get(
            folded[key], 0
        ):
            folded[key] = tier
    return folded


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
    # Reserved claims mark local sessions; an IdP must never be able to mint one.
    roles = [
        r for r in (user_roles or [])
        if r in relevant_roles and not r.startswith(RESERVED_CLAIM_PREFIX)
    ]
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
    # True for a users-table account: its role decides writes and admin even
    # with no role map, so the legacy write_users/admin_users lists (which
    # only apply to the no-role-map directory path) must not widen it.
    local_account: bool = False
    # Explicit marker for trusted request-less work (scheduler/CLI) and for
    # auth-disabled requests. Services reject a missing context, so privileged
    # internal work must be intentional rather than represented by ``None``.
    is_system: bool = False

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
        local_account: bool = False,
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
            local_account=local_account,
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

    @classmethod
    def system(cls) -> AuthContext:
        """Build the explicit unrestricted principal for trusted internal work."""
        return cls(
            username="system",
            roles=[ROLE_ADMIN],
            permissions=frozenset(Permission),
            tier=ROLE_ADMIN,
            is_system=True,
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
        return any(_TIER_ORDER.get(t, 0) >= 1 for t in self.tag_tiers.values())

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
        # Tags match case-insensitively, as everywhere else in scope (#69).
        folded = _highest_tag_tiers(self.tag_tiers)
        return any(
            _TIER_ORDER.get(folded.get(t.casefold(), ROLE_VIEWER), 0) >= 1
            for t in resource_tags
        )

    @property
    def is_admin(self) -> bool:
        return Permission.SETTINGS_ADMIN in self.permissions


# ---------------------------------------------------------------------------
# Role map parsing and context builder
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# The Settings → Roles IdP mapping (kv ``ldap_role_map``)
# ---------------------------------------------------------------------------

UI_ROLE_MAP_KV_KEY = "ldap_role_map"
# Sticky: set the first time a Settings → Roles mapping exists. From then on
# an empty map means "directory users are least-privileged", never the
# legacy "no role map = full access" (PR #78 re-verification, N-1).
UI_ROLE_MAP_CONFIGURED_KV_KEY = "ldap_role_map_configured"
# A role-map entry that matches nobody. Its presence makes the map non-empty,
# so every "role map configured?" check takes the RBAC path and an unmatched
# directory user resolves to viewer. Used when mapping is configured but no
# mapping is left, and when the role map cannot be read at startup.
RBAC_ENFORCED_KEY = "cw:rbac-enforced"


def _read_raw_ui_role_map_state(db_path: Any) -> tuple[dict[str, Any], bool]:
    """``(mapping, malformed)`` for the stored value. A value that exists but
    is not a JSON object reads as ``({}, True)``; a database error propagates,
    so a failed settings rebuild keeps the last good role map instead of
    silently emptying it (B-1)."""
    import json

    from cert_watch.database import kv_get

    raw = kv_get(db_path, UI_ROLE_MAP_KV_KEY)
    if raw is None or raw == "":
        return {}, False
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}, True
    return (data, False) if isinstance(data, dict) else ({}, True)


def _read_raw_ui_role_map(db_path: Any) -> dict[str, Any]:
    return _read_raw_ui_role_map_state(db_path)[0]


def load_ui_role_map(db_path: Any) -> dict[str, dict[str, list[str]]]:
    """Return the Settings → Roles mapping keyed by **role id**.

    Entries are stored by role id so a rename cannot orphan them and a delete
    removes them (PR #78 review, B1). Only keys that are the id of an existing
    role count: name keys are rewritten once by :func:`normalize_ui_role_map`
    and ignored afterwards, so a later role that happens to reuse a name
    never adopts a stale entry (N-2). Database errors propagate.
    """
    from cert_watch.database.users_roles import SqliteRoleRepository

    data = _read_raw_ui_role_map(db_path)
    if not data:
        return {}
    role_ids = {r.id for r in SqliteRoleRepository(db_path).list_all()}
    return {
        key: _clean_mapping(mapping)
        for key, mapping in data.items()
        if key in role_ids and isinstance(mapping, dict)
    }


def _clean_mapping(mapping: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "groups": [str(g) for g in mapping.get("groups", []) if g],
        "users": [str(u) for u in mapping.get("users", []) if u],
    }


def normalize_ui_role_map(db_path: Any) -> None:
    """One-time rewrite of the stored mapping to role-id keys.

    A name key (as written by earlier releases) is rewritten to the id of the
    role that has that name now; entries that resolve to no role are dropped.
    A non-empty stored map also sets the sticky "configured" flag. Writes
    only when something changes, so it is cheap to call on every load.
    """
    import json

    from cert_watch.database import get_write_lock, kv_get, kv_set
    from cert_watch.database.users_roles import SqliteRoleRepository

    with get_write_lock():
        data, malformed = _read_raw_ui_role_map_state(db_path)
        if malformed:
            # Someone configured a mapping we cannot read: fail closed (the
            # sticky flag makes the empty map least privilege), keep the value.
            logger.error(
                "stored %s is not a JSON object; directory users are treated "
                "as unmapped (read-only) until it is re-saved", UI_ROLE_MAP_KV_KEY,
            )
            if kv_get(db_path, UI_ROLE_MAP_CONFIGURED_KV_KEY) != "1":
                kv_set(db_path, UI_ROLE_MAP_CONFIGURED_KV_KEY, "1")
            return
        if not data:
            return
        if kv_get(db_path, UI_ROLE_MAP_CONFIGURED_KV_KEY) != "1":
            kv_set(db_path, UI_ROLE_MAP_CONFIGURED_KV_KEY, "1")
        roles = SqliteRoleRepository(db_path).list_all()
        by_id = {r.id for r in roles}
        by_name = {r.name: r.id for r in roles}
        out: dict[str, dict[str, list[str]]] = {}
        for key, mapping in data.items():
            if not isinstance(mapping, dict):
                continue
            if key in by_id:
                out[key] = _clean_mapping(mapping)
            elif key in by_name and by_name[key] not in data:
                out.setdefault(by_name[key], _clean_mapping(mapping))
        if out != data:
            kv_set(db_path, UI_ROLE_MAP_KV_KEY, json.dumps(out))


def ui_role_map_configured(db_path: Any) -> bool:
    from cert_watch.database import kv_get

    return kv_get(db_path, UI_ROLE_MAP_CONFIGURED_KV_KEY) == "1"


def ui_role_map_by_name(db_path: Any) -> dict[str, dict[str, Any]]:
    """The UI mapping in role-map shape (keyed by current role name).

    Each entry carries its ``role_id`` so :func:`_role_tiers_from_map` reads
    the tier from that role and grants nothing if it has since been deleted,
    even while a cached ``Settings.role_map`` still lists it. Database errors
    propagate (B-1).
    """
    from cert_watch.database.users_roles import SqliteRoleRepository

    ui = load_ui_role_map(db_path)
    if not ui:
        return {}
    names = {r.id: r.name for r in SqliteRoleRepository(db_path).list_all()}
    return {
        names[rid]: {**mapping, "role_id": rid} for rid, mapping in ui.items() if rid in names
    }


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
    db_roles_by_id: dict[str, tuple[str, str, dict[str, str]]] = {}
    if role_repo is not None:
        try:
            overrides = role_repo.all_tag_tiers()
            for role in role_repo.list_all():
                db_roles[role.name] = db_roles_by_id[role.id] = (
                    role.permission_tier,
                    role.scope_tag,
                    overrides.get(role.id, {}),
                )
        except (OSError, sqlite3.Error):
            pass
    for role_name, mapping in role_map.items():
        role_id = mapping.get("role_id") if isinstance(mapping, dict) else None
        if role_id:
            # UI-sourced entry: bound to one role row. A deleted role grants
            # nothing -- no fall back to the built-in tier of the same name.
            if role_id in db_roles_by_id:
                result[role_name] = db_roles_by_id[role_id]
            continue
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

    chosen_tier = ROLE_VIEWER
    scope_tags: dict[str, str] = {}
    folded_tag_tiers: dict[str, str] = {}
    for name in resolved_role_names:
        tier, scope, overrides = role_tiers.get(name, (ROLE_VIEWER, "", {}))
        role_scope_tags = parse_tags(scope)
        # Union ALL roles' tags (scoped + unscoped) for visibility/alerts.
        for tag in role_scope_tags:
            scope_tags.setdefault(tag.casefold(), tag)
        if scope:
            # Scoped role: its tier applies per-tag, never globally. Every
            # scope tag gets an explicit entry (viewer included) so the UI
            # can show the full per-tag picture.
            folded_overrides = _highest_tag_tiers(overrides)
            for tag in role_scope_tags:
                key = tag.casefold()
                tag_tier = folded_overrides.get(key, tier)
                if key not in folded_tag_tiers or _TIER_ORDER.get(
                    tag_tier, 0
                ) > _TIER_ORDER.get(
                    folded_tag_tiers[key], 0
                ):
                    folded_tag_tiers[key] = tag_tier
        # Only unscoped roles (empty scope_tag) contribute to the tier.
        elif _TIER_ORDER.get(tier, 0) > _TIER_ORDER.get(chosen_tier, 0):
            chosen_tier = tier
    scope = format_tags(scope_tags.values())
    tag_tiers = {
        scope_tags[key]: tier for key, tier in folded_tag_tiers.items()
    }
    return chosen_tier, scope, tag_tiers


def _local_user_context(
    username: str,
    role_repo: SqliteRoleRepository | None,
    user_repo: SqliteUserRepository | None,
) -> AuthContext:
    """AuthContext for a users-table account, from its assigned role.

    The role is read on every request, so a role change or deletion applies
    to live sessions. No user row, no role, a dangling ``role_id`` or an
    unreadable database all resolve to viewer -- never to full access.
    """
    viewer = AuthContext.from_tier(username, tier=ROLE_VIEWER, local_account=True)
    if user_repo is None or role_repo is None:
        return viewer
    try:
        user = user_repo.get_by_username(username)
        role = role_repo.get(user.role_id) if user is not None and user.role_id else None
        if user is None or role is None:
            return viewer
        overrides = role_repo.list_tag_tiers(role.id)
    except (OSError, sqlite3.Error):
        return viewer
    tier, scope, tag_tiers = _resolve_tier_and_scope(
        [role.name], {role.name: (role.permission_tier, role.scope_tag, overrides)},
    )
    return AuthContext.from_tier(
        username, tier=tier, roles=[role.name], scope_tag=scope,
        email=user.email, tag_tiers=tag_tiers, local_account=True,
    )


def _legacy_list_context(
    username: str,
    write_users: tuple[str, ...] | list[str],
    admin_users: tuple[str, ...] | list[str],
) -> AuthContext:
    """A directory user's context with no role map: the documented legacy lists.

    ``CERT_WATCH_ADMINS``, when set, is the allowlist for admin (README: the
    usernames allowed to reach /settings); ``CERT_WATCH_WRITE_USERS``, when
    set, is the allowlist for writes, and listed admins always write. Admin
    implies write: with only ``CERT_WATCH_WRITE_USERS`` set, admin requires
    membership in it. With neither set, everyone is full access.
    Before this, the no-role-map path returned full access unconditionally,
    so ``CERT_WATCH_ADMINS`` restricted nothing and a user outside
    ``CERT_WATCH_WRITE_USERS`` could mint a write API key (plan 057 W6).
    """
    may_write = not write_users or username in write_users
    # Admin implies write: with CERT_WATCH_ADMINS unset, a user who may not
    # write data (outside a set CERT_WATCH_WRITE_USERS) never administers.
    is_admin = username in admin_users if admin_users else may_write
    if is_admin:
        return AuthContext.full_access(username)
    return AuthContext.from_tier(username, tier=ROLE_OPERATOR if may_write else ROLE_VIEWER)


def build_auth_context(
    username: str,
    user_groups: list[str],
    user_roles: list[str],
    role_map: dict[str, dict[str, Any]],
    role_repo: SqliteRoleRepository | None = None,
    user_repo: SqliteUserRepository | None = None,
    *,
    write_users: tuple[str, ...] | list[str] = (),
    admin_users: tuple[str, ...] | list[str] = (),
) -> AuthContext:
    """Build an AuthContext by resolving IdP groups/roles to cert-watch roles.

    Local sessions come first and ignore *role_map*: the break-glass admin is
    always admin, and a users-table account resolves from its assigned role
    (see :func:`_local_user_context`).

    For directory users: if *role_map* is empty, the legacy lists decide
    (:func:`_legacy_list_context`): with neither ``CERT_WATCH_ADMINS``
    (*admin_users*) nor ``CERT_WATCH_WRITE_USERS`` (*write_users*) set, a
    full-access context (backward compat). When *role_repo* is supplied, the permission tier and
    scope tag are read from the Role row (WI-050). Otherwise the legacy
    role-name → permission mapping is used.
    """
    if BREAK_GLASS_CLAIM in user_roles:
        return AuthContext.full_access(username)
    if LOCAL_USER_CLAIM in user_roles:
        return _local_user_context(username, role_repo, user_repo)
    if not role_map:
        return _legacy_list_context(username, write_users, admin_users)

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
