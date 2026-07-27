# Plan 053 — RBAC v2: Per-Tag-Scoped Permission Tiers (WI-064)

**Status:** proposed 2026-07-26
**Author:** glm-5.2 (research-driven; cross-lineage review required before execution)
**Strategic role:** the **1.0 vehicle**. This is the only parked item with a
strong, evidence-backed case for un-parking — closing WI-135/WI-136 confirmed
the architectural seam (see §1). Targets the `1.0` milestone referenced in
WI-064 and positioning.md.

---

## 1. Why now — the seam WI-135/136 exposed

Today's permission model is **host-centric via tags but globally tiered**: a
user has one effective `permission_tier` (`admin`/`operator`/`viewer`) computed
across all their roles, plus a *union* of scope tags. Write/read checks are
tag-aware for *visibility* (`build_scope_tag_clause`) but tag-blind for *tier*:
`require_write` consults `auth_ctx.may_write()` — a single global permission set.

WI-135 (events without hostname) and WI-136 (uploaded certs without hosts)
were patched by extending the tag-clause helpers to cover host-less entities.
That fixed visibility but **left the tier global** — an operator-for-tag-A is
operator everywhere they can see, including tag B. The patches confirmed the
right 1.0 fix is not more scope-filter patching but **per-tag tiering**: tier
becomes a function of the resource's tag.

Quoting WI-064 itself: v1 (WI-061 tier decoupling) "removes the
privilege-elevation footgun, which is the security-critical part; per-tag
tiering is a correctness/least-privilege refinement."

## 2. Goals / non-goals

**Goals**
- A user may be `operator` for tag A and `viewer` for tag B.
- Write-path authorization consults the tier scoped to the *target resource's*
  effective tags, not a global scalar.
- Tag-agnostic actions (settings admin, role/user management, API-key admin)
  still gate on a global tier derived **only from unscoped roles** (WI-061
  invariant preserved).
- No regression to the scope-filter SQL shape (`build_scope_tag_clause`) or the
  tier-decoupling contract (`test_rbac_tier_decoupling.py`).

**Non-goals**
- Attribute-based access control (ABAC) beyond tags.
- Row-level security at the DB layer (stays application-enforced).
- A JSON role-management API (form-POST stays; `/api/settings/roles` is a
  separate, opt-in slice if a 1.0 wants it — not required for per-tag tiers).
- Changing the tags data model (still comma-separated TEXT on hosts/certs).

## 3. Design decisions (require human sign-off)

These are surfaced per AGENTS.md ("anything touching auth/session/CSRF defaults
or other security posture"). Each has a recommendation; the human decides.

### D1 — Schema for per-tag tiers
- **Option A (recommended): child table `role_tag_tiers`.**
  `role_tag_tiers(role_id TEXT, tag TEXT, permission_tier TEXT, PRIMARY KEY(role_id, tag))`,
  FK `role_id → roles(id) ON DELETE CASCADE`. A role's tier for a tag is the
  matching row; absence = inherit the role's default `permission_tier` (kept on
  `roles` as the fallback / unscoped-tier source). Normalized, queryable,
  consistent with the repo pattern.
- **Option B: JSON column.** Replace `roles.permission_tier` with a JSON map
  `{"*": "viewer", "platform": "operator"}`. Compact; harder to query/index;
  SQLite JSON1 is available but the project avoids JSON-in-columns where a join
  is cheap.
- **Recommendation: A.** Migration `0029_role_tag_tiers`.

### D2 — Multi-tag resource semantics
A resource can carry several tags (cert effective tags = own ∪ host's). When a
user's per-tag tiers differ across the resource's tags, the effective tier is:
- **max over intersecting tag-tiers** (a cert with {A, B}, user operator-for-A /
  viewer-for-B → operator). Least-surprising for operators; "can edit if any of
  my roles grants edit on any of this resource's tags."
- Document and test both the all-viewer (no edit) and mixed (edit) cases.

### D3 — Local-user multi-role
IdP users already resolve to multiple roles via `CERT_WATCH_ROLE_MAP`. Local
users have a single `users.role_id` FK, so they can't *compose* per-tag tiers.
- **Option A (recommended): add `user_roles` M2M** (`user_roles(user_id, role_id)`,
  migration `0030`). Keep `users.role_id` as a deprecated single-role fallback
  (read at login, mirrored into `user_roles` on first login for back-compat).
  Lets a local admin assign "platform-operator" + "edge-viewer" to one user.
- **Option B: one role per local user, but roles carry multi-tag tiers (D1).**
  Simpler (no M2M) but a local user's composition is bounded by one role's rows.
- **Recommendation: A**, but **defer M2M to a later 1.0 slice** if the human
  wants the smallest safe landing — D1 alone already delivers per-tag tiers
  within a single (multi-tag) role, which covers the IdP-driven majority.

### D4 — AuthContext shape
Replace the single `tier: str` + `scope_tag: str` with:
```python
@dataclass
class AuthContext:
    username: str
    tier: str                       # global tier (tag-agnostic actions); unscoped roles only
    tag_tiers: dict[str, str]       # tag → tier (empty = tier applies to all visible)
    permissions: frozenset[Permission]   # derived from `tier` (global, unchanged semantics)
    email: str = ""
```
`may_write()` stays (global, for tag-agnostic actions). **New:**
`may_write_tags(resource_tags: collection[str]) -> bool` — returns True if any
intersecting tag's tier ≥ operator, OR (back-compat) if `tag_tiers` is empty and
the global tier ≥ operator.

### D5 — Write-path enforcement point
`routes/_scoped.py:scope_write_denied` already fetches the target's effective
tags. **The seam exists** — extend it to consult `may_write_tags(...)` instead
of the global `may_write()`. `require_write` (tag-agnostic mutations like
settings) keeps the global check. No new route-level seam needed.

## 4. Phased work breakdown

### Phase 1 — Schema + model (no behavior change)
- P1.1 Migration `0029_role_tag_tiers` (D1). Backfill: no rows; all roles
  inherit existing `permission_tier` (unchanged behavior).
- P1.2 `Role` / `SqliteRoleRepository` read/write `tag_tiers` (add
  `list_tag_tiers(role_id)`, `set_tag_tiers(role_id, {tag: tier})`).
- P1.3 `build_auth_context` populates `AuthContext.tag_tiers` from the user's
  roles' rows; `tier` (global) still from unscoped roles only.
- **Verify:** suite green, no behavior change (tag_tiers empty everywhere).

### Phase 2 — Per-tag write enforcement (the behavior change)
- P2.1 `AuthContext.may_write_tags(resource_tags)`.
- P2.2 `routes/_scoped.py:scope_write_denied` / `scope_read_denied` use it.
- P2.3 New tests: mixed-tier user (operator-for-A, viewer-for-B) can edit a
  tag-A cert, cannot edit a tag-B-only cert; viewer-everywhere can't edit.
- **Verify:** `test_rbac_tier_decoupling.py` still passes; new tests fail
  without P2.2 (break-the-code ritual).

### Phase 3 — Management surface
- P3.1 Role form (`templates/settings.html`) gains a repeatable
  `(tag, tier)` row editor posting to the existing `POST /settings/roles`.
- P3.2 `_normalize_*` helpers + CSRF + audit logging (consistent with today).
- P3.3 (Optional, D3-A) `user_roles` M2M + multi-select on the user form.
- **Verify:** e2e `test_settings_post.py` extended; role-tiers CRUD covered.

### Phase 4 — Docs + close
- P4.1 AGENTS.md RBAC section updated (D4/D5 semantics).
- P4.2 README "permissions" blurb; UPGRADING note (1.0 migration).
- P4.3 Close WI-064 via cross-lineage review.

## 5. Test strategy (what must not regress)

| Suite | Guards |
|---|---|
| `test_rbac_tier_decoupling.py` | WI-061 invariant — global tier from unscoped roles only |
| `test_tag_scoped_access.py` | scope-filter SQL shape; multi-tag scope = union; bulk ops honor scope |
| `test_wi128_api_scope_filtering.py` | every fleet query enforces scope_tags |
| `test_role_tiers.py` | role CRUD + tier/scope round-trips |
| `test_role_alert_routing.py` | `scope_tag` feeds recipient resolver (must keep working) |
| `test_middleware_deps.py` | `require_write`/`require_admin` behavior |
| new `test_rbac_per_tag_tiers.py` | the mixed-tier matrix (P2.3) |

**Break-the-code ritual:** for P2.1/P2.2, revert the enforcement line and
confirm `test_rbac_per_tag_tiers.py` catches it before merging.

## 6. Risks

- **Privilege escalation via the max-over-tags rule (D2).** If a user holds
  operator on any tag attached to a resource, they can edit it. Mitigation:
  tag hygiene (operators must not over-tag); document; the orphan-notice flow
  (Plan 050) already surfaces over-broad routing.
- **Silent global-tier elevation.** Any per-tag model must keep the WI-061
  invariant: scoped roles never raise the global tier. Covered by
  `test_rbac_tier_decoupling.py` — keep it red-green.
- **Back-compat for existing single-role installs.** Empty `role_tag_tiers` +
  existing `permission_tier` must reproduce today's behavior exactly (Phase 1
  is a no-op by construction).
- **Session token contents.** `AuthContext` is rebuilt per request from the DB
  (roles resolved live), so tier changes take effect on the next request — no
  token-minting change needed. Confirm no path caches `tier` beyond the request.

## 7. Decision register (human inputs needed before Phase 2)

1. D1 schema (child table vs JSON) — recommend child table.
2. D2 multi-tag semantics (max-over-intersecting) — recommend max.
3. D3 local-user M2M now or defer — recommend defer (ship D1 first).
4. Is a JSON `/api/settings/roles` in scope for 1.0, or form-POST only?
