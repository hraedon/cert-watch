# RBAC / Tagging / Scoping architecture report (exploration, 2026-08-12)

Produced by a read-only exploration pass for the 2026-08 UI redesign.
Note: `security.py` is session-key/CSRF material only; the authorization core
is `src/cert_watch/auth/rbac.py`.

## 1. Data model

There is **no `teams` table**. A "team" is a row in `roles`.

| Table | Defined at | Key columns |
|---|---|---|
| `roles` | `migrations/m0019_users_roles.py:16` + `m0024_role_tiers` + `m0026_role_alert_group_link` | `id`, `name` (UNIQUE), `email`, `description`, `permission_tier` (default `viewer`), `scope_tag` (CSV string), `alert_group_id` |
| `users` | `m0019_users_roles.py:28` | `id`, `username` (UNIQUE), `email`, `password_hash`, `role_id` FK — single-valued |
| `api_keys` | `database/schema.py:129` | `key_hash`, `name`, `scope` (read/write/admin), `revoked`. **No tag column.** |
| `hosts` | `database/schema.py:65` | `tags` CSV, `owner_email`, `owner_name`, `owner_slack` |
| `certificates` | `database/schema.py:19` | `tags` CSV |
| `alert_groups` | `schema.py:139` + `m0025` | `name`, `recipients`, `webhook_url`, `match_tags` CSV, `threshold_days` |
| `alert_group_certs` | `schema.py:148` | manual cert↔group M2M |
| `session_versions` | `schema.py:170` | per-username session invalidation counter |

One `roles` row carries four distinct things: (1) `permission_tier` → RBAC
tier; (2) `scope_tag` → tag-based visibility ACL (`routes/_scoped.py`);
(3) `email` → matched against `hosts.owner_email` (`database/team.py:14`,
`alerts.py:327`); (4) `alert_group_id` → alert routing (`alerts.py:930`).
`roles.name` is also the IdP role-map join key (`rbac.py:232`).

Identity: three providers (`auth/factory.py`) converge on `AuthContext`
(`rbac.py:147`) via `build_auth_context` (`rbac.py:271`) from role_map +
session `groups`/`roles` claims. **`users.role_id` is never read at request
time**; at login `local_admin.py:131-142` stuffs the role *name* into the
session claims, which then flow through role-map matching like IdP claims.

## 2. Authorization layers

1. **Global gate** `middleware.py:615` (`auth_middleware`) — session cookie →
   `request.state.auth_context` (`:655`), API-key bearer fallback (`:663`).
2. **Route deps** `middleware.py:937-1030` — API-style (HTTPException):
   `require_auth:937`, `require_write:945`, `require_admin:959`,
   `require_admin_write:969`; form-style (RedirectResponse):
   `require_write_form:1000`, `require_admin_form:983`,
   `require_admin_write_form:1013`. All funnel to `_check_auth:896` →
   `_write_denied:793` / `_admin_allowed:830`.
3. **Tag scoping** `routes/_scoped.py`, applied *manually per handler*:
   `scope_tags_from_auth:11` (returns `()` for admins/unscoped),
   `scope_write_denied:68`, `scope_read_denied:95`, `enforce_scope_tag:123`,
   `scope_new_tags_denied:150`, `tags_with_scope:29`. SQL via
   `_add_effective_tag_filter` (`database/dashboard_helpers.py:25`) and
   `build_scope_tag_clause:67` — LIKE `,tag,` match over cert∪host tags.

**Tier resolution** `rbac.py:240` (`_resolve_tier_and_scope`) — WI-061:
tier = max over roles WHERE scope_tag=='' (scoped roles contribute NOTHING
to tier); scope = union over ALL roles' scope_tags. Only-scoped-roles user →
viewer (`rbac.py:259`). `is_admin` is a permission check (SETTINGS_ADMIN),
`rbac.py:206`.

## 3. Tags: labels AND ACLs (the central overload)

`tags.py` is a 60-line string utility (parse/format/merge/match); storage is
CSV TEXT on hosts + certificates; effective tags = cert ∪ host (`tags.py:41`).
Four consumers of one namespace: org labels; alert-group `match_tags`
(`alerts.py:948`); role `scope_tag` ACLs (`_scoped.py`); compliance report
scope param (`compliance.py:214`).

Tag creation/assignment: anyone with `cert:write` — `routes/hosts.py:401`,
`routes/certificates.py:493`, `routes/api/hosts.py:246`,
`routes/api/certificates.py:234`. **No registry / vocabulary / reserved-tag
concept.** Scoped users limited by `scope_new_tags_denied` (`_scoped.py:150`);
an unscoped operator can apply ANY string including another role's scope_tag —
tag assignment is a write op whose *effect* is an access grant.

## 4. /team

`routes/team.py:25` (require_auth only): local `users` table lookup →
`role.email` non-empty gate (`:40`) → `team_dashboard_data` filters purely on
`LOWER(h.owner_email)=LOWER(?)` (`database/team.py:14,28,42`).
- Never touches scope_tag or permission_tier.
- **Local users only** — IdP users have no `users` row → permanent "No team
  assigned" (`team_dashboard.html:54`) with unactionable advice.
- So there are two disjoint team-membership definitions: scope_tag↔tags
  (everywhere else) and roles.email↔hosts.owner_email (here + alert fanout
  `alerts.py:327-351`).

## 5. Tangles (by severity)

- **C1 — `users.role_id` grants nothing.** role_map empty →
  `rbac.py:286-287` full access for ALL local users (roles UI inert);
  role_map set → resolution only via claim matching, else viewer
  (`rbac.py:109`). Users-tab role assignment has no permission effect on
  either path. `tests/test_rbac.py:95` encodes no-map=full-access as intended
  back-compat — tension with the Plan-040 local-user feature.
- **C2 — three "team" mechanisms on one row**; alert routing uses BOTH
  tag-matching (`alerts.py:930,962`) and email-matching (`alerts.py:343-347`)
  simultaneously.
- **C3 — scoped roles can't carry privilege** (`rbac.py:266`): "operator for
  prod" inexpressible; settings form still offers the ignored tier selector
  (warns in prose `settings.html:666,686`). Plan 053 fixes exactly this.
- **C4 — admin disables scoping** (`_scoped.py:19,81,109,134,161` short-circuit
  on is_admin): privilege level and scope boundary conflated.
- **C5 — scoping opt-in per handler; opted-out routes**: `routes/audit.py:22`
  (full audit log for any authenticated user), `routes/scan_history.py:27`
  (fleet-wide, no route dep at all), team, metrics, health, api/policy,
  api/keys.
- **C6 — API keys: tier but no scope** (`middleware.py:607-608` no scope_tag
  arg) → every key sees the whole fleet.
- **C7 — two admin sources of truth**: form deps honor legacy
  `settings.admin_users` (`:844-846`, `admin_legacy=True` at `:988,:1016`);
  API deps don't.
- **C8 — three authz regimes** selected in `_write_denied:793`: API-key /
  role_map RBAC / legacy write_users+admin_users, plus no-auth bypass
  (`_check_auth:904-906`).
- **C9 — compliance scope bug**: `compliance.py:214-226` filters only
  `c.tags`, not effective tags — scoped reports silently omit host-tagged
  certs. Genuine bug.
- **C10 — `enforce_scope_tag` dual meaning**: mandatory constraint for scoped
  users, optional filter for unscoped (`_scoped.py:137-138`); used by
  `insights.py:174`, `api/reports.py:204,228`.
- **C11 — scope_tag CSV round-trip**: `rbac.py:268` serializes, `_scoped.py`
  re-parses in 5 places. Should be `tuple[str,...]`.
- **C12 — scope invisible in UI**: `middleware.py:456-457` exports
  `scope_tag`/`permission_tier` to every template; rendered nowhere.
- **C13 — local users one role, IdP users many** (`users_roles.py:32` vs
  `rbac.py:106-109`). Plan 053 D3 defers.
- **C14 — dead surface**: `AuthContext.from_roles` (`rbac.py:164`) no callers;
  tier names and role names share a namespace (`rbac.py:235`).
- **C15 — cookie-size trimming** (`auth/session.py:198-222`) can silently drop
  groups/roles claims → permission downgrade without error (mitigated by
  `claims_for_session`, `rbac.py:112`).

## 6. UI surfaces

| Surface | Route | Guard |
|---|---|---|
| Roles tab | `settings/roles.py:47,64,94,129` → `settings.html:663-800` | require_admin_form |
| Users tab | `settings/roles.py:152,170,209,258` → `settings.html:801-890` | require_admin_form |
| API keys | `settings/api_keys.py:27,37,72` | require_admin_form |
| Alert groups | `settings/alert_groups.py:99,122,206,240,279` → `settings.html:442-571` | require_admin_form |
| Auth/IdP | `settings/auth.py:45` → `settings.html:31-243` | require_admin_form |
| IdP role map | `POST /settings/ldap-role-map` → nested subform `settings.html:770-795` | — |
| Team | `team.py:25` | require_auth |
| Tag editing | host/cert detail inline only | require_write_form |

**No tag-management surface** — no list of tags in use, no rename, no "which
roles scope to this tag" (renaming silently revokes access). Role form
collects 6 fields spanning 4 concerns (C2 as a form). Admin workflow requires
two different identity-binding paths (IdP subform vs Users tab) and a
tag-independent owner_email step for /team, with no UI connecting them.
Session invalidation on role/user mutation is handled correctly
(`settings/roles.py:124-125,142-143,254` bump_session_version).

## 7. Rationalization framing

One row (`roles`) carries four orthogonal concepts; one namespace (tags)
carries two. Three separable decisions: (1) split or honestly present the
roles union (C2/C3); (2) decide whether tags are ACLs — if yes they need a
registry + protected tags + write-authz on assignment; if no, scoping needs
its own binding (C5/C6); (3) fix or delete the local-user role path (C1).
Plan 053 (approved §7) is the starting substrate for the per-tag tier piece.
