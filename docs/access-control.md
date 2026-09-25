# Access control

This page explains who can sign in to cert-watch, what each person can do once
signed in, and how to narrow a person to part of the estate. It describes 1.0
behaviour. If you are upgrading from 0.9, read the access-control section of
[UPGRADING.md](../UPGRADING.md) first: several defaults became stricter.

## The three kinds of account

**The break-glass admin.** A single local account that is always an
administrator and works when your directory does not. It comes from one of
three places: `CERT_WATCH_LOCAL_ADMIN_USER` plus
`CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` (generate the hash with
`cert-watch hash-password`), the first-run setup wizard, or the password
cert-watch generates on first start when it is network-exposed with nothing
else configured (see [install.md](install.md#first-start)). Keep its password
somewhere you can reach during an outage, and don't use it day to day.

**Local accounts.** Created by an administrator under **Settings → Users**,
each with a password and an assigned role. A local account's role is the whole
story: it is re-read on every request, so changing or removing a role takes
effect immediately. An account with no role, or whose role has been deleted,
is a viewer. Directory settings such as `CERT_WATCH_ALLOWED_GROUPS` and the
legacy user lists below do not apply to local accounts.

**Directory accounts.** People who sign in through LDAP / Active Directory or
OAuth / OIDC (Entra ID, Google and other OIDC providers). cert-watch doesn't
store their passwords; it decides what they may do from their directory
groups, IdP roles or username, as described below.

## Permission tiers

| Tier | Can |
|------|-----|
| **viewer** | See everything in scope. No write controls are shown, and write requests are refused server-side. |
| **operator** | Everything a viewer can, plus add, scan, upload, edit and delete hosts and certificates, and manage tags, notes and ownership. |
| **admin** | Everything, including Settings, users, roles, API keys, trust anchors, alert groups and policy. Admin always implies write. |

Every state-changing request is checked on the server, and every request made
with a browser session must carry a valid CSRF token. Hiding a button is never
the protection.

## How directory users get a tier

cert-watch looks for a role mapping first. If there isn't one, it falls back
to two older username lists. If neither exists, every signed-in directory user
is an administrator; that default exists for compatibility and you should not
rely on it.

### 1. Role mapping (recommended)

A role mapping connects directory groups, IdP roles or usernames to
cert-watch roles. You can define it in two places, and they are merged:

- **Settings → Roles**, where each role lists the directory groups and
  usernames that receive it.
- `CERT_WATCH_ROLE_MAP`, a JSON object for configuration-as-code, which can
  also map OIDC roles:

  ```json
  {"operator": {"groups": ["CN=cert-ops,OU=Groups,DC=example,DC=com"]},
   "admin":    {"roles": ["cert-watch-admin"]}}
  ```

  For any role named in both places, the environment variable wins.

A user receives every role whose groups, roles or usernames match. Among
their unscoped roles, the most permissive tier applies. A scoped role's tier
applies only to its own tags (see scoping below). A user who matches nothing
is a viewer.

Once a mapping has been saved under **Settings → Roles**, cert-watch remembers
that role mapping is in use. A mapping that exists only in
`CERT_WATCH_ROLE_MAP` isn't remembered this way; removing it returns directory
users to the username lists below. Removing every mapping afterwards leaves directory users as
viewers; it doesn't return them to full access. The same applies if the
stored mapping becomes unreadable. Going back to the unmapped behaviour is
deliberately awkward. With cert-watch stopped, delete the `ldap_role_map` and
`ldap_role_map_configured` rows from the `kv_store` table.

Group membership is read when a user signs in and carried in their session.
So a change that depends on groups, whether in the directory or a new group
mapping in cert-watch, applies from the user's next sign-in. Changes to a
role's tier or scope, and username mappings, apply on the next request.

### 2. Username lists (older deployments)

With no role mapping at all, two comma-separated lists decide access:

| Setting | Effect |
|---------|--------|
| `CERT_WATCH_ADMINS` | Only these users are administrators. |
| `CERT_WATCH_WRITE_USERS` | Only these users (and the administrators) may change data; everyone else is read-only. If this is set and `CERT_WATCH_ADMINS` is not, administration is limited to these users too. |

If neither list is set, every signed-in directory user is an administrator.

### Who may sign in at all

Independently of tiers, you can refuse sign-in to directory users outside
particular groups: `CERT_WATCH_ALLOWED_GROUPS` (directory groups),
`CERT_WATCH_ALLOWED_ROLES` (OIDC roles) and, for LDAP, `LDAP_REQUIRED_GROUPS`
(checked transitively). These gates don't apply to local accounts or the
break-glass admin.

## Scoping people to part of the estate

A role can carry a **scope**: one or more tags. A non-administrator who holds
any scoped role sees and changes only hosts and certificates carrying one of
their scope tags, even if they also hold an unscoped role. A role can also grant a different tier on specific tags, for example
viewer everywhere in scope but operator on `payments`.

Scope applies to the inventory, certificate and host pages, alerts, scan
history, posture and readiness reports, compliance reports, exports and the
JSON API used by the browser session. The audit log is administrator-only and
therefore not scoped. The health endpoints (`/readyz`, `/api/health`) report
on the whole estate and cannot be scoped, so a scoped user gets only the
overall status from them; the detail is for administrators and the metrics
token (see [operations.md](operations.md#monitoring)).

Tags match without regard to case, using Unicode case folding: `Payments`
and `payments` are the same tag, and so are `straße` and `strasse`. The same
rule applies to usernames listed in a role mapping.

## API keys

Scripts and other systems authenticate with API keys, created by an
administrator under **Settings → API keys**. A key has one of three scopes:
`read` (viewer), `write` (operator) or `admin`. The token is shown once; only
its hash is stored. Send it as `Authorization: Bearer cwk_…`.

API keys are not tag-scoped: a `read` key can read the whole estate. Create
keys for systems, not people, and revoke them when they are no longer needed.
Creating, listing and revoking keys needs an administrator's browser session,
so an API key can't mint more keys, not even an `admin` key. A key keeps
working after the person who created it loses administrator access, so review
keys when access changes.

Routing identities are administrator-only. Certificate status responses and
`GET /api/certificates/{id}/alert-routing` expose delivery state, channel types
and anonymous recipient/group route counts to viewers, operators, and `read`
or `write` API keys. Only administrators and `admin` API keys receive recipient
addresses and matched alert-group names.

`/metrics` is separate from all of this. It accepts its own bearer token
(`CERT_WATCH_METRICS_TOKEN`) or an administrator's browser session, and
nothing else.

## Sessions

A sign-in produces a signed session cookie that lasts eight hours by default
(`CERT_WATCH_SESSION_TTL`, in seconds). Deleting, renaming or re-creating a
local account signs out any session for that username immediately. Upgrading
to 1.0 signs everyone out once, including the break-glass admin, because the
session format changed; API keys are unaffected.

Rotating `CERT_WATCH_AUTH_SECRET` also signs everyone out and requires
`cert-watch re-encrypt <old-key>` to re-encrypt stored secrets. See
[operations.md](operations.md#rotating-secrets).

## Checking what someone can do

- **Settings → Users** and **Settings → Roles** show each local account's role,
  each role's tier, scope and per-tag tiers, and the directory mapping.
- The audit log (**Activity → Audit log**, administrators only) records every
  sign-in, every change and the account or API key that made it.
