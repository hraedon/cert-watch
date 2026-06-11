# Plan 036: Fleet-wide E2E + Vault Credential Lifecycle

**Created:** 2026-06-05
**Status:** proposed
**Builds on:** Plan 034 (E2E), the Vault provisioning + LDAP harness proven in the
2026-06-05 session (see `docs/archive/2026-06-05-ldap-e2e-handoff.md`), `deploy/vault/`.

---

## Why

Two lessons from getting the agentic LDAP runthrough working:

1. **Opus driving every E2E is the wrong cost tier.** Once the runthrough is
   green, repeatedly having a top-tier reasoning agent launch Playwright and read
   screenshots is wasteful. Regression should be deterministic and cheap; the
   *adaptive* agent layer should run rarely (UI drift, new flows), and a
   capable-but-cheaper agent should handle on-demand runs.
2. **The Vault secret-id expiry repeatedly blocked the work.** A short-TTL AppRole
   secret-id that needs admin to re-mint mid-session is the wrong credential model
   for unattended/fleet use.

Goal: make the LDAP/Entra E2E **runnable by any agent (and CI) on the right cost
tier**, and give the fleet a **self-healing credential path** so no one babysits
tokens.

---

## What already exists (don't rebuild)

- A working, manual LDAP runthrough harness (launch env + Playwright script in
  `docs/archive/2026-06-05-ldap-e2e-handoff.md`), proven against real lab AD over LDAPS.
- Vault provisioned: policies `cert-watch-{setup,app,e2e-runner,totp-mcp}`,
  AppRoles `cert-watch-e2e` / `cert-watch-totp-mcp`, **kubernetes auth** (role
  `cert-watch` → SA `cert-watch/cert-watch`), TOTP broker. k8s-auth login already
  verified end-to-end (`kubectl create token … | vault write auth/kubernetes/login`).
- `tests/e2e/` Playwright harness + `e2e.yml` CI job (Plan 034).

---

## Part 1 — The credential lifecycle solution (the token problem)

**Root issue:** AppRole secret-ids expire / exhaust uses, and re-minting needs
admin. Static long-lived secret-ids "fix" it but leave a durable secret lying
around.

### Recommended: Kubernetes auth as the primary agent identity
The fleet has working kubectl. k8s auth has **no static secret to expire** — the
caller mints a fresh, short-lived SA JWT on demand and exchanges it for a scoped
Vault token:
```bash
JWT=$(kubectl create token cert-watch-agent -n cert-watch --duration=30m)
VAULT_TOKEN=$(vault write -field=token auth/kubernetes/login role=cert-watch-agent jwt="$JWT")
```
- Self-healing: nothing to babysit, kube re-mints each run.
- Scoped + audited: the role binds a least-priv policy; every login is logged.
- Setup (one-time, operator/automation identity):
  - `kubectl create serviceaccount cert-watch-agent -n cert-watch`
  - `vault write auth/kubernetes/role/cert-watch-agent bound_service_account_names=cert-watch-agent bound_service_account_namespaces=cert-watch policies=cert-watch-e2e-runner,cert-watch-totp-mcp ttl=30m`
  - (Optionally a stricter `cert-watch-e2e` namespace if you don't want the agent SA in the app namespace.)

### Fallback: long-lived AppRole for agents without kube access (lab-acceptable)
Operator is OK with longer-lived creds in the lab. For non-kube runners:
- `vault write auth/approle/role/cert-watch-e2e secret_id_ttl=0 secret_id_num_uses=0 token_ttl=30m` (non-expiring secret-id, unlimited uses, still short *token* TTL).
- Store `role_id`+`secret_id` in a durable, gitignored file (not `/tmp`). Accept the standing secret as a lab tradeoff; document it.

### The broker: one helper every agent/skill calls
`scripts/vault-login.sh` — abstracts the choice so no agent reimplements the dance:
1. If `VAULT_TOKEN` already set and valid → use it.
2. Else if `kubectl` + the agent SA are available → k8s auth (preferred).
3. Else if `VAULT_ROLE_ID`/`VAULT_SECRET_ID` present → AppRole.
4. Else fail loudly with the exact remediation.
Prints `VAULT_TOKEN` (or exports via `eval $(scripts/vault-login.sh)`); never logs
secrets. This also fixes the "launch script silently aborts on bad creds" trap —
the broker validates and explains.

**AC:** any fleet agent gets a scoped Vault token with zero manual secret-id
refresh, via k8s auth; AppRole path works where kube is absent.

---

## Part 2 — Package the runthrough so any agent (and CI) can run it

Move the ephemeral session artifacts into the repo, parameterized and asserted:

- `scripts/e2e/build_ldap_ca.sh` — rebuild the CA bundle from `hraedon_root.cer` +
  the live DC handshake (today's openssl dance, committed).
- `scripts/e2e/launch_cert_watch_ldap.sh` — broker-login → read LDAP secrets from
  Vault → launch cert-watch (fresh port, no pkill-race) → wait for health.
- `tests/e2e/test_ldap_login_real.py` — the runthrough as a proper `-m e2e`
  pytest: cw-admin/cw-user land on dashboard, bad creds rejected, out-of-group
  denied. Skips cleanly when `CW_LDAP_E2E=1` (real-AD opt-in) is unset, like the
  other e2e gates. Reads creds via the broker.
- A **project skill** (e.g. `/verify-ldap-e2e`) wrapping launch + run + report, so
  any agent invokes one command instead of re-deriving the procedure.

**AC:** `CW_LDAP_E2E=1 pytest -m e2e tests/e2e/test_ldap_login_real.py` is green
locally and via the skill, with no Opus-level reasoning required.

---

## Part 3 — Tiered execution (who runs what, when)

| Tier | Runner | Cadence | Purpose |
|---|---|---|---|
| Deterministic regression | CI (`e2e.yml`) + synthetic LDAP (Plan 034 Slice 1) | every PR | gate; no secrets, no agent |
| Real-AD fidelity | scheduled job / **cheaper agent** via the skill | nightly / pre-release | catch referrals, TLS, group nesting |
| Adaptive UI-aware | designated agent + Playwright MCP | on UI change / occasional | markup-drift resilience (retires BC-132) |
| Net-new capability / debugging | Opus (this tier) | rare | build/extend, not repeat |

Principle: **Opus builds the capability once; cheaper tiers run it forever.** The
skill + broker make the cheap tiers self-sufficient.

---

## Slices
1. **Credential broker** — `scripts/vault-login.sh` + the `cert-watch-agent` SA and
   Vault k8s role; AppRole long-lived fallback documented. (Unblocks everything.)
2. **Commit the harness** — `scripts/e2e/*` + `tests/e2e/test_ldap_login_real.py`
   (opt-in), using the broker. Replaces the ephemeral `/tmp` artifacts.
3. **Project skill** — `/verify-ldap-e2e` wrapping launch+run+report for any agent.
4. **Tiering** — wire synthetic LDAP into per-PR CI (Plan 034 Slice 1–2); schedule
   the real-AD fidelity run; reserve Opus for net-new.
5. **Entra parity** — same broker + skill for the Entra runthrough (TOTP via the
   codes-only path); Plan 034 Appendix A.

## Risks / decisions
- **k8s auth reachability** — agents must have kubectl to the cluster *and* network
  line-of-sight to the lab DCs (this session confirmed both from the sandbox). If a
  runner lacks kube, it uses the AppRole fallback.
- **Standing secret-id (fallback)** — a non-expiring AppRole secret-id is a durable
  secret; acceptable for lab, must be gitignored and noted. Prefer k8s auth.
- **Agent SA scope** — `cert-watch-agent` gets `e2e-runner`+`totp-mcp` (passwords +
  codes). That's broader than the strict "agent = codes only" boundary; justified
  because the *test process* needs passwords. If a true autonomous-agent context is
  added, give it only `cert-watch-totp-mcp` and keep passwords in the process.
- **Don't let the cheap tier mask bugs** — the real-AD pytest must assert outcomes
  (dashboard reached, group denial), not just "page loads" (cf. BC-017).

## Dependencies
- Plan 035 (RBAC) for admin-vs-read-only assertions in the runthrough.
- `docs/archive/2026-06-05-ldap-e2e-handoff.md` for the exact working launch/runthrough this generalizes.
