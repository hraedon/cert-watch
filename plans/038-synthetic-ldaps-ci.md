# Plan 038: Synthetic LDAPS server in CI (the deterministic auth-test tier)

**Created:** 2026-06-05
**Status:** proposed
**Builds on:** the three LDAPS auth bugs fixed in the 2026-06-05 session, the
`integration` pytest marker (`pyproject.toml`), the CI/e2e workflow conventions
(`.github/workflows/{ci,e2e}.yml`), and Plan 036's tier table (this is the
top "deterministic regression / every PR" row, currently unbuilt).

---

## Why (the evidence)

Three bugs that broke **100% of private-CA LDAPS logins** shipped through a suite
with **1257 passing tests and ~90% coverage**:

1. `use_ssl=` passed to `ldap3.Connection` (real ldap3 rejects it; `MagicMock` ate it).
2. inline-PEM CA made `Path.is_file()` raise `OSError(ENAMETOOLONG)` (no test ran
   `_resolve_ca_cert` over a real TLS socket).
3. `LDAP_REQUIRED_GROUPS` split on `,` shredded comma-bearing DNs (no test ran the
   group filter against a real entry with a real DN).

Root cause is **mock fidelity**, not coverage: the tests exercised the lines but
against fakes more forgiving than the library and the protocol. High coverage on
low-fidelity mocks is a confidence mirage. The only thing that caught these was a
live, manual, Opus-driven E2E against the lab — expensive, gated, and not on any
PR.

**Goal:** a deterministic test tier that runs the auth stack against a *real* LDAP
implementation over *real* LDAPS with a *real* private CA, on **every PR**, with
no secrets, no lab line-of-sight, and no agent. It should have caught all three
bugs — and catch the next one in this class.

## What exists (don't rebuild)

- `tests/test_auth.py` — fast mocked unit tests (keep; they're fine for logic that
  doesn't touch the library/protocol boundary). Now includes the stricter-fake
  regression tests from this session.
- `integration` marker already defined ("integration tests requiring external
  tools"); default `addopts` exclude it, so it won't slow the main unit job.
- `LDAPAuthProvider` is fully parameterized (server URL, CA, filters, groups), so
  it can be pointed at a container with no production changes.
- The working launch/runthrough recipe in `docs/archive/2026-06-05-ldap-e2e-handoff.md` to mirror at app level.

## The fidelity decision (important — drives server choice)

The default group gate uses the **AD-specific** transitive matching rule
`(memberOf:1.2.840.113556.1.4.1941:={group})` (`ldap_provider._build_group_filter`).

- **Plain OpenLDAP does NOT support that OID.** Against OpenLDAP the default filter
  returns nothing *even when correctly configured* — which would confound the
  comma-split bug (#3) with "server doesn't implement the rule." OpenLDAP can only
  test the group path via the `LDAP_GROUP_FILTER` override (`memberOf={group}`),
  leaving the **default** code path untested against a real server.
- **samba-AD DC** emulates AD: it supports the matching-rule OID, `sAMAccountName`,
  and LDAPS — so it exercises the *actual default* gating path users hit.

**Recommendation:** samba-AD DC as the primary synthetic target (it's the only
option that faithfully covers bug-#3's default path + sAMAccountName + LDAPS
together). Document OpenLDAP as a lighter fallback that still covers TLS + bind +
inline-CA + direct-`memberOf`, i.e. bugs #1 and #2 and a non-default group path.

> Decision to confirm with the operator: accept samba-AD's heavier spin-up
> (~10–20s, more config) for full fidelity, vs OpenLDAP's speed at the cost of not
> exercising the default group filter. Recommended: samba-AD.

## What this adds

### A. A container fixture (works locally and in CI)
`tests/integration/conftest.py` — a session-scoped fixture that:
- Starts a samba-AD DC container (pinned digest) with a generated **private CA**
  and an LDAPS listener on 636; seeds two users (`cw-admin`, `cw-user` by
  `sAMAccountName`) and two groups (`cert-watch-admins`, `cert-watch-users`) with
  one membership each — mirroring the lab so tests read like the real runthrough.
- Exports the CA **as inline PEM** (so we test the `ca_cert=` inline path — the
  one bug #1 lived in — not just a file path).
- Uses **testcontainers-python** so the same fixture runs in CI and on a dev box
  with Docker; **skips cleanly** (not fails) when Docker is unavailable, like the
  e2e gate skips without Playwright.
- Marked `integration`; excluded from the default/fast unit run.

### B. Provider-level integration tests (fast, focused)
`tests/integration/test_ldap_provider_real.py` — drive `LDAPAuthProvider`
directly against the container:
- inline-PEM CA over LDAPS → bind succeeds (would fail on bug #1 and #2).
- `cw-admin`/`cw-user` authenticate; out-of-group user denied.
- the **default** transitive group filter (the OID) matches real membership
  (would fail on bug #3's filter shape).
- bad password rejected; wrong CA rejected (fail-closed CERT_REQUIRED holds).

### C. App-level login test through config parsing (catches the wiring)
`tests/integration/test_ldap_login_real.py` — bug #3 lives in **config.py**, not
the provider, so at least one test must go through `Settings.from_env`:
- set `LDAP_REQUIRED_GROUPS` via the **env** (semicolon-separated), launch the app
  against the container, and assert the HTTP login lands on the dashboard and the
  out-of-group user is denied. This exercises parse → provider → route end to end.

### D. CI wiring
New job `ldap-integration` (own job, not the fast unit job, since it needs Docker
and is slower):
```yaml
ldap-integration:
  runs-on: ubuntu-latest   # Docker available on GH-hosted runners
  steps: [checkout, setup-uv (3.13), uv pip install -e ".[dev,auth,integration]",
          run: .venv/bin/pytest -m integration tests/integration -q --no-cov -n0]
```
(`--no-cov -n0` mirrors the e2e job: container-bound, not parallel-safe; coverage
gate stays on the unit job.) Add a small `integration` extra for
`testcontainers`. Runs on every PR alongside `ci` and `e2e`.

## Slices
1. **Container fixture** — samba-AD container + CA + seeded users/groups; inline-PEM
   export; Docker-absent skip. (Unblocks B and C.)
2. **Provider integration tests** (B) — the focused real-LDAPS assertions.
3. **App-level login test** (C) — through `Settings.from_env`, catches the parse wiring.
4. **CI job** (D) — `ldap-integration` on every PR; `integration` extra for testcontainers.
5. **Mutation-verify** — temporarily reintroduce each of the three bugs and confirm
   a test in this tier goes red (the standard set this session: a regression test
   that can't fail against the bug is theater).

## Acceptance
- `pytest -m integration tests/integration` is green locally (Docker present) and
  in the `ldap-integration` CI job, with **no secrets and no lab access**.
- Mutation check: each of the three 2026-06-05 bugs, reintroduced, turns this tier
  red — proving it would have caught them on the PR that introduced them.

## Risks / decisions
- **samba-AD spin-up cost/flakiness** — heavier than OpenLDAP; pin a digest, give
  the fixture a generous readiness wait (poll LDAPS bind, not a fixed sleep), and
  scope it session-wide so it starts once. If flake proves unmanageable, fall back
  to OpenLDAP and accept that the *default* group filter is covered only by the
  real-AD tier (Plan 036) — state that tradeoff explicitly, don't paper over it.
- **Docker-in-CI** — GH-hosted `ubuntu-latest` has Docker; self-hosted runners may
  not. The skip-when-no-Docker guard keeps local dev unblocked; CI must have it.
- **Don't let this replace the real-AD tier** — synthetic ≠ Hraedon AD. It won't
  catch lab-specific PKI (the stale-root issue in the archived 2026-06-05 handoff), referral chasing, or
  Entra. This **demotes** the real-AD run from "only safety net" to "fidelity
  backstop" (Plan 036), it does not retire it.
- **Keep the fast unit job fast** — integration is a separate job/marker; the
  per-PR unit feedback loop stays quick.

## Dependencies / relationships
- **Complements Plan 036:** this is 036's top tier row (deterministic, every PR);
  036 Slice 1–2 makes the *fidelity* tier (real AD) repeatable. Build both; this
  one first — it's the per-PR net.
- **Independent of Plan 035 (RBAC):** RBAC assertions can be added to these tests
  once roles exist, but this plan needs no RBAC to land.
- Reuses the `integration` marker and the e2e job's `--no-cov -n0` convention.
