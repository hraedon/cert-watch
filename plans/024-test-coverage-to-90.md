# Plan 024: Raise Test Coverage to ≥90% (and ratchet the gate)

> **Status:** ready for implementation. Grounded in a coverage run on the 0.4.0
> release commit (`--ignore=tests/e2e`, the CI configuration). Test-only — no
> production code changes — so it carries little risk and parallelizes cleanly
> with the 0.5.0 feature work.

## Goal

Lift total line coverage from **81.7% → ≥90%**, then bump the CI gate
(`--cov-fail-under`) from **75 → 90** so it ratchets and can't silently regress.

## Current state (statements / missing / coverage)

Total ≈ **6552 stmts, ~1199 missing (81.7%)**. To reach 90% we must cover
**≈ 545** of those missing lines (target ≤ 655 missing). The gap is concentrated:

| Module | Cov | Missing | Where the gap is |
|--------|----:|--------:|------------------|
| `routes/views.py` | 56% | **136** | dashboard/insights/discover/detail render paths, filter branches |
| `routes/certificates.py` | 58% | **116** | detail panels, delete, tag PUT, error/404 paths |
| `routes/api.py` | 74% | **116** | pagination edges, CT reconciliation, webhook-URL validation branches |
| `routes/settings.py` | 72% | **87** | auth/SMTP/alert save paths, validation errors, test buttons |
| `routes/hosts.py` | 79% | **48** | bulk import, scan trigger, delete, form validation |
| `auth/oauth_provider.py` | 76% | 51 | token exchange, JWKS verify, error paths |
| `middleware.py` | 80% | 68 | rate-limit, CSRF, CSP-nonce, trusted-proxy IP branches |
| `scan.py` | 75% | 88 | openssl fallback, timeout/retry, blocked-IP, async paths |
| `scheduler.py` | 66% | 46 | scheduled-job failure handling, next-run math |
| `database/queries.py` | 89% | 102 | less-used query branches (big file: 938 stmts) |
| `config.py` | 85% | 39 | env-parse edges, `from_env_with_kv` |
| `cert_chain.py` | 83% | 36 | chain-validation error paths |
| `routes/audit.py` | 61% | 14 | filter params, pagination |

**The `routes/` layer holds 534 of the missing lines** — it is the coverage gap,
and (not coincidentally) the user-facing surface where a regression is most
visible. It's also the lowest-covered area precisely because route handlers are
exercised only indirectly today.

## Overlap with 0.5.0 (don't double-count)

Several 0.5.0 items add tests for under-covered modules **as a side effect**:
- **[[BC-115]]** (LDAP) lifts `auth/ldap_provider.py`.
- **[[BC-116]]/[[BC-117]]** (SSRF opener) lift `scan.py` and the revocation paths
  in `posture.py`.
- OAuth work touches `auth/oauth_provider.py`.

So this plan focuses the *dedicated* effort on the **route layer + middleware +
scheduler**, and treats the security-module gains as coming from 0.5.0.

## Strategy

Lean on **TestClient integration tests** for the route layer — the pattern is
already established (`test_app_endpoints.py`, `test_rest_api.py`, `test_dashboard.py`,
the new `test_oauth_callback.py`). Each route file gets tests for: the happy
render/response, the **auth-gated** branch (anon → redirect/401; non-admin → 403;
read-only user → blocked mutation), **error paths** (404 for missing id, 400 for
bad form/CSV, validation failures), and **pagination edges** (page/limit bounds,
empty result). These are cheap per-line and exercise exactly the missing branches.

## Slices (with coverage budget)

1. **Route layer — read/render paths** (`views.py`, `certificates.py` detail,
   `audit.py`): drive every page with a seeded DB (a few certs/hosts/alerts,
   tags, history) and assert status + key content. *Recovers ≈ 200 lines.*
2. **Route layer — mutation & API paths** (`hosts.py`, `certificates.py` delete/tag,
   `api.py`, `settings.py`): add host / bulk import (valid + malformed CSV),
   trigger scan, delete, tag PUT, settings save (auth/SMTP/alerts) incl. validation
   errors and the authz tiers (`CERT_WATCH_ADMINS`, `CERT_WATCH_WRITE_USERS`).
   *Recovers ≈ 230 lines.*
3. **middleware.py** branches: rate-limit exceeded, CSRF reject/accept, CSP nonce
   issuance, trusted-proxy `X-Forwarded-For` parsing, metrics bearer gate.
   *Recovers ≈ 50 lines.*
4. **scheduler.py + scan.py error paths**: scheduled-job exception handling, the
   openssl fallback (mock `subprocess`), timeout/retry, all-IPs-blocked. (Coordinate
   with the BC-116/117 scan tests to avoid overlap.) *Recovers ≈ 80 lines.*
5. **Targeted top-ups** (`config.py`, `cert_chain.py`, `database/queries.py`):
   only the branches needed to clear 90% — env-parse edges, chain error paths,
   a few query filters. *Recovers ≈ 60 lines.*

Slices 1–3 alone (~480 lines) plus part of 4 clear the ~545 needed; 5 is margin.

## Pragmatic exclusions (keep the target honest)

Some missing lines are genuinely defensive and not worth contrived tests. Apply
`# pragma: no cover` narrowly to: `if TYPE_CHECKING:` blocks, `__main__` guards,
truly unreachable `except` fallbacks, and platform-specific branches. Keep this to
a documented minimum (grep-able) so it isn't used to paper over real gaps — the
goal is 90% of *meaningful* lines, reached honestly, not a number gamed with
pragmas.

## Ratchet

Once ≥90% is real, bump `--cov-fail-under` **75 → 90** in `pyproject.toml`. From
then on CI blocks any change that drops below 90%, so coverage only goes up. (The
0.4.0 work already runs comfortably above 80%; the ratchet should move in steps —
e.g. 75 → 85 after slice 2, → 90 after slice 5 — so an in-flight branch isn't
blocked mid-effort.)

## Verification

`pytest -q --ignore=tests/e2e --cov-report=term-missing` after each slice; confirm
the per-module numbers above close, total ≥ 90%, and no production code changed.

## Open question

- **Sequencing:** run this in parallel with 0.5.0 (test-only, low conflict risk),
  or gate the 0.5.0 release on hitting 90% first? Recommend parallel, with the
  gate bumped to 90 as the last step before the 0.5.0 tag.
