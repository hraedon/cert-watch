# Plan 057: The road to 1.0

Authorized by the owner on 2026-09-22: drive cert-watch to a 1.x release,
ignore the maintenance-mode posture, nothing is sacred, rewrite the docs.

This plan supersedes the *ordering* of plan 056, not its diagnosis. 056 aims
first at a replaceable presentation layer. The measured maintenance cost and the
bug stream sit underneath it: in September `alerts.py` took 16 commits and
produced #30, #37, #38, #39, #43, #61 and #62; config merging produced two
silent-drop bugs; the data layer has no transaction owner. So the core goes
first and the presentation seam goes last, where it is cheap because the layers
under it have settled.

## Ground rules

- One PR per workstream, branched from current `main`. Merge on green CI plus
  an independent review. Anything touching auth, CSRF, scope, SSRF, key
  handling or an external sink gets **two** reviewers of different lineage, at
  least one of which executes probes.
- Every bug fix lands with a regression test that fails on the old code.
- Behaviour changes visible to operators go in `CHANGELOG.md` and, if they need
  action, `UPGRADING.md`. Pre-1.0 is the moment for endpoint and audit-name
  changes; after 1.0 they are compatibility events.
- Refactors are behaviour-preserving unless the PR says otherwise. The unit
  suite (≈3,000 tests, ≈1 min) and e2e suite are the net.

## Workstreams, in order

**W0 — Land what exists.** Branch `refactor/presentation-service-owner`
(056 §1–3 and the first services/presenter slice). Note the audit-action
unification (`*.set_tags` → `*.update_tags`) in the changelog.

**W1 — Stop the bleeding.** Known defects, each with a failing-first test:
- kv merge drops `renewal_webhook_url`/`_headers` (env-configured renewal
  webhook silently disabled once setup has run).
- `POST /alerts/flush` runs blocking delivery on the event loop and races the
  scheduler with no claim on pending rows.
- Open issues #58, #59, #60, #61, #65, #66, #67, #68, #69.
- `/scan-history` is not scope-filtered.

**W2 — Config has one source of truth.** A declarative field table drives env
parsing, kv merge (`dataclasses.replace`, never a hand-listed constructor),
bounds and sensitivity. A test proves every `Settings` field survives the merge.
The test fixture builds settings through the production path. Direct
`os.environ`/`kv_get` reads outside `config/` go away.

**W3 — The data layer owns transactions.** One `transaction(db_path)` helper
(write lock + single commit). SQL outside `database/` moves in; the unused
repository ABCs go. `ensure_base` is frozen at the 0001 shape; each migration
commits together with its version row; a test compares fresh and upgraded
schemas.

**W4 — Alerting is a package with one persisted lifecycle.** Rules (one dedupe
policy per alert type) → routing → dispatch (claims/leases, persisted
per-alert delivery state per #38) → transports that return results instead of
mutating `Alert`. One digest engine replaces the two near-copies.

**W5 — The scheduler is an object.** Owns its thread, pools and locks; tests
construct it instead of monkeypatching module globals. Bounded shutdown (#68).

**W6 — One way to guard a route.** A single guard family where every write
guard includes CSRF; `middleware.py` split by concern; services take the actor
and enforce scope themselves.

**W7 — The presentation seam (056 §5).** Presenters for detail and browse,
template business logic out, stray `/api/` endpoints consolidated, one write
path per concept, API-completeness and inventory contract tests.

**W8 — Tests follow the code.** Coverage top-up files folded into feature
tests as their areas are touched; private-symbol imports reduced.

**W9 — Documentation, rewritten.** README, operator guide, architecture,
AGENTS.md, UPGRADING for 1.0. `plans/` and `reflections/` move to an archive;
the product tree carries current documentation only.

**W10 — Release 1.0.0.**

## Parallelism

W1 first. W2+W3 (config/, database/) and W6 (middleware, routes, auth) touch
disjoint trees and can run concurrently. W4+W5 follow W2/W3. W7 follows W6.
W9 is written last against the code that ships.

## Out of scope

A second front end; replacing SQLite; dropping Windows/IIS (it is deployed).
