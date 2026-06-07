---
model: kimi-k2p6-turbo
datetime: 2026-06-07T05:25 UTC
project: cert-watch
---

# Session Reflection — 2026-06-07

**Work summary:** Validated Plan 046 (v0.6.5 hardening pass) against the repo, resolved the two open security breadcrumbs (BC-116/117), reconciled the breadcrumb DB with the filesystem, and closed three stale breadcrumbs (BC-118, BC-137, BC-147). The open backlog dropped from 17 to 14 items.

---

## On the project

cert-watch is a remarkably mature "MVP" — it has RBAC, API keys, compliance reports, audit logging, multiple auth providers, and a full E2E suite. The biggest risk to its credibility is not missing features but **surfaces that look done but aren't** (the plan calls this "truth-in-advertising"). The v0.6.5 hardening pass was the right call: fix the silently-inert RBAC path for AD (BC-150), remove the stubbed mis-issuance UI, and close the security gap around webhook/OCSP SSRF. The codebase is well-organized for an agent: the `AGENTS.md` is precise, the test suite is fast (~90s for 1347 tests), and the CI is comprehensive (unit, e2e, visual, integration, deploy-smoke on docker/linux/k8s/windows).

One thing that feels slightly wrong: the breadcrumb management. The `OPEN_BREADCRUMBS.txt` is generated from a postgres-backed `agent-notes` CLI, but the filesystem under `breadcrumbs/` had 80 resolved files with `status: open` in their frontmatter — a stale projection that was confusing. The two sources of truth (DB vs. files) were out of sync. I fixed this by bulk-correcting the resolved files and syncing, but the sync workflow itself seems fragile.

## On the work done

The validation was straightforward: ruff, mypy, unit tests, e2e, integration all passed. The coverage is at 90.09%, which is honest (not theater). The scan.py coverage hit 85% after the 20 new tests in BC-155.

The BC-116/117 resolution was the most judgment-heavy part. The code was already implemented — `http_client.ssrf_safe_urlopen` validates every redirect, `alerts.py` and `posture.py` both use it. But the env-configured webhook path (`ALERT_WEBHOOK_URL` in `config.build_webhook_config`) was never validated at startup, so the GUI and env paths were inconsistent. I added a validation call in `build_webhook_config()` and a test. This is a small fix but it closes the consistency gap that the original BC-116 explicitly called out.

The three stale breadcrumbs I closed were genuinely done: BC-118 (LDAP group filter configurable via `LDAP_GROUP_FILTER`), BC-137 (inline imports are the documented design), BC-147 (the `c` variable reuse pattern is not present in current code). I verified each before closing.

## On what remains

The v0.6.5 plan is essentially complete. The only remaining step is **E (cut v0.6.5 tag)** — the user already bumped versions in `pyproject.toml` and `_version.txt`, wrote the CHANGELOG, and updated the README. The tag `v0.6.5` does not exist yet. The git state is clean, `main` is 2 commits ahead of `origin/main`, and the working tree is ready.

The 14 remaining open breadcrumbs are legitimate deferred work:
- Feature requests (BC-020, BC-121, BC-131, BC-136, BC-151, BC-021, BC-103)
- CI/test hygiene (BC-143, BC-123)
- Code quality (BC-095, BC-096, BC-100)
- The BC-144 "remaining refactors" todo, which is a grab-bag that should be split

None of these are hardening gaps; they are roadmap items for 0.7.0 or 1.1.

## Gaps to flag

- **Breadcrumb-DB sync fragility**: The `agent-notes` CLI and the filesystem under `breadcrumbs/` can diverge. The resolved files had `status: open` for months, and the `OPEN_BREADCRUMBS.txt` was generating stale lists (17 items, many of which were already resolved in the DB). The `reconcile` command was not sufficient because it only looks at git commits, not at the filesystem state. A periodic `breadcrumb sync` should be part of the workflow.
- **BC-144 is a grab-bag**: It bundles config.py decomposition (deferred to 0.7.0), spec completeness (deferred to 0.7.0), and ~8 test files with inline `importlib.reload` (mechanical cleanup). It should be split into two breadcrumbs so the backlog is honest.
- **BC-095 (SSRF deduplication)**: The `routes/hosts.py` `_ssrf_check_host()` duplicates logic from `scan.py` and `http_client.py`. This is a genuine security-adjacent gap that could be closed in a single commit. It's the one remaining item I'd consider pulling into a future hardening pass.
- **BC-100 (hardcoded issuer fragments)**: The Discover page uses `NOT LIKE '%Let%'` etc. to identify private CAs. This is brittle and will miss private CAs with unexpected names. The README documents this as a known limitation, but the code is still in production.
- **No uncommitted secrets**: The diff shows only the intended files (config.py, test files, breadcrumbs). No `.env`, no generated artifacts, no secrets.
