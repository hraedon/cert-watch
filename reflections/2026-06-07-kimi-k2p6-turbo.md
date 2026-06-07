---
model: fireworks-ai/accounts/fireworks/routers/kimi-k2p6-turbo
datetime: 2026-06-07T03:15 UTC
project: cert-watch
---

# Session Reflection — 2026-06-07

**Work summary:** Completed the v0.6.5 hardening team items (C2 compliance N+1 fix, D2 Node-24 action pins, D3 e2e pip-audit) and the release cut (E): CHANGELOG, README Known limitations, version bump to 0.6.5. Also ran a maturity review and added a new Section F to Plan 046 for post-review hardening (HSTS, scan.py coverage, backlog hygiene). Breadcrumbs reconciled: BC-150 resolved.

---

## On the project

cert-watch is genuinely production-credible. The architecture is deliberate: repository pattern in database/, decomposed auth package, FastAPI factory with DI, security middleware with CSP nonces and session revocation. The test suite is honest (the 2026-06-04 theater cleanup is a real quality signal). What stands out is the **security discipline**: BC-xxx breadcrumbs show iterative adversarial hardening, not checkbox compliance. The biggest structural gap is spec completeness — docs/spec/ only covers the v0.1.0 MVP, leaving auth, RBAC, compliance, posture, and SIEM undocumented as formal requirements. That matters for a 4/5 maturity rating.

## On the work done

The C2 compliance fix was clean: replacing `list_dashboard_rows` with `_load_compliance_rows` that only fetches leaf certs via SQL JOIN with SQL-level tag filtering. It removed an N+1 and an unbounded memory load without changing the report output. All 28 compliance tests passed, and the full suite stayed at 89.58% coverage.

The D2/D3 CI changes were mechanical but important: bumping setup-uv, upload-artifact, and download-artifact to Node-24-capable pins before GitHub's 2026-06-16 deadline. The pip-audit step in the e2e job was a one-line addition but closes a supply-chain gap.

The maturity review was the most valuable part of this session. The four subagents (architecture, testing, security, docs) gave convergent 4/5 ratings with specific, bounded gaps. I pushed back two items (spec completeness, config.py decomposition) because they are multi-day cross-cutting efforts that don't fit a feature-freeze hardening iteration. The three accepted items (F1 backlog hygiene, F2 HSTS, F3 scan.py coverage) are small, bounded, and security-relevant.

## On what remains

Before v0.6.5 can ship:
1. **F2 (BC-154)** — Add HSTS header in `security_headers_middleware` when `CERT_WATCH_COOKIE_SECURE=1`, with a ratchet test.
2. **F3 (BC-155)** — Mock the `openssl s_client` subprocess path and socket-error branches in `scan.py` to push coverage above 85%.
3. **F1** — Regenerate `OPEN_BREADCRUMBS.txt` and confirm no stale entries.
4. **E** — Tag `v0.6.5` (triggers release.yml image build + Trivy).

After v0.6.5:
- Spec completeness for auth, RBAC, compliance, posture, alert adapters, SIEM → 0.7.0 docs plan.
- config.py decomposition → dedicated plan with QA.
- Real CT mis-issuance + CAA per-scan → 1.1.

## Gaps to flag

- **scan.py coverage at 74%** — the openssl subprocess path (lines 328-389) and socket error branches are the dominant untested surface. The review noted this as the one genuine gap that could hide a regression in the field (`tests/test_scan.py` exists but doesn't mock the subprocess). F3 addresses this.
- **HSTS on own UI** — The app probes HSTS on remote hosts but doesn't set it on its own responses. This is a credibility gap for a security tool; F2 addresses it.
- **OPEN_BREADCRUMBS.txt drift** — The export file was stale with resolved items still appearing open. F1 addresses this, but the underlying process (regenerate after each release) needs to be documented or automated.
- **config.py at 305 lines** — The procedural `Settings.from_env()` is a known smell. It's documented as deferred, but the risk is that new settings continue to be added to this monolith, increasing the refactoring cost over time.
- **DOM-based XSS risk** — Several templates assign server data to `innerHTML` inside nonce-gated script blocks. While the data is currently server-generated, any future route that reflects user input (tags, notes, search) without escaping could introduce DOM XSS. This is a latent risk, not an immediate vulnerability.
- **AGENTS.md Plan status** — The plan status list in AGENTS.md is now stale (Plan 046 items are done in working tree but not reflected). The file says "Do not hand-maintain a backlog list here — it drifts," which is correct, but the plan status paragraph is itself a hand-maintained list that has drifted.
