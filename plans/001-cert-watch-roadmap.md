# cert-watch — Plan & Roadmap

**Last updated:** 2026-05-25
**Status:** v0.2.0 implemented (untagged); v0.1.0 tagged as comparison artifact

---

## Why this project exists (don't lose this thread)

cert-watch is a **traditional-build comparison artifact** for the multi-agent factory pipeline at [software-factory-2](https://github.com/hraedon/software-factory-2). Two implementations of the same MVP from the same spec — one one-shot Opus 4.7 (this repo), one multi-agent factory (`hraedon/cert-watch-factory-failed`). The convergence of their gaps is the experimental finding that drove [debate 005 → process v6 in socratic-specification](https://github.com/hraedon/socratic-specification/blob/master/debate/resolved/005-composition-audit.md).

The repo serves two audiences:
1. **The experiment**: stable comparison points against factory outputs.
2. **Real usage**: a tool that can actually be deployed and used internally to track cert expirations.

These pull in slightly different directions. Tag boundaries (v0.1, v0.2, v0.3) keep both audiences served — every release is a checkpoint we can compare against future factory work.

---

## Current state

### v0.1.0 (tagged 2026-05-25, commit 8644187)

- All 8 spec modules implemented; PKCS#12 upload; leaf+chain rendering; add-host UI
- 55 unit tests, 4 E2E tests, CI green, image pushed, Argo CD deployed
- **Known gaps preserved as comparison data** — see release notes

### v0.2.0 (implemented, not yet tagged; HEAD ~ 2218ae1 + e2e fix)

Fixes the cert-watch gaps that became debate 005 evidence:
- Scheduler wired into FastAPI lifespan
- `AlertConfig` loaded from `SMTP_*` env vars (no-ops cleanly if absent)
- `validate_chain_order` called during scan + upload; `chain_valid` column persisted
- Delete UI for hosts and certificates
- "Scan now" button per host
- `/alerts` and `/scan-history` read-only views
- `humanize_expiry` Jinja filter

75 unit tests, 5 E2E tests, CI green.

### Three open judgment calls on v0.2

1. **`chain_valid` is nullable, not `DEFAULT 1`.** Existing rows from v0.1.0 stay `NULL` (template shows no badge). More honest than asserting validity for rows never tested. **Decision needed:** keep as-is, or backfill validation for v0.1-era rows on first startup?
2. **Version bump landed in `pyproject.toml` and `__init__.py` already.** Tag whenever you're ready: `git tag v0.2.0 HEAD && git push --tags && gh release create v0.2.0 --generate-notes`.
3. **`unittest.mock.patch` on `datetime`** instead of `pytest-freezegun` — avoided adding a dev dep, functionally fine.

---

## Tomorrow's experiment (the cross-stage validation)

Run cert-watch through a **fresh Socratic session** under the amended Step 5 (composition audit folded in). Predicted outcome: the three v0.1-era composition gaps (scheduler wiring, scan_history display, AlertConfig source) should be flagged **before synthesis** and either answered by the human or recorded as open questions.

- **Setup**: clean room, no priors from the existing wi_*.md files. Use a fresh vibe-spec equivalent to the original cert-watch prompt.
- **Reviewer**: use a different model from the elicitation AI (per debate 005's cross-model audit requirement). Suggested: opencode/Kimi K2.6 as the elicitor, DeepSeek v4-pro or Claude Sonnet as the composition-audit reviewer.
- **Pass condition**: at least 2 of 3 predicted gaps are surfaced as open questions in the resulting spec.
- **Fail condition**: composition gaps still missing → Step 5 needs more work; reopen debate 005 or open 006.
- **Output artifact**: `/projects/socratic-specification/experiments/2026-05-26-cert-watch-rerun.md` with the elicitation transcript, audit output, and gap-detection result.

---

## v0.3 backlog (deferred from v0.2 with `TODO(v0.3)` markers in code)

In priority order:

1. **SSRF guard on `POST /hosts`** — currently any internal-network user can ask cert-watch to TCP-connect to arbitrary `host:port`, including internal infra. Decision needed: allowlist of CIDR ranges, denylist of internal ranges (RFC1918 + link-local), or just refuse non-443/non-TLS ports. Talk to user before implementing.
2. **PKCS#7 (`.p7b` / `.p7c`) upload** — common Windows certificate export format. One-liner via `cryptography.hazmat.primitives.serialization.pkcs7.load_der_pkcs7_certificates`.
3. **Bulk host import** — CSV or YAML upload; anyone migrating >10 endpoints will want this. Endpoint: `POST /hosts/bulk`.
4. **`/metrics` Prometheus endpoint** — `cert_watch_certs_total`, `cert_watch_certs_expiring_within_days{days="7"}`, `cert_watch_last_scan_timestamp`, `cert_watch_scan_failures_total`. Library: `prometheus-fastapi-instrumentator` (would be a new dep — get sign-off).
5. **JKS support** — only if there's actual demand. Java keystores are heavy and would require a new dep (`pyjks`). Default no.
6. **Auth** — explicitly out of scope by spec but flagged as v0.4+ once it becomes load-bearing.

---

## Operational notes

- **Single-replica + sqlite**: `replicas: 1` + `Recreate` rollout → ~30s downtime per deploy. Acceptable for this scale; flag if traffic grows.
- **Scheduler runs in-process**: with replicas>1 it would multi-fire. Don't scale horizontally without first extracting the scheduler to a separate Deployment or adding leader election.
- **`enableServiceLinks: false`** is load-bearing on the k8s Deployment — the Service's auto-injected `CERT_WATCH_PORT=tcp://...` env var would otherwise shadow our config. Don't remove it.
- **Argo CD `Application`** is at `deploy/argocd/application.yaml`; applied to the cluster on 2026-05-25. Self-heal + auto-prune on. Manual sync if needed: `argocd app sync cert-watch`.
- **GHCR images**: every push to main builds multi-arch (amd64+arm64), tags with short sha + `latest`, and CI auto-commits a tag bump to `deploy/k8s/kustomization.yaml`. Don't edit that file manually.

---

## Files / paths quick reference

- App entry: `src/cert_watch/app.py` (FastAPI w/ lifespan)
- Config: `src/cert_watch/config.py` (env-driven `Settings`)
- DB: `src/cert_watch/database.py` (sqlite, idempotent `init_schema`)
- Spec source of truth: `docs/spec/wi_*.md`
- Manifests: `deploy/k8s/` (kustomize); Argo CD app: `deploy/argocd/application.yaml`
- Compose: `deploy/compose/docker-compose.yml`; systemd: `deploy/systemd/cert-watch.service`
- E2E: `tests/e2e/` (opt-in via `pytest -m e2e`; CI runs separately in `e2e.yml`)

---

## Open questions for next session

1. Tag v0.2.0 now, or hold until tomorrow's experiment confirms the process change works?
2. SSRF policy: allowlist / denylist / port-only filter — your call.
3. Should v0.3 add `/metrics` (Prometheus dep) or is observability staying log-based?
4. Backfill `chain_valid` for v0.1-era rows on first boot, or leave them `NULL`?
