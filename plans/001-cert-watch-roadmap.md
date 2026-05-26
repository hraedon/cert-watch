# cert-watch — Plan & Roadmap

**Last updated:** 2026-05-26
**Status:** v0.3.0 implemented; v0.1.0 tagged as comparison artifact; v0.2.0 tagged

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

### v0.2.0 (tagged 2026-05-25, commit 2218ae1+)

Fixes the cert-watch gaps that became debate 005 evidence:
- Scheduler wired into FastAPI lifespan
- `AlertConfig` loaded from `SMTP_*` env vars (no-ops cleanly if absent)
- `validate_chain_order` called during scan + upload; `chain_valid` column persisted
- Delete UI for hosts and certificates
- "Scan now" button per host
- `/alerts` and `/scan-history` read-only views
- `humanize_expiry` Jinja filter

75 unit tests, 5 E2E tests, CI green.

### v0.3.0 (implemented, not yet tagged; HEAD)

Major feature release covering the entire v0.3 backlog and more:

**Security hardening:**
- CSRF double-submit cookie protection on all POST endpoints
- SSRF guard on host addition (blocks RFC1918 + link-local + loopback ranges)
- Rate limiting (in-memory sliding window) on add-host, scan, upload, import
- Upload size cap (10 MiB) for certificates and CSV imports
- SMTP credential sanitization in error messages

**API & observability:**
- JSON REST API: `/api/certificates`, `/api/hosts`, `/api/alerts` (paginated, with `?page=&limit=`)
- Prometheus `/metrics` endpoint (no external dep; cert_expiry_days, hosts_tracked, certs_tracked, certs_expired)
- `/healthz` endpoint with DB connectivity, last scan, scheduler status, cert counts
- Certificate Transparency log lookup via crt.sh (`/ct-lookup/{domain}`)

**Features:**
- Bulk host import via CSV (`/hosts/import`)
- Webhook/Slack alert delivery alongside SMTP (`ALERT_WEBHOOK_URL` env)
- Per-host custom alert thresholds (`threshold_days` column on hosts)
- Renewal tracking (`replaces_cert_id` links new certs to predecessors)
- PKCS#7 (`.p7b`/`.p7c`) upload support
- PKCS#12 (`.pfx`/`.p12`) upload with password

**Bug fixes:**
- Scheduler loop: scan/alert calls were outside while loop (only ran once)
- WAL mode on SQLite connections (eliminates `database is locked` contention)
- Atomic cert replacement via `replace_scanned()` (single transaction)
- `validate_chain_order` returns `None` for single-cert bundles (not `False`)

112 unit tests, 5 E2E tests, ruff clean.

---

## Tomorrow's experiment (the cross-stage validation)

Run cert-watch through a **fresh Socratic session** under the amended Step 5 (composition audit folded in). Predicted outcome: the three v0.1-era composition gaps (scheduler wiring, scan_history display, AlertConfig source) should be flagged **before synthesis** and either answered by the human or recorded as open questions.

- **Setup**: clean room, no priors from the existing wi_*.md files. Use a fresh vibe-spec equivalent to the original cert-watch prompt.
- **Reviewer**: use a different model from the elicitation AI (per debate 005's cross-model audit requirement). Suggested: opencode/Kimi K2.6 as the elicitor, DeepSeek v4-pro or Claude Sonnet as the composition-audit reviewer.
- **Pass condition**: at least 2 of 3 predicted gaps are surfaced as open questions in the resulting spec.
- **Fail condition**: composition gaps still missing → Step 5 needs more work; reopen debate 005 or open 006.
- **Output artifact**: `/projects/socratic-specification/experiments/2026-05-26-cert-watch-rerun.md` with the elicitation transcript, audit output, and gap-detection result.

---

## v0.4 backlog (deferred from v0.3)

In priority order:

1. **Auth** — explicitly out of scope for v1 spec but needed once the tool is network-accessible. Options: API keys for the REST API, basic auth for the UI, or OIDC integration.
2. **JKS support** — only if there's actual demand. Java keystores are heavy and would require a new dep (`pyjks`). Default no.
3. **Dashboard pagination** — `list_dashboard_rows` loads ALL certificates into Python memory. Fine at v1 volumes but degrades with scale. Add cursor-based pagination.
4. **Multi-host scheduler** — with replicas>1 the in-process scheduler would multi-fire. Extract to a separate Deployment or add leader election before scaling horizontally.
5. **Alert history cleanup** — old sent/failed alerts accumulate. Add a retention policy (e.g., delete alerts older than 90 days).

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
