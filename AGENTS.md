# AGENTS.md

Conventions and quick reference for agents (and humans) working on cert-watch.

## Why this project exists

cert-watch is a "traditional"-build comparison point for [software-factory-2](https://github.com/hraedon/software-factory-2). Same MVP spec; hand-rolled (or single-shot agent-built) instead of factory-orchestrated. The repo at `hraedon/cert-watch-factory-failed` is the prior factory attempt — kept for comparison, not for reuse.

## Orient

1. **Read the spec.** `docs/spec/wi_*.md` — one file per FR or interface module, with explicit acceptance criteria. The spec is the contract.
2. **Read the scaffold.** `src/cert_watch/` — `app.py` (FastAPI), `templates/`, `static/`, plus stub modules: `certificate_model.py`, `cert_chain.py`, `database.py`, `scan.py`, `upload.py`, `alerts.py`, `scheduler.py`. Each stub names its corresponding spec file.
3. **Note the deploy story.** See `deploy/` (k8s + Argo CD, docker compose, systemd). Argo CD watches `deploy/k8s/`; CI bumps the image tag there on every merge to `main`. Do not commit changes to `deploy/k8s/kustomization.yaml` in feature PRs.

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q            # unit tests
.venv/bin/ruff check .         # lint
uv pip install -e ".[e2e]" && .venv/bin/playwright install --with-deps chromium
.venv/bin/pytest -m e2e tests/e2e -q   # opt-in E2E
```

E2E tests on the dev host need `libatk-1.0-0t64 libatk-bridge-2.0-0t64 libcups2t64 libxcomposite1 libxdamage1 libxrandr2 libgtk-3-0t64 libasound2t64` (one-time sudo install). CI handles this via `playwright install --with-deps`.

## Conventions

- **Single SQLite file** at `${CERT_WATCH_DATA_DIR}/cert-watch.sqlite3` (default `/var/lib/cert-watch`). Deployment is single-writer; `Recreate` rollout strategy in k8s.
- **PKCS#12 (`.pfx`) support extends the original spec** — use `cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates`.
- **No auth in v1.** Stated requirement; do not add login flows.
- **Empty-state must not error.** The dashboard renders an "empty state" message when no certificates exist.
- **Don't add features beyond the spec.** Acceptance criteria are the boundary.

## Breadcrumbs / memory

Project is registered with agent-notes (postgres-backed). Use the `mcp__breadcrumb__*` / `mcp__memory__*` / `mcp__search__*` tools from Claude Code; resolves via path `/projects/cert-watch`. Local mirror directories: `breadcrumbs/active/`, `breadcrumbs/resolved/`, `plans/`, `reflections/`.

## CI workflows

- `ci.yml` — ruff + pytest (unit) on every push/PR
- `e2e.yml` — Playwright E2E on every push/PR
- `release.yml` — on `main`: multi-arch image build → GHCR → commit kustomize tag bump (skips itself via `paths-ignore`)
