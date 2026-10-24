# AGENTS.md

Notes for coding agents working on cert-watch. The rules in
[CONTRIBUTING.md](CONTRIBUTING.md) apply to you in full. This file adds only
what is specific to agents.

## Orient

1. Read [CONTRIBUTING.md](CONTRIBUTING.md), then
   [docs/architecture.md](docs/architecture.md).
2. Check open pull requests and recent `main` history before starting. Other
   agents work on this repository too. Fetch before you push, and read the
   push output: a rejected push is easy to miss.
3. This repository is **public**. Stage files by explicit path. Keep reviewer
   scratch directories (`.review/`) out of commits. Don't put private host
   names, credentials or work-domain identifiers in code, docs or commit
   messages. The identifier gate catches some of this, not all of it.

## Breadcrumbs

The project is registered with agent-notes (use the repository's checkout path). Use
the `agent-notes` CLI or the breadcrumb skills, and search before filing. Don't
create breadcrumb files in the tree. Historical plans and session reflections
are archived; see [docs/history.md](docs/history.md).

## Seeing the UI

A Playwright MCP server is configured in `.mcp.json`. Use it to look at the
running app: navigate, click through a flow, take screenshots. Use it to *see*
a change before committing, and the e2e suite to *lock it in*.

## Test estate

Validation that fixtures cannot stand in for (real certificates, tags, routing, AD LDAP login, scheduler behavior across reboots) needs a live instance on a Windows/IIS host joined to an Active Directory test domain. The host should:

- run cert-watch under IIS via HttpPlatformHandler, installed with `scripts/install-windows.ps1` (see `deploy/iis/README.md`), including the Application Initialization role service and `preloadEnabled=true` so scanning survives recycles and reboots;
- authenticate against the test domain over LDAPS with a dedicated bind account;
- be allowed to scan private addresses (`CERT_WATCH_ALLOW_PRIVATE_IPS=1`) and be seeded with a dozen real hosts: domain controllers on :636, public ACME-issued sites on :443, and a Kubernetes API endpoint.

Operator notes: the remote shell is PowerShell, so pipe multi-line Python to `python.exe -` over stdin instead of using `python -c`. Never read the instance's `secrets\` directory. Treat the seeded data as read-only unless intentionally repopulating it, and do not mutate a production instance without a reason. Site-specific hostnames, credentials and incident history belong in private operator notes, not in this repository.

## Releasing

The git tag sets the version. At build time the release workflow stamps
`src/cert_watch/_version.txt` from `GIT_TAG`; the committed file is the
fallback when running from a checkout. To release:

1. Set the version in `pyproject.toml` and `_version.txt`.
2. Update `CHANGELOG.md` and `UPGRADING.md`.
3. Merge, then push a `vX.Y.Z` tag.

The workflow refuses a tag that doesn't match `pyproject.toml`. Releases are
the maintainer's call.
