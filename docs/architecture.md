# Architecture

cert-watch is a FastAPI application with a background scheduler, backed by one
SQLite file. This page describes how the code is organised and the few rules
that keep it that way. [CONTRIBUTING.md](../CONTRIBUTING.md) lists the rules
as a checklist; this page explains them.

## Layers

```
routes/, routes/api/          HTTP adapters: parse, guard, call a service or presenter, render
presenters/                   page view models, built from service results; no HTTP, no SQL
services/                     one function per operation: validate, authorize, transact, audit
alerting/                     alert rules, routing, dispatch, transports, digests
scan*.py, cert_chain.py,      acquiring certificates and judging them
posture.py, policy*.py
database/, migrations/        all SQL; schema history
config/                       settings: one table, one loader, one runtime snapshot
auth/, security/              identity, sessions, guards, CSRF, rate limiting, headers
```

Calls go downward: routes call presenters and services; services call the
domain modules and `database/`; nothing below `routes/` imports FastAPI or
Starlette. `tests/test_alerting_layering.py` enforces the direction for the
alerting package. Elsewhere it is a convention that reviewers check.

### Routes are adapters

Every page and endpoint does four things: authenticate and authorise through
exactly one guard from `auth/guards.py`, turn the request into typed inputs,
call one service (for a change) or build one presenter (for a page), and turn
the result into a response. The HTML route and the JSON route for the same
operation call the same service. `UI-INVENTORY.md` lists those pairs, and
`tests/test_ui_inventory_contract.py` proves both reach the service.

Because the JSON API covers every operation the UI performs
(`tests/test_api_completeness.py`), it is a complete seam: a different front
end could be built on it without touching anything below `routes/`.

### Services own the rules

A service function takes validated inputs and the acting user (`auth=`, a
required keyword; `None` is refused). It checks tag scope and permissions
*inside* the write lock, performs the change in one transaction, and records
the audit row in that transaction. SIEM export happens after the commit,
outside the lock. Scheduler and CLI code that acts without a user passes the
explicit system principal.

### Presenters shape pages

A presenter turns service results into a typed view model for one page: labels,
counts, tones, grouping. Templates render the view model and keep only
presentational conditionals. Presenters are unit-tested without an HTTP client,
and `tests/golden/pages/` pins the rendered HTML of every page for a seeded
estate.

## The data

`database/` holds all SQL. Most of it is plain functions over a connection;
`alert_store.py` owns the alert lifecycle. Connections are cached per thread,
and a process-wide re-entrant lock serialises writes. SQLite in WAL mode lets
readers carry on during a write.

The schema is defined only by the numbered migrations in `migrations/`,
starting from the 0001 baseline. Each migration and its version row commit
together. A cross-process lock serialises startup, so two processes starting
at once can't both migrate. Before any migration runs, the database is backed
up. `tests/test_schema_migration_invariants.py` compares a fresh schema with
one upgraded from real historical versions.

## Configuration

`config/field_specs.py` declares every setting once: environment names,
optional database key for settings editable in the UI, parser, default,
bounds, sensitivity. `config/loader.py` resolves them all with one precedence
rule. The resolved `Settings` object is published as a runtime snapshot.
Saving a setting in the UI bumps a generation counter, so a rebuild that
raced a save can't publish stale values. The operator reference is generated
from the same table (`scripts/gen_config_reference.py`).

## Scanning

A scan connects to a host, directly or with STARTTLS, and reads the certificate
chain; `openssl s_client` handles protocols Python can't. It then:

1. validates the chain against the system trust store and any uploaded anchors;
2. grades posture;
3. applies the policy rules.

The result is stored in one transaction, which also records history and
events and evaluates drift and policy alerts. Network work happens before the
transaction, and webhooks after it. The scanning allowlist (`host_validation.py`,
`http_client.py`) is applied before any connection, and again at every
redirect for outbound HTTP.

## Alerting

`alerting/` is layered in one direction:

`model` → `messages` → `routing` → `rules` → `dispatch` → `transports` → `digest`

- **Rules** create alerts. Each alert type has one dedupe key, built from the
  certificate fingerprint, and a partial unique index keeps at most one open
  alert per key.
- **Routing** is resolved when an alert is created and stored with it.
- **Dispatch** claims due alerts atomically under a lease, sends them, and
  records every attempt in the append-only delivery ledger. It then completes
  each alert as sent, backs it off (1 h, 4 h, 12 h), or gives up after 12
  attempts.
- **Transports** (SMTP and the webhook adapters) return a `SendResult`; they
  never touch the alert.

[alerting.md](alerting.md) describes the behaviour operators see.

## The scheduler

A single thread runs the daily cycle: scan what is due, evaluate alert rules,
deliver, send digests, purge by retention. Each phase is isolated, so one
failure doesn't stop the rest. The cycle holds a lock that the manual *flush*
action also respects. Alert claims make double delivery impossible even
without it. Shutdown cancels queued work rather than draining it.

## Security boundaries

[threat-model.md](threat-model.md) lists the assets, the adversaries and the
controls. In code, the boundaries are:

- **Guards** (`auth/guards.py`) decide who may call a route.
- **Services** decide what they may touch.
- **The scanning allowlist** decides what cert-watch may connect to.
- **CSRF, security headers and rate limits** live in `security/`.
- **Sessions** are signed, versioned per user, and revoked on account changes.
