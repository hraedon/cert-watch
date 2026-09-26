# Contributing to cert-watch

This page is for anyone changing the code, people and coding agents alike.
[docs/architecture.md](docs/architecture.md) explains how the code is laid
out. [AGENTS.md](AGENTS.md) adds a few notes that only matter to coding agents.

## Setting up

```bash
uv venv && uv pip install -e ".[dev,auth]"
.venv/bin/pytest -q                       # unit tests, in parallel, about a minute
.venv/bin/ruff check .
.venv/bin/mypy src/cert_watch
.venv/bin/python -m cert_watch --host 127.0.0.1   # http://localhost:8000, opens /setup
```

`uv.lock` pins every dependency, and CI installs from it. A bare
`pip install -e .` re-resolves and may pull newer versions than CI tests.

Other suites run on request:

```bash
uv pip install -e ".[e2e]" && .venv/bin/playwright install chromium
.venv/bin/pytest -m e2e tests/e2e -q --no-cov -n0      # browser tests
.venv/bin/pytest -m integration -q                     # needs a real openssl binary
```

Run the browser suite locally after any change to templates, CSS or page
routes. The default run leaves it out.

## What CI checks

Every pull request runs:

- ruff, mypy (strict) and djlint;
- the unit suite with a coverage floor, plus per-module floors that only move
  up;
- the browser suite, including visual comparison against committed
  screenshots;
- LDAP tests against a real directory container;
- deployment smoke tests for the container, Kubernetes, the Linux entrypoint
  and Windows (install script, IIS prerequisites, the Event Log sink);
- the identifier gate, which keeps work-domain identifiers out of this public
  repository.

A release tag publishes a signed, attested multi-architecture image, but only
after the same checks pass on that exact commit.

Several tests are ratchets. They pin a number (coverage per module, complexity
limits) or a rule, and the only way to change the number is to make things
better. They fail loudly by design. Don't loosen one to get a change through;
fix what it found.

## Rules that protect users

These came out of real incidents. Each one is enforced by a test or a review
check.

- **Every route has exactly one guard** from `auth/guards.py`. Write guards
  always include CSRF. `tests/test_route_guards.py` fails on a mutating route
  without one.
- **Services own authorization.** A service that changes data takes the
  acting user as `auth=`, checks tag scope inside the write lock, and refuses a
  missing principal. System callers (the scheduler, the CLI) pass the system
  principal explicitly.
- **The authorization matrix is golden.** `tests/fixtures/authz_matrix.json`
  records who may do what on every mutating route. A change to an existing
  cell must be intentional and called out in the PR.
- **The write lock covers database work only, never network I/O.** Scans,
  SMTP, webhooks and SIEM export happen outside it. A slow relay must not stall
  every writer.
- **Every alert state change goes through `database/alert_store.py`.**
  Delivery claims an alert before sending it. That is what stops two
  processes, or a flush racing the scheduler, from paging someone twice.
- **Schema changes are migrations.** Each migration commits atomically with
  its version row and must not commit or run `executescript` itself. The
  fresh-versus-upgraded schema test must stay green.
- **Every setting is declared once**, in `config/field_specs.py`, with a
  description in `config/field_docs.py`. Then run
  `python scripts/gen_config_reference.py`. The configuration reference is
  generated, and a test fails if it is stale.
- **Every UI write has one service and a JSON equivalent.** The contracts are
  listed in `UI-INVENTORY.md` and checked by
  `tests/test_ui_inventory_contract.py` and `tests/test_api_completeness.py`.
- **Fail closed.** When something that guards access can't be read (a role
  mapping, a secret file, a session in an old format), cert-watch refuses or
  degrades to the least privilege. It never falls back to open.

## When you change the UI

Each of these bugs shipped once, past a green suite:

- Look at every page you changed with data and empty, in light and dark theme.
  `tests/e2e/_seed.py <data_dir>` seeds a realistic estate.
- Read the words on the screen: pluralisation, doubled prefixes, raw ISO
  timestamps.
- A zero is not an alarm. "Failures 0" renders neutral, not red.
- `static/css/tokens.css` is vendored from the patina design system. Never
  edit it here; component styles and local tokens live in `cw.css`. Check that
  a utility class exists before relying on it.
- Colour means status, and only status: crit for expired, 7 days or less and
  failing delivery; warn for 8–30 days and failing monitoring; ok for current.
  Expired is crit plus the word "Expired". Links, focus rings and active states
  are neutral ink (links get a hairline underline), never a status colour or
  the patina accent.
- One type scale: 12, 14, 16, 20 and 28 px (`--cw-fs-xs` to `--cw-fs-xl` in
  `cw.css`). Monospace is for hostnames, serials, fingerprints and other
  machine syntax such as raw errors, identifiers, API paths and headers,
  and report hashes; chips, labels, dates and counts are sans.
- If you add, move or remove an editing control, update `UI-INVENTORY.md` in
  the same pull request.
- Visual baselines match GitHub's `ubuntu-latest` rendering. Regenerate them
  with `scripts/update-visual-baselines.sh`, not from a local machine.

## Tests

- **A test you have never seen fail is a rumour.** Break the code once and
  watch the new test catch it. Bug fixes land with a regression test that
  fails without the fix.
- **Skipped is invisible.** Check the skip count as well as the failures.
  Docker-, LDAP- and Playwright-dependent tests skip quietly when their
  dependency is missing.
- **Say what you didn't verify.** A pull request that couldn't exercise
  something, such as a real directory, a real Windows host or a real mail
  relay, says so.

## Review

Every pull request gets an independent review before it merges. Changes that
touch authentication, authorization, sessions, CSRF, secret handling, the
scanning allowlist or an outbound integration get **two** independent
reviewers, at least one of whom runs probes against the change rather than
only reading it. Merge only on green CI.

## Decisions for the maintainer

Implementation choices are yours. These need the maintainer's agreement
before they merge, because their consequences are ones the tests can't see:

- new runtime dependencies;
- changes to authentication, session or CSRF defaults, or other security
  posture;
- changes to public API paths or response shapes, and to audit action names;
- removing a user-facing feature;
- releases.

Schema migrations need a note in [UPGRADING.md](UPGRADING.md), and every
operator-visible change needs a line in [CHANGELOG.md](CHANGELOG.md).

## Platform notes

- **PowerShell scripts must run on Windows PowerShell 5.1**, which reads files
  without a byte-order mark as the ANSI code page. Keep scripts ASCII, and
  don't put single quotes inside double-quoted strings. The Windows smoke job
  parses both installer scripts under 5.1.
- **IIS needs Application Initialization and `preloadEnabled`.** Without them
  the process starts only on the first request, and the scheduler silently
  never runs. The installer checks this; keep it that way.
- **SQLite is single-writer by design.** Don't add anything that assumes two
  live application processes.
