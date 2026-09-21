# Plan 056: Defensible maintenance and a replaceable presentation layer

Authorized by the operator on 2026-09-21 after a cross-project review of
cert-watch, adcs-lens and acme-adcs-ra. Two motivations, one bounded plan.

The first is remediation. cert-watch has the most sophisticated pipeline of the
three and the most internal decay behind it. The gaps are specific and measured,
not impressions, and each one below carries the measurement that found it.

The second is replaceability. The presentation layer should be straightforward to
tweak, restyle, or replace outright. Today it is not — not because the templates
are bad, but because there is no seam: routes build view context inline, both
route families reach past the repositories into raw SQL, and the HTTP API that
looks like a substitution point is a parallel implementation that no UI calls.

1. Make the linters tell the truth. The explicit rule list is narrower than
   Ruff's own default, so 31 of 42 suppressions in `src/` suppress nothing.
2. Write the adversary down. This is the only one of the three projects that is
   an internet-facing web application, and the only one with no threat model.
3. Prove the Windows Event Log sink. It is a documented shipped feature whose
   real dependency is installed nowhere — not in CI, not by the installer.
4. Pay down the structural coupling, with ratchets rather than a rewrite: five
   real import cycles, 278 deferred imports, and 87 data-access sites that
   bypass the repositories.
5. Build the presentation seam, and prove it by crossing it.

Deferred-import cleanup, the service layer and the presenter layer are
intentional and touch many files. Existing auth/session/CSRF defaults, the
visual design, the patina version, RBAC semantics, runtime dependencies, deploy
manifests and public response contracts remain outside this change.

## What "defensible" means here

The operator's calibration: defensible, not parity with acme-adcs-ra. That
project is issuance-path infrastructure and carries an issuance-path regime —
a three-version Python matrix, twelve dated security review documents, an
exact-pinned test framework. cert-watch does not need that.

The bar adopted instead: **every quality claim is backed by a mechanical check
or a written decision, and nothing rests on recollection.** A suppression that
suppresses nothing fails this bar. A guarantee about a shipped feature whose
dependency is never installed fails it. A "replaceable UI" that nothing has ever
replaced fails it.

Taken from acme-adcs-ra because it is cheap and closes a real gap: proving that
platform-gated imports resolve (§3). Deliberately not taken: the Python version
matrix (cert-watch ships as a pinned container image), per-review security
documents (one living threat model instead, §2), and exact-pinning every tool
(`uv.lock` and `uv sync --frozen` already give determinism).

## 1 — Make the linters tell the truth

`[tool.ruff.lint] select = ["E", "F", "I", "B", "UP", "SIM"]` was written as
rigor and now acts as a freeze: it excludes the `RUF` linter, which is in Ruff
0.16's default set. Measured consequence — `ruff check --select "E,F,I,B,UP,SIM,RUF100" src/cert_watch`
reports **31 unused `noqa` directives**, all of them `non-enabled`. Five sit on
swallowed exceptions:

```python
except Exception:  # noqa: BLE001 — TLS probe; failure must not crash settings save
    pass
```

`BLE` is not selected, so that line reads as a reviewed and accepted exception
while suppressing nothing. The sibling projects, which set no explicit `select`
at all, inherit the broader modern default and do get `RUF100`.

- Add `RUF` to the select list, then remove the 31 dead directives.
- For the five blind excepts, make a real decision per site rather than a bulk
  edit: enable `BLE` and keep a justified `noqa`, or convert to
  `contextlib.suppress` where the intent is genuinely best-effort.
  `upload.py:244` carries no justification at all and needs one or a fix.
- Add complexity rules (`C901`, `PLR0912`, `PLR0915`) configured at the current
  worst values, as a ratchet that only tightens. This is the idiom
  `tests/test_module_coverage_floors.py` already established for coverage; it
  was never applied to structure, and 59 of 954 functions now exceed 80 lines,
  the largest being `certificate_detail` at 376.
- Record in `pyproject.toml` why the select list is explicit and that it must be
  reviewed against Ruff's default on each upgrade, so the freeze cannot recur.

Small; a few hours. Do it first — it changes what every later step is measured by.

## 2 — Write the adversary down

cert-watch has authentication, API keys, LDAP and OAuth providers, an SSRF
allowlist, audit logging and SIEM export. It has 57 plans and 122 reflections. It
has no threat model and no `SECURITY.md`. Both quieter, less exposed siblings
have both.

- `docs/threat-model.md`: trust boundaries (browser, API client, scan target,
  SMTP/webhook sink, SIEM sink, LDAP/OAuth provider), the assets, the assumed
  adversary, and what is explicitly out of scope. Name the controls that already
  exist — the SSRF allowlist and its test, CSRF defaults, scoped tags, API-key
  handling — so this documents reality rather than aspiration.
- `SECURITY.md`: supported versions and a private reporting channel.
- A written rule for when a security review is required (a change touching auth,
  the allowlist, key handling, or an external sink), rather than a standing
  cadence. One living threat model, revised in the PR that invalidates it.

Small; about a day. The highest defensibility return in the plan.

## 3 — Prove the Windows Event Log sink

The README lists the Windows Event Log as a SIEM target. `siem.py` binds it
through `import win32evtlog` / `win32evtlogutil` behind the `cert-watch[windows]`
extra. That extra is installed **nowhere**: not in `ci.yml`, not in the
`windows` job of `deploy-smoke.yml`, not by `scripts/install-windows.ps1`. The
tests in `tests/test_siem.py` cover syslog and HEC; the Event Log binding's real
import path has never run.

The Windows deploy-smoke job already exists and does good work — it installs the
IIS Application Initialization prerequisite rather than weakening the production
preflight, and parses both PowerShell scripts under Windows PowerShell 5.1
because that is the production shell. Add two lines to it:

```powershell
uv pip install -e ".[windows]"
python -c "import cert_watch.siem, win32evtlog, win32evtlogutil; print('eventlog imports: OK')"
```

Then decide whether the installer should offer the extra when the operator
selects Event Log export, or whether the feature is documented as requiring a
manual install. Either is defensible; silence is not.

Very small. This is the one acme-adcs-ra practice worth importing wholesale.

## 4 — Pay down the structural coupling

Three measurements, all from the module graph and the source tree:

- **278 deferred intra-package imports across 62 of 154 modules** (the siblings
  have 2 and 3). Only 17 carry any comment.
- **Five real import cycles**, masked by those deferrals. With every import
  hoisted to module level: `config.kv_loader ↔ config.settings`,
  `routes.settings ↔ routes.settings.auth`, `alerts ↔ alert_delivery`,
  `alerts ↔ alert_adapters`, `scheduler ↔ scan_freshness`. At module-import time
  today there are zero cycles, so this is latent, not breaking.
- **87 of 319 non-migration data-access sites bypass the repositories** — 32 raw
  `conn.execute` calls across 10 route modules and 55 across 12 domain modules.
  `certificate_detail` constructs `SqliteCertificateRepository` and then queries
  `scan_history` and `certificates` directly a few lines later.

Five cycles do not justify 278 deferrals; the rest are habit. The work is
incremental and must not become a rewrite:

- Break the five cycles by moving the shared types or the direction of
  dependency — `alerts ↔ alert_delivery` and `alerts ↔ alert_adapters` are the
  same shape and likely one extraction.
- Hoist deferred imports to module level wherever no cycle requires deferral.
  Where one does, keep it and say so in a comment naming the cycle.
- Add `tests/test_import_hygiene.py` holding two ratchets, in the coverage-floor
  idiom: a ceiling on deferred intra-package imports, and a ceiling on raw SQL
  outside `database/` and `migrations/`. Both start at the current counts and
  only move down. This stops the bleeding on day one even though the cleanup
  takes weeks, and it is what makes §5 affordable.

## 5 — The presentation seam

This is the part the operator asked for, and the finding underneath it is the
one that matters: **the seam that should exist already appears to exist, and
does not hold.**

`routes/api/` is 1956 lines across 11 modules and looks like the substitution
point a replacement UI would build against. It is not one:

- Six endpoints in `UI-INVENTORY.md` are annotated **(no UI caller)** —
  `PUT /api/certificates/{id}/tags`, `PATCH /api/hosts/{id}/owner`,
  `PUT /api/hosts/{id}/tags` among them. Each duplicates a write the HTML UI
  performs through a different endpoint. A parallel implementation that nothing
  exercises is not a seam; it is a second place for the same rule to drift.
- Five `/api/` endpoints are defined **outside** `routes/api/` — in
  `certificates.py`, `hosts.py`, `audit.py`, `health.py` and `dashboard.py` — so
  the API is not even a coherent module boundary.
- Several UI mutations have **no** API equivalent at all (upload, trust anchors,
  certificate delete), so a replacement UI could not perform them.
- There is no service layer. Route modules import from `cert_watch.database`
  directly 30 times and build template context inline; `certificate_detail` is 376 lines
  of exactly that.
- Templates carry the other half: `certificate_detail.html` has 92 control-flow
  tags in 562 lines, `dashboard.html` 81 in 456.
- patina's `structure` facet is `deferred` in `patina.toml` — "no surface briefs
  written" — so nothing records what each page is *for*.

Design tokens are the part that is already right: `tokens.css`, the patina
vendor and contract facets enforced, and `UI-INVENTORY.md` as a content-model
contract with a review gate. Restyling is genuinely easy today. Replacing the
*structure* is not.

The target, in order:

**5a — One write path per concept.** Work `UI-INVENTORY.md` top to bottom and
resolve each **(no UI caller)** endpoint: promote it to the single path the UI
also uses, or delete it. Close V4 (owner edits on a certificate-namespaced
endpoint) and V5 (add-host accepts fields the drawer never offers) in the same
pass. The inventory already names them; this plan commits to finishing them.

**5b — An application service layer.** A `services/` package whose functions take
validated inputs and return domain results, owning the transaction and the audit
write. Both `routes/` and `routes/api/` delegate; neither touches a repository or
raw SQL directly. Start with the concepts in 5a rather than all at once — tags,
owner, notes, scan-now, delete, upload — because those are where the duplication
already is.

**5c — Presenters.** A typed view model per page, built from service results, and
a template that renders it without reaching further. `certificate_detail` becomes
a thin route plus a presenter, and the presenter is unit-testable without an HTTP
client. This is the single change that makes a different template set — or a JSON
serializer for a different front end — a swap at one place.

**5d — Consolidate the API surface.** Move the five stray `/api/` endpoints into
`routes/api/`. Pre-1.0 (0.9.5 today) is the moment for this; after 1.0 it is a
compatibility event.

**5e — Surface briefs.** One per domain page, saying what the surface is for and
what it must show. This closes patina's deferred `structure` facet, which is
currently waiting on exactly this work.

**5f — Prove the seam by crossing it.** A claim of replaceability that nothing
has tested is the failure this plan is named against. Two mechanical proofs:

- A contract test asserting that every concept in `UI-INVENTORY.md` maps to
  exactly one service function, and that both the HTML route and the API route
  for that concept reach it. The inventory becomes executable rather than
  advisory.
- An API-completeness test: every mutating UI action has an API equivalent. This
  is the property that makes a replacement UI *possible*, stated as a check
  rather than an intention.

Full replacement — an SPA, a second template set — is **not** a goal of this
plan and is not required to land it. The goal is that the seam exists, is
singular, and is exercised from both sides. If a replacement is later wanted,
the existing e2e and visual-regression suites are the regression net for it.

## Sequencing

§1 and §3 are hours and unblock measurement; do them together in one PR. §2 is
about a day and is independent. §4's ratchets land next and are cheap; the
cleanup behind them proceeds incrementally and need not complete before §5
starts. §5 is the substantial work: 5a and 5d before 1.0 because they change
endpoints, 5b/5c incrementally per concept, 5e and 5f as they are earned.

Branch per workstream. §4's ratchets and §5f's contract tests are the parts that
survive the plan — everything else is a one-time payment.

## Qualification

Each workstream qualifies on: the full unit suite and coverage floors, the new
ratchets at their committed values, Ruff/mypy/template lint, and the browser
suite for anything touching §5. §3 qualifies on the Windows deploy-smoke job
reporting the import check, not on a local run. §5f qualifies on the contract and
completeness tests failing when a write path is duplicated or an API equivalent
is missing — verified by introducing both faults deliberately before trusting
the tests.

This plan does not claim that the UI has been replaced, that a second front end
exists, or that the service layer is complete when the first concepts land. It
does not claim the structural cleanup in §4 is finished when its ratchets are
committed; the ratchets bound the problem, they do not solve it. The threat model
in §2 records the controls that exist and the adversary assumed — it is not an
external security assessment and should not be cited as one.
