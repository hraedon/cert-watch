# Alert routing: receipt evidence and offline inspection

Plan 050 qualification, based on `a181632d` (2026-09-12).

## Inspect a completed backup

```console
cert-watch routing-report /path/to/backup.sqlite3
cert-watch routing-report /path/to/backup.sqlite3 --format json
```

Input must be an offline, consolidated SQLite backup with this build's complete
migration history. The inspection runtime requires SQLite 3.37 or newer.
The command refuses WAL, SHM or journal companions, missing
files, incompatible schemas and observed changes while reading. It never creates,
migrates or repairs the source database. Backup acquisition is a separate step.
SQLite's [immutable URI](https://www.sqlite.org/uri.html) disables locking and
change detection; it is an assertion about a completed input, not a backup method.
A raw copy of a live [WAL database](https://www.sqlite.org/wal.html) may omit
committed data even if that copied file has no companions.

The report binds its input with SHA-256. Only allowlisted routing fields are read
into a disposable scratch database, where the existing matching and recipient
resolvers run. No credential columns, API keys, sessions or settings records are
queried or copied into scratch. The whole-file hash does read the input bytes.
Schema validation rejects views, virtual tables and generated routing columns
before querying rows; malformed scalar types are also refused. Scratch-only
repository fields use empty/synthetic values, and the temporary database and its
cached connection are removed on exit.

The output separates:

- **Group coverage:** matched certificate IDs, including groups matching nobody.
- **Multiple matches:** a leaf selected by more than one distinct group. A group
  reached through tags, manual assignment and a role link is counted once.
- **Specific recipients:** the group, owner and role-member address list from
  `resolve_cert_recipients`. Invalid addresses are flagged separately.
- **Orphans:** zero specific recipients. A matching group with no addresses can
  still leave a certificate orphaned; an owner-only route is not an orphan.

The report does not load global delivery configuration. Global SMTP recipients
are included on every actual email and may receive orphan alerts. Invalid
addresses are rejected at send time. SMTP is attempted first; the single global
webhook is used on failure or absence. Stored group webhook URLs do not trigger
independent sends here. Thresholds, renewed-host suppression, digest eligibility,
network reachability and mailbox outcomes are outside this report.

## What the receiver tests prove

The estate is synthetic and generated through the real certificate parser and
database repositories. The test drives `evaluate_all_certs` and `process_pending`,
then checks actual SMTP envelopes, message bodies and HTTP request paths.
It checks the entire receipt set, including absent recipients and paths.

The SMTP receiver uses [aiosmtpd](https://aiosmtpd.aio-libs.org/en/latest/controller.html)
as a development-only dependency. STARTTLS and implicit TLS, certificate/hostname
validation, AUTH and message receipt are real. A test-only socket-address redirect
maps configured ports 587 and 465 to ephemeral loopback listeners; it does not
replace smtplib, TLS negotiation, login or message sending. A synthetic test CA is
trusted for the successful path. Separate tests require rejection of wrong
credentials, an untrusted CA, a wrong hostname, plaintext credential delivery
and missing AUTH.

The routing matrix covers host/certificate tag union, Unicode and whitespace,
overlapping groups, manual assignments, role links, owner/team membership,
orphans, healthy/renewed exclusions, webhook fallback and durable retry identity.
SMTP receipt establishes local relay acceptance, not arrival in a production
mailbox. HTTP receipt establishes the selected local endpoint received a request,
not that a third-party provider processed it. The threaded event-stream path is
separate and is not claimed as covered by this matrix.

## Repeat the checks

```console
uv sync --frozen --extra dev --extra auth
.venv/bin/pytest -m integration -q --no-cov -n0 tests/test_alert_targets.py tests/test_alert_routing_matrix.py
.venv/bin/pytest -q --no-cov -n0 tests/test_routing_report.py
.venv/bin/ruff check .
.venv/bin/mypy src/cert_watch
```

The CI workflow explicitly enrolls both root-level receipt modules. The default
unit marker and the pre-existing integration job would otherwise exclude them.

## Qualification record (2026-09-12)

The pre-change Python 3.14 unit baseline passed 2,723 tests with one optional
Patina checkout skip and 91.00% total coverage. Its separate LDAP module floor
was already below the 90% requirement (89.26%). Final qualification therefore
uses Python 3.13, matching CI; no LDAP source or coverage floor was changed.

The frozen development dependency audit initially reported five newly published
advisories against the existing HTTPX2/httpcore2 2.5.0 pair. The development-only
HTTPX2 floor and both locked versions are now 2.12.0; the updated audit reports
no known vulnerabilities. HTTPX2 requires its matching core version.
See the [upstream release](https://github.com/pydantic/httpx2/releases/tag/v2.12.0).
No application runtime dependency changed. The universal lock also records
HTTPX2's Emscripten-only transport; it is not installed on Linux or Windows.

The 21 local receipt tests passed on both Python 3.14 and Python 3.13. Six
separate process-local fault injections each made the intended assertion fail:

| Deliberate fault | Observed failure |
| --- | --- |
| Accept the wrong SMTP password | Expected authentication refusal instead delivered |
| Disable CA validation | Expected untrusted-certificate refusal instead delivered |
| Disable hostname validation | Expected hostname refusal instead delivered |
| Remove the global recipient | Exact receiver ledger missed the expected address |
| Add an unrelated recipient | Exact receiver ledger contained an unexpected address |
| Send one alert twice | Receiver accepted nine messages where eight were expected |

The routing mutations retained successful application sent-counts, so the
receiver assertions supplied independent evidence. Normal processes passed
again after the mutations; no production source file was altered for injection.

Independent review reproduced and corrected generated/virtual-schema bypasses
and malformed BLOB/NULL routing values. Their regressions failed before the
fix, then passed with the complete 28-case report suite on Python 3.13.
On Windows 11, Python 3.13.15 and SQLite 3.50.4, all 28 report tests and 21 receipt
tests passed with zero skips, using the final frozen dependency set. This covers
Windows URI filenames, source preservation and scratch-connection cleanup.
Repository-wide Ruff, strict mypy (150 source files), template lint (24 files)
and the updated dependency audit passed on Linux. The focused non-UI environments
warn about two unrecognized Playwright configuration options; no case is skipped
for those warnings. Full unit coverage, module floors, browser and deployment
results are attached to the pull request's checks for its exact revision.

## Remaining operator evidence

No production database or recipient is used by these tests. The final Plan 050
acceptance step remains: acquire a proper real-estate backup, run the diagnostic,
and have its owner review the expected recipients, gaps and multiple matches.
Synthetic agreement and a green CI run cannot supply that judgment.
