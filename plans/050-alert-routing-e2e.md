# Plan 050 — Alert-system E2E: routing-matrix coverage + real-estate dry-run

**Status:** proposed 2026-06-18
**Author:** Opus 4.8 (session with user)
**Strategic role:** Close the gap the 2026-06-17 reflection named as the biggest
unknown — *nothing validates alert **routing** against a realistic estate.* Every
routing/tag test today uses synthetic, well-formed tags. Build the hermetic
in-CI coverage that proves the routing matrix (which cert → which group → which
recipient/channel, including the negatives), and add a read-only dry-run that can
answer the same question against the *real* estate without delivering anything.

## Ground truth at time of writing

- **The gap:** `test_alerts_integration.py` proves "one webhook delivers, payload
  is right." Nothing proves the *fan-out matrix*: a cert matching 2+ groups, 0
  groups, or messy/Unicode tags, and *who correctly received nothing.*
- **Infra that already exists (build on it, don't reinvent):**
  - `tests/_integration_servers.py` — `HTTPTestServer` records `router.requests`;
    `https_server`; `allow_loopback_transport` monkeypatch (flips the SSRF
    blocklist to permit loopback for tests).
  - `tests/e2e/_seed.py` — deterministic demo-estate seeder (also runnable
    standalone).
  - `e2e.yml` (functional / ldap / visual jobs); `integration` marker for
    opt-in tests needing external tooling.
- **Two delivery paths — know which one routes:**
  - `alerts.send_alert` / `alerts.send_webhook` — **synchronous**; reached via
    `alerts.evaluate_all_certs` / `evaluate_thresholds`. **This is where
    cert→group→recipient routing lives.** Start here.
  - `events._deliver_webhook` — **threaded** (`_get_pool().submit`); the
    event-stream firehose. Covering it requires flushing the pool before
    asserting (determinism).
- **Decisions already made this session (don't relitigate):**
  - In-process sinks only. No external alert targets in the routing loop — they
    add flakiness and zero routing fidelity (see "real targets" discussion).
  - The SMTP sink **must speak TLS + AUTH**, because that's the only place
    "real" mattered (`alerts.py` navigates `SMTP_SSL` on 465 / `negotiate_starttls`
    / `s.login`). A plaintext sink tests none of it.
  - **No `mock-infra` project.** cert-watch is the sole consumer; siblings need
    *different* mocks (ACME/`certsrv`) or AD fixtures, not these. Vendor a single
    file; copy it if a second tool ever reaches for it.
  - Tier-2 (real estate) is a **read-only dry-run report**, not a CI gate, built
    on the existing `alert_groups._match_preview` matcher.

---

## Phase 1 — Mock targets: the delivery oracle (`tests/_mock_targets.py`)

One new, dependency-light, vendored file. The "did it arrive, and *where*" oracle.

### WI-1.1 — Multi-endpoint capturing HTTP sink
- Extend the `HTTPTestServer` pattern so a single server exposes **distinct paths
  per recipient/group** and records `(path, method, headers, body)` keyed by path.
  The routing test needs to assert *which group's* recipient URL was hit, not just
  "a webhook fired."
- Reuse `allow_loopback_transport` so the SSRF guard permits the loopback sinks.
- **AC:** a test can register N recipient URLs, fire alerts, and read back a
  per-URL list of received payloads; unmatched URLs show empty.

### WI-1.2 — TLS + AUTH in-process SMTP sink
- Add `aiosmtpd` to the `dev` extra. In-process `Controller` configured with a
  **self-signed cert** (mint via `cryptography`, or reuse the e2e TOFU-CA helper
  from Plan 037) and an **auth callback**, capturing envelope + body in memory.
- Must exercise the real branches: STARTTLS negotiation on 587 *and* `SMTP_SSL`
  on 465, plus `s.login()`.
- **AC:** sending through `alerts.send_alert` against the sink succeeds over TLS,
  the captured message has the right recipients/subject/body, and a test that
  forces a bad login observes the auth failure (not a silent pass).
- **Skip-watch:** if `aiosmtpd` is absent the tests must *fail loudly or be
  provably run in CI* — "skipped is invisible." Do not `importorskip` into
  silence on the CI path.

### WI-1.3 — Adversarial estate factory
- Seed certs **directly via `database.repo`** (not by scanning — scanning real
  hosts is the wrong dependency for routing logic). Build a deliberately messy
  population as a fixture/factory:
  - a cert matching **2+ groups** (dup vs single? — pin the intended behavior)
  - a cert matching **0 groups** (the orphan — assert who is/ isn't alerted)
  - **cert-tag vs host-tag union** seam (matcher unions them)
  - a **Unicode/casefold** pair (`Straßen` cert vs `STRASSE` group) — drives the
    `cw_casefold` path end to end (the WI-066 fix)
  - whitespace / case / duplicate junk tags; overlapping group `match_tags`
- **AC:** factory produces a named, documented estate; each adversarial case is
  individually addressable so a failing assertion names the scenario.

---

## Phase 2 — The routing-matrix test (`tests/test_alert_routing_matrix.py`)

### WI-2.1 — Assert the full matrix, including the negatives
- Drive the real evaluate→deliver path (`evaluate_all_certs` →
  `send_alert`/`send_webhook`) with the WI-1.3 estate pointed at the WI-1.1/1.2
  sinks.
- Assert, per seeded cert: **exactly** the expected recipients/channels received
  **exactly** the expected alerts — and the negatives: orphan dropped, no
  cross-delivery between groups, no duplicate to a multi-match cert, casefold
  match delivered.
- Mark `integration`. **Break-and-watch every assertion once** (mis-tag a cert,
  watch the matrix test catch it) before merging — a green matrix nobody has seen
  fail is a rumor.
- **AC:** test passes on `main`; each negative assertion demonstrably fails when
  the corresponding routing rule is perturbed.

### WI-2.2 — Event-path determinism (only if covering `events._deliver_webhook`)
- If the matrix also exercises the threaded event-stream path, add a deterministic
  flush (join/drain `_get_pool()`) before asserting. The recovery-commit change
  (mark `failed` on exception instead of stuck `pending`) makes outcomes
  assertable; lean on it.
- **AC:** the event-path leg is non-flaky across 20 consecutive runs (`-n0`).

### WI-2.3 — CI wiring
- Verify how the `integration` marker is executed in CI (`ci.yml` / `e2e.yml`) and
  ensure a job **provably runs** these (with `aiosmtpd` installed) — not skipped.
- **AC:** a CI job shows the routing-matrix tests in its *run* count, green.

---

## Phase 3 — Real-estate dry-run report *(the Tier-2 answer; in scope)*

The hermetic matrix uses synthetic-but-messy tags. It does **not** discharge the
reflection's deeper worry: messy *real-world* tags on the actual prod estate.

### WI-3.1 — `cw alert routing-report` (read-only, delivers nothing)
- A CLI/diagnostic that wraps `alert_groups._match_preview` over a **prod DB
  snapshot/replica**, printing the routing matrix: per group, matched cert count
  + sample; and crucially the **orphans** (certs matching no group) and
  **multi-match** certs.
- Delivers nothing, mutates nothing — operator-paced validation, not a gate.
- **AC:** run against a copy of the real DB, produces a human-readable matrix +
  an orphan/multi-match summary; reviewed by a human against expectations.

---

## Risks & notes

- **Don't let Phase 1–2 convince you the worry is closed.** Synthetic-messy ≠ real
  estate. Phase 3 is the part that actually answers "does routing do the right
  thing on *our* certs." Sequence Phase 3 deliberately, don't let it fall off.
- **Two delivery paths is the subtle trap.** Routing lives in the synchronous
  `alerts` path; the threaded `events` path is a different beast. Be explicit in
  each test about which one is under test.
- **Vendored, not shared.** `tests/_mock_targets.py` stays in cert-watch. The day a
  second tool copies it is fine; a shared dependency that turns three tools' CI
  red at once is not.

## Scope — decided

Full scope: **Phase 1 + 2 + 3.** Phase 3 was confirmed in (2026-06-18 session) —
it's cheap because the matcher already exists, and it's the part that actually
answers the question that motivated the plan.

## Decisions that must be pinned *before* Phase 1 implementation

These are specification choices, not code — the team should not guess them, because
a factory + matrix test built on a guess will lock in possibly-wrong behavior with
full green confidence:

- **Multi-match:** a cert matching N alert groups → **one alert** (deduped) or
  **N alerts** (one per group/recipient set)? The matrix test asserts this either
  way; it must assert the *intended* way.
- **Orphan:** a cert matching **zero** groups → silently un-alerted, or routed to a
  default/catch-all? Today's behavior should be confirmed and then locked, or
  changed deliberately — not discovered by accident.
