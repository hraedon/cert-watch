# Plan 037: TOFU CA auto-provisioning for the LDAP connection test

**Created:** 2026-06-05
**Status:** proposed
**Builds on:** the `/settings/test-ldap` handler (`src/cert_watch/routes/settings.py`),
the three LDAPS auth fixes from the 2026-06-05 session, and the manual
openssl-`s_client`-+-bundle dance recorded in `docs/archive/2026-06-05-ldap-e2e-handoff.md`.

---

## Why

Connecting cert-watch to a private-CA AD over LDAPS currently requires the
operator to **manually** obtain the CA chain out of band:

```bash
openssl s_client -connect dc:636 -showcerts ... | awk ... > chain.pem
cat root.cer issuing.pem > ca.pem   # then paste into the CA field
```

That is exactly the friction this session hit. The operator's framing:

> "Even automatic provisioning is better than raw LDAP."

i.e. a Trust-On-First-Use (TOFU) flow — capture the cert the server actually
presents, show it to the operator, let them accept it — is strictly better than
the status quo of either (a) fiddling with openssl, or (b) giving up on TLS
validation. It does not weaken security relative to today: today the operator
already hand-copies a CA they eyeballed; TOFU just makes the eyeball step
structured and records the decision.

## What exists today (the integration point)

`POST /settings/test-ldap` (`settings.py:438`) probes each server URL, builds a
`ldap3.Tls(validate=CERT_REQUIRED, ca_certs_file=<pinned CA>)`, and binds. When
the CA isn't pinned (or is wrong), the bind fails inside the TLS handshake with a
cert-verify error and the handler returns `{"ok": False, "error": "<url>: ..."}`.
There is **no** path to see *what* cert the server presented — the operator is
told "it failed" and left to the openssl dance.

## What this adds

When (and only when) the LDAPS handshake fails certificate verification, the
test handler performs a **second, non-validating** probe to capture the chain the
server actually presents, and returns it to the UI as a *proposed* CA to pin.
The operator reviews fingerprints/subjects and clicks **Trust & pin**, which
writes the captured root/issuing chain into `ldap_ca_cert`. Nothing is pinned
without an explicit click.

### Flow
1. Normal validated probe runs (unchanged).
2. On a TLS cert-verify failure specifically (not connect-refused, not bind
   creds), run a capture probe:
   - `ssl.create_default_context()` with `check_hostname=False`,
     `verify_mode=CERT_NONE`, wrap a socket to `host:636`, read
     `getpeercert(binary_form=True)` — and, to get the *chain* (not just the
     leaf), use `SSLSocket.get_verified_chain()` / `get_unverified_chain()`
     (3.13+) or fall back to an `openssl s_client -showcerts` subprocess.
   - Reduce to the CA certs (drop the leaf): keep issuing CA + root.
3. Return `{"ok": False, "tofu": {chain: [{subject, issuer, not_after, sha256}],
   pem: "<root+issuing>"}}`. The leaf is shown for context but excluded from the
   pinned PEM.
4. UI renders a "couldn't validate — server presented this CA" panel with
   subject/SHA-256 per cert + a **Trust & pin** button (and a copy-PEM affordance).
5. Clicking posts the captured PEM to the existing save path as `ldap_ca_cert`;
   re-running the test now validates.

### Capture-probe safety
- Reuse the existing **SSRF guard** (`_is_blocked_ip`) before the capture probe —
  same allowlist as the validated probe; no new egress surface.
- Capture is read-only (handshake + peer cert, no bind with creds over the
  unverified channel — do NOT send the bind password on a CERT_NONE socket).
- Gate behind the existing admin + CSRF checks (handler already has both).
- Cap the captured PEM size; only emit `BEGIN CERTIFICATE` blocks.

## Trust & provenance (the honest part)

TOFU means the *first* connection is unauthenticated — a MITM at first-pin time
could present their own CA. Mitigations, surfaced in the UI, not hidden:
- Show **SHA-256 fingerprints** so an operator with an out-of-band value (e.g.
  from `certutil`/AD) can verify before trusting.
- Label it plainly: "Trust on first use — verify the fingerprint against a known
  good source if your network may be hostile."
- Record the pin decision in the **audit log** (who, when, fingerprint) so the
  trust event is reviewable. (Ties to the agent-provenance theme: a trust
  decision is exactly the kind of action that should leave a durable record.)

## Scope / non-goals

- **In:** capture-on-verify-failure, fingerprint display, one-click pin, audit
  trail of the pin.
- **Out (this plan):** auto-pinning without a click; periodic CA rotation/renewal
  tracking; fetching the CA from AD's `cACertificate`/CDP (the directory-published
  bundle is a separate, stale-PKI rabbit hole — see the archived 2026-06-05 handoff "CA" note); doing the
  same for SMTP STARTTLS (could reuse the pattern later).

## Slices
1. **Backend capture** — factor the capture probe into a helper
   (`_capture_ldaps_chain(url, timeout) -> list[pem]`), invoked from
   `test_ldap_connection` only on a cert-verify failure. Unit-test with a
   self-signed server fixture (or mock the ssl handshake) asserting: leaf
   excluded, CA chain returned, SSRF guard honored, no creds sent.
2. **API shape** — extend the JSON response with the `tofu` block; keep the
   `ok/error` contract backward-compatible (older UI ignores the extra key).
3. **UI** — the "server presented this CA" panel + Trust & pin button in
   `settings.html`, no inline styles (respect the ratchet), posts to save.
4. **Audit** — write a `ca_pinned` audit row on accept (subject + sha256 + actor).
5. **Docs** — update the LDAP setup section: "you no longer need the openssl
   dance; click Test, then Trust & pin."

## Acceptance
- Against the lab DC with **no** CA pinned: clicking Test returns the Hraedon
  Root + ad-MVMCA01 chain with correct SHA-256s; clicking Trust & pin populates
  `ldap_ca_cert`; re-testing validates; the pin is in the audit log. This
  reproduces, in one click, the bundle I built by hand this session.

## Risks / decisions
- **`get_unverified_chain()` availability** — added in CPython 3.13. Detect and
  fall back to an `openssl s_client -showcerts` subprocess (already a project
  dependency in practice) when unavailable.
- **Don't let TOFU become silent trust** — the click + fingerprint + audit row
  are load-bearing; without them this is just "disable verification," which we
  explicitly do not want (cf. the fail-closed CERT_REQUIRED stance in
  `ldap_provider._build_tls`).
