# Plan 033: Action Hooks (Workstream G)

> **Status:** **Deferred (post-0.6.0).** Renamed from 029 (collided with
> `029-security-review-hardening`). Deferred after review for three reasons:
> (1) shell execution is off-brand — cert-watch positions as *read-only*
> observability, and operator-defined command execution changes that identity;
> (2) the HTTP hook largely duplicates the existing generic webhook adapter
> (`alert_adapters.py`), so the only genuinely new capability is local shell
> execution — the most security-sensitive part; (3) any automation story should
> land **behind REST API machine-to-machine auth (BC-104)** first. Revisit only
> if a concrete operator need emerges that the existing webhook adapter can't
> serve. Original draft preserved below.
>
> Grounded in the alert adapter registry (`alert_adapters.py`), the
> `process_pending` delivery loop (`alerts.py`), and the `store_scanned`
> post-persist callback (`scan.py`).

## Goal

Let operators define **automated actions** that fire when specific alert types
are raised — shell scripts, HTTP callbacks, or command execution — so cert-watch
can *trigger* remediation (restart a service, call certbot, bounce an app pool)
without becoming an ACME client itself.

The key distinction: cert-watch does not issue, renew, or deploy certificates.
It detects conditions and *delegates* to whatever tooling the operator already
has. The action hook is a thin execution seam, not a certificate operations
engine.

## What already exists (build on, don't rebuild)

- **Alert adapter registry** (`alert_adapters.py:251`): `_ADAPTERS` dict +
  `get_adapter(kind)` pattern. A new adapter type slots in cleanly.
- **`WebhookConfig`** (`alerts.py:37`): carries `url`, `kind`, `headers`,
  `timeout`, `template`, `allow_private`, `allowed_subnets`. The `template`
  field already does `{{key}}` substitution in `GenericAdapter.build()`.
- **`process_pending` retry loop** (`alerts.py:739`): tries SMTP then webhook
  per alert. A third delivery channel can be added as another fallback or a
  parallel dispatch.
- **`store_scanned` post-persist hook** (`scan.py:681`): PagerDuty auto-resolve
  fires here on cert replacement — the "cert renewed" event. A general
  post-renewal hook could dispatch action hooks at this point.
- **SSRF-safe opener** (`http_client.py`): already validates HTTP callback URLs.
- **Drift events** (`database/drift.py:create_drift_alert`): structured
  `DriftEvent(field, old, new, severity)` data available during `store_scanned`.

## Non-goals

- Not an ACME client. No CSR generation, no challenge handling, no cert issuance.
- Not a deployment agent. No SSH, WinRM, or push-to-host capability.
- Not a workflow engine. No chaining, no conditional logic, no retries beyond
  the existing alert retry loop.
- Not a replacement for webhook receivers. If the operator already has a webhook
  endpoint that does remediation, the existing generic webhook adapter is the
  right tool. Action hooks are for operators who want local script execution
  without standing up a webhook receiver.

## Signal definition

An action hook fires when an alert is **successfully delivered** (or, for
post-renewal hooks, when a cert replacement is detected). The hook receives a
structured context object with enough information to make remediation decisions.

### Hook context (environment variables for shell hooks, JSON body for HTTP hooks)

```
CW_ALERT_TYPE       — "expiry_warning" | "expired" | "drift" | "renewal_stalled"
CW_CERT_ID          — certificate ID
CW_HOSTNAME         — host:port (from cert_id)
CW_MESSAGE          — alert message
CW_THRESHOLD_DAYS   — threshold that triggered (if applicable)
CW_DAYS_UNTIL_EXPIRY — days until expiry (negative if expired)
CW_POSTURE_GRADE    — current posture grade (if available)
CW_DRIFT_FIELDS     — comma-separated drift field names (if drift alert)
CW_ALERT_STATUS     — "sent" | "retrying"
CW_ALERT_ID         — alert row ID
```

## Config

- `CERT_WATCH_ACTION_HOOKS` — semicolon-separated list of hook definitions.
  Each: `name:type:target[:filter]`
  - `name` — identifier for logging
  - `type` — `shell` or `http`
  - `target` — command template (shell) or URL (http)
  - `filter` — optional: `alert_type=expiry_warning,drift` to limit which
    alert types trigger this hook (default: all)

  Example:
  ```
  CERT_WATCH_ACTION_HOOKS=certbot-renew:shell:/usr/local/bin/renew.sh:alert_type=expiry_warning;pager-hook:http:https://hooks.example.com/cert-alert
  ```

- `CERT_WATCH_ACTION_HOOK_TIMEOUT` — per-hook timeout in seconds (default 30).
- `CERT_WATCH_ACTION_HOOK_ON_RENEWAL` — `1` to fire hooks on cert replacement
  (post-renewal event) in addition to alert events (default 0).

### Shell hooks

- Command is executed via `subprocess.run` with a 30s timeout.
- Context is passed as environment variables (prefixed `CW_`).
- stdout/stderr are captured and logged at DEBUG/WARNING level.
- Exit code is ignored (fail-open, matching the alert delivery contract).
- The command string supports `{{variable}}` substitution (matching the existing
  template pattern in `GenericAdapter.build()`), so operators can embed cert_id
  or hostname directly in the command.

### HTTP hooks

- POST to the target URL with JSON body containing the context fields.
- Goes through `ssrf_safe_urlopen` (SSRF-guarded).
- Response status is logged; non-2xx is a warning, not a failure.
- Supports custom headers via `CERT_WATCH_ACTION_HOOK_HEADERS` (JSON dict).

## Slices

1. **Config + parser**: parse `CERT_WATCH_ACTION_HOOKS` into a list of
   `ActionHookDef` dataclasses. Validate on startup; warn on malformed entries.
   Wire into `Settings`.
2. **Shell executor**: `execute_shell_hook(hook, context)` — subprocess call with
   env vars, timeout, capture output. Pure function, easily testable.
3. **HTTP executor**: `execute_http_hook(hook, context)` — POST JSON through
   `ssrf_safe_urlopen`. Reuse existing SSRF infrastructure.
4. **Alert integration**: in `process_pending`, after a successful delivery
   (SMTP or webhook), dispatch all matching action hooks. Fail-open: hook
   failures are logged and swallowed, never block alert delivery.
5. **Post-renewal hook** (optional, behind `CERT_WATCH_ACTION_HOOK_ON_RENEWAL`):
   in `store_scanned`, after `replace_scanned` returns a `replaced_cert_id`,
   fire hooks with `alert_type=renewal_completed` and the new/old cert context.
6. **UI (small)**: surface configured hooks on the Settings page (read-only
   display of hook names/types/targets, not editable).

## Testing

- **Shell hook**: mock `subprocess.run`; assert env vars are set correctly from
  context; assert timeout is respected; assert exit code != 0 is swallowed.
- **HTTP hook**: mock `ssrf_safe_urlopen`; assert JSON body fields; assert SSRF
  validation applies (blocked URL is logged, not raised).
- **Filter**: seed hooks with `alert_type=drift`; fire an `expiry_warning` →
  hook does not fire. Fire a `drift` → hook fires.
- **Fail-open**: shell hook times out → alert is still marked `sent`.
- **No-config**: with `CERT_WATCH_ACTION_HOOKS` unset, zero overhead.
- **Post-renewal**: mock a cert replacement; assert hook fires with
  `renewal_completed` type when enabled, does not fire when disabled.

## Risks / decisions

- **Arbitrary command execution** — shell hooks run operator-defined commands
  with the cert-watch process's permissions. This is the same risk model as
  cron jobs or systemd service restarts. The config is env-var-only (no GUI
  editing), so an attacker with env access already has full control. Document
  the security model clearly.
- **Hook timeout blocking the alert loop** — mitigated by running hooks *after*
  the alert is marked `sent`. A slow hook delays the next alert's delivery but
  does not block the current one. The 30s default timeout is generous; operators
  should design hooks to be fast.
- **Template injection** — the `{{variable}}` substitution in shell commands
  must sanitize special characters. Use `shlex.quote()` on all substituted
  values. For HTTP hooks, the JSON body is structured (no injection risk).
- **Not an Ansible/Puppet** — deliberately simple. No state management, no
  idempotency, no rollback. If the operator needs complex orchestration, they
  should use the HTTP hook to trigger their existing automation platform.
