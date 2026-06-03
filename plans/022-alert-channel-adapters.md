# Plan 022: Alert Channel Adapters (Teams, Discord, PagerDuty)

> **Status:** draft for review. Grounded in the code as of the 0.4.0 release
> commit. Builds on the existing webhook delivery path in `alerts.py`.

## Goal

Make Microsoft Teams, Discord, and PagerDuty **first-class alert channels** for
expiry/drift alerts, rather than leaving users to hand-craft `ALERT_WEBHOOK_TEMPLATE`
payloads. Each provider has a different payload shape (and PagerDuty has incident
*lifecycle* semantics), so a single freeform template can't serve all three well.

The unifying idea: an **alert channel adapter** is a pure function that turns an
`Alert` into a provider-specific HTTP request `(method, url, headers, body)`. The
existing generic webhook becomes one adapter among several; delivery stays a
single code path.

## Non-goals

- Not adding inbound integrations or two-way interactivity (buttons/acks from the
  provider back into cert-watch).
- Not replacing email/SMTP alerting — adapters extend the webhook lane only.
- Not per-alert-group channel routing in this plan (Plan 015 owns groups; see
  "Interactions").

## Depends on

- **Plan-pending SSRF-safe opener** (`scan.safe_urlopen`, the Gemini SSRF batch).
  Adapter *delivery* must go through it so a malicious/redirecting endpoint can't
  pivot internally. Teams/Discord/PagerDuty endpoints are public, so they deliver
  with `allow_private=False`. **Sequence this plan after that opener lands**, or
  the adapters ship with the same SSRF gap we're closing elsewhere.
- Existing `Alert` fields: `alert_type`, `cert_id`, `message`, `threshold_days`,
  `status`, `extra_recipients` (see `send_webhook`, `alerts.py:309`).

---

## Architecture

### New module: `src/cert_watch/alert_adapters.py`

```python
@dataclass(frozen=True)
class AlertRequest:
    url: str
    body: bytes
    headers: dict[str, str]
    method: str = "POST"

class AlertAdapter(Protocol):
    kind: str
    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest: ...
```

Four adapters, each a **pure** `build()` (no I/O — trivially golden-testable):

| kind         | endpoint                                   | secret carried in        |
|--------------|--------------------------------------------|--------------------------|
| `generic`    | `config.url`                               | the URL                  |
| `discord`    | `config.url` (incoming webhook)            | the URL                  |
| `teams`      | `config.url` (Workflows incoming webhook)  | the URL                  |
| `pagerduty`  | `https://events.pagerduty.com/v2/enqueue`  | `routing_key` (not URL)  |

`generic` is today's behaviour (default JSON, or `template` substitution) moved
verbatim into an adapter, so existing configs are unchanged.

### Config surface

Extend `WebhookConfig` (`alerts.py:37`) and `Settings.build_webhook_config`
(`config.py:332`):

```python
@dataclass
class WebhookConfig:
    url: str = ""
    kind: str = "generic"          # generic|discord|teams|pagerduty
    routing_key: str = ""          # pagerduty Events API v2 integration key
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 15
    template: str = ""             # generic-only
```

Env (all optional, back-compatible — absence ⇒ `generic`):

- `ALERT_WEBHOOK_KIND` = `generic|discord|teams|pagerduty`
- `ALERT_PAGERDUTY_ROUTING_KEY` (+ `_FILE`, like other secrets) — required when
  `kind=pagerduty`; the URL field is ignored.
- Reuse `ALERT_WEBHOOK_URL` for `discord`/`teams`.

GUI: the Settings → Alerts panel already edits webhook URL/headers/template; add a
**kind** selector that shows/hides the routing-key field and a "Send test alert"
button that exercises the chosen adapter.

### Delivery

`send_webhook` becomes a dispatcher:

```python
def send_webhook(alert, config):
    adapter = _ADAPTERS[config.kind]
    req = adapter.build(alert, config)
    resp = scan.safe_urlopen(
        urllib.request.Request(req.url, data=req.body, headers=req.headers, method=req.method),
        timeout=config.timeout, allow_private=False,
    )
    return _provider_ok(config.kind, resp)   # 2xx; PagerDuty returns 202
```

`_sanitize_webhook_error` (`alerts.py:262`) must also strip `routing_key` from
logged errors.

---

## Provider payload specifics (the crux — get these exact)

### Discord — incoming webhook
- `POST {url}` JSON: `{"username": "cert-watch", "embeds": [ { "title", "description", "color", "fields": [{"name","value","inline"}] } ] }`.
- `color` is a **decimal int** — map status → red `0xCC0000` / amber `0xE0A800` /
  green `0x2E7D32` / grey info.
- 1–10 embeds per message; rate limit ~30/min/webhook (429 carries `retry_after`)
  — reuse `retry.backoff_range` on 429.

### Microsoft Teams — Workflows / Adaptive Card only
- Target the **Power Automate "Workflows"** incoming webhook (the current
  mechanism; the legacy Office 365 Connectors / `MessageCard` are being retired by
  Microsoft and are **deliberately not supported** — new format or nothing).
- It expects an **Adaptive Card** wrapped in a message envelope:
  ```json
  {"type":"message","attachments":[
    {"contentType":"application/vnd.microsoft.card.adaptive",
     "content":{"type":"AdaptiveCard","version":"1.4","body":[ ... ]}}]}
  ```
  Body: a title `TextBlock` (color via `"color":"attention|warning|good"`), a
  `FactSet` (host, expires, days-left, status), and the message.

### PagerDuty — Events API v2 (incident lifecycle, not fire-and-forget)
- `POST https://events.pagerduty.com/v2/enqueue` (fixed), JSON:
  ```json
  {"routing_key":"<32-char key>","event_action":"trigger",
   "dedup_key":"<stable per cert+threshold>",
   "payload":{"summary":"<=1024 chars","source":"cert-watch",
     "severity":"critical|error|warning|info","component":"<host>",
     "group":"<tag?>","class":"cert-expiry","custom_details":{...}}}
  ```
- Success is **HTTP 202** (not 200) and returns the `dedup_key`.
- **Severity map:** expired → `critical`; within critical threshold → `error`;
  within warn threshold → `warning`; drift/info → `warning`/`info`.
- **`dedup_key`** must be deterministic per (cert fingerprint + alert_type +
  threshold) so repeated alerts coalesce into one incident.

---

## Slices

1. **Adapter seam + Discord** — introduce `alert_adapters.py`, move `generic` into
   it, add `discord`, wire `WebhookConfig.kind` + dispatcher + delivery through
   `safe_urlopen`. Ship golden-payload tests. *(Smallest, proves the seam.)*
2. **Teams** — Adaptive Card via the Workflows webhook (new format only).
3. **PagerDuty trigger** — Events API v2, `routing_key` config, deterministic
   `dedup_key`, 202 handling, severity map.
4. **PagerDuty resolve-on-renewal** *(follow-up, can slip past the feature
   release)* — when renewal tracking links a successor cert, emit `event_action:
   resolve` with the same `dedup_key` so the incident auto-closes. This is the
   payoff of PagerDuty's lifecycle model and the one piece that needs new wiring
   into the renewal path (`certificate_model`/renewal tracking).

## Testing

The adapter `build()` functions are pure, so each provider gets **golden-payload
unit tests** asserting the exact JSON for an expired cert, an expiring cert, and a
drift alert — plus severity/color mapping. Delivery is tested by mocking
`safe_urlopen` and asserting endpoint + headers + that `routing_key`/URL never
leak into logs. PagerDuty `dedup_key` determinism gets its own test (same input ⇒
same key). This is the regression net the alerting lane currently lacks.

## Interactions / risks

- **Alert groups (Plan 015):** `alert_groups.webhook_url` exists in schema.
  Per-group *kind/routing-key* is a natural future extension; this plan keeps the
  global webhook config and notes the seam. Don't fold groups in here.
- **Secrets:** PagerDuty routing key and Discord/Teams URLs are credentials — they
  go through the same `kv_store` encryption + `*_FILE` env support as SMTP creds,
  and must be sanitized from logs.
- **Version/scope:** a multi-provider channel system is a semver-**minor** feature.
  Recommend it lands as **0.5.0** rather than retro-expanding the already-tagged
  0.4.0 — but that's a release-framing call (see open question).

## Open questions

1. **Release framing** — 0.5.0 (recommended; it's a feature, and 0.4.0 is already
   deployable and tagged) vs. holding the 0.4.0 push to include it.
2. **PagerDuty resolve** — in the feature release, or explicitly a fast-follow?
