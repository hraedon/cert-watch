# Alerting

cert-watch raises an alert when something about a certificate needs a person's
attention. It works out who that person is, delivers the alert by email or
webhook, and keeps a record of every delivery attempt. This page explains each
step.

## What raises an alert

| Alert | Raised when | Raised again |
|---|---|---|
| **Expiry warning** | A certificate crosses an expiry threshold (see below). | Once per threshold. The next threshold is a new alert. |
| **Expired** | A certificate has expired. | Once. |
| **Renewal stalled** | A certificate is inside its renewal window (`CERT_WATCH_RENEWAL_WINDOW_DAYS`, 30 by default) and no successor has appeared. | Once per certificate, until a successor appears or someone marks the renewal in progress. The weekly renewal digest is the reminder. |
| **Policy violation** | A scan finds a critical or warning finding from the posture policy, such as SHA-1, short keys or an old TLS version. | Once while the violation persists. If it clears and comes back, again. |
| **Drift** | A scan sees the issuer change, the key shrink, the signature algorithm or TLS version downgrade, or the posture grade drop. Turn off with `CERT_WATCH_DRIFT_ALERTS=0`. | Each drift is its own alert. |

Every endpoint is tracked separately. A wildcard certificate served by five
hosts produces an alert for each of them, routed to each host's owner.

### Expiry thresholds

A long-lived leaf certificate alerts at **14, 7, 3 and 1 day** before expiry.
Intermediate and root certificates alert at 30, 14 and 7 days.

Short-lived certificates (90 days or less) alert at 50 %, 25 % and 10 % of
their lifetime instead: a 90-day certificate at 45, 23 and 9 days, a 47-day
one at 24, 12 and 5. A fixed 14-day warning would be meaningless for them.

You can override the first threshold for a host on its detail page, or for
every certificate in an alert group. cert-watch then alerts at that many days,
half of it, a quarter of it, and 1 day. When several groups match a
certificate, the most urgent setting wins.

Only the most urgent newly crossed threshold alerts. A certificate discovered
3 days from expiry produces one "3 days" alert, not four.

### Digest mode

With `ALERT_DIGEST_ONLY=1`, expiry warnings are collected into a digest instead
of one email each. Everyone configured receives a global summary, and each
owner receives a digest listing only their own certificates. The final
countdown (3 days and less) and every other alert type are still sent
individually. Digest mode is the better choice for an estate of any size.

## Who gets an alert

An alert goes to all of these, with duplicates removed:

1. **Global recipients** (`ALERT_RECIPIENTS`), who receive everything.
2. **Alert groups** whose tags match the certificate or its host. Groups are
   defined under **Settings → Alert groups**, each with recipients, match tags,
   and optionally its own threshold and digest cadence.
3. **The host's owner**, the owner email on the endpoint's detail page.
4. **Members of roles** linked to a matching alert group.

Recipients are resolved when the alert is raised and stored with it. If you
change a group while an alert is waiting to be delivered, that alert still
goes to the recipients it was raised with. New alerts use the new routing. The
delivery channels themselves (SMTP relay, webhook URL) are read at send time,
so fixing a broken relay takes effect for queued alerts.

A certificate with no specific recipient, meaning no group, owner or role, is
an **orphan**. Once a week cert-watch sends administrators a list of orphans,
so nothing is watched by nobody.

### Checking routing

```bash
cert-watch backup /tmp/snapshot.sqlite3
cert-watch routing-report /tmp/snapshot.sqlite3
```

This reads the snapshot without sending anything or loading any credentials.
It lists group coverage, specific recipients, certificates matched by several
groups, and orphans. It uses the same resolver as delivery. Global recipients
aren't listed, and it doesn't forecast which thresholds will fire.
`--format json` gives machine-readable output.

## How alerts are delivered

Email is tried first. If it isn't configured or doesn't deliver, the alert
webhook is tried. The webhook formats are `generic` (JSON, optionally
templated), `slack`, `teams`, `discord`, `pagerduty` and `alertmanager`. All
webhook traffic goes through the same address allowlist as scanning, checked
at every redirect.

Each alert moves through a small set of states, shown in **Activity → Alerts**:

| State | Meaning |
|---|---|
| **Pending** | Waiting to be sent, now or after a backoff. |
| **Sending** | Claimed by the delivery process right now. |
| **Sent** | At least one channel accepted it. |
| **Failed** | cert-watch gave up after 12 delivery attempts. |
| **Cancelled** | The condition went away before it was delivered, e.g. the certificate was replaced. |

Delivery runs every alert cycle, and on demand from **Activity → Alerts →
Flush**. Each round retries a failing channel three times. If the alert still
isn't delivered, it waits 1 hour, then 4 hours, then 12 hours between rounds,
and after 12 attempts it is marked failed.

An alert that can't be sent because no channel is configured waits without
using up attempts. Configuring SMTP or a webhook sends it on the next cycle.

Delivery is **at least once**. If cert-watch stops in the moment between a
relay accepting an alert and recording that it did, the alert is sent again
after restart. It is never silently dropped.

A failed alert stays failed until someone acts on it. Use **Retry** on the
alert once the cause is fixed. `cert_watch_alerts_failed_recent` counts recent
give-ups for your monitoring, and `deploy/k8s/prometheus-rules.yaml` includes
a rule for it.

### Delivery evidence

Every attempt is recorded: channel, outcome, the recipients tried and the
reason for any failure. Administrators can open an alert in **Activity →
Alerts** to see who it was routed to and why, and what each channel did with
it. The record is append-only; nothing rewrites it.

### Resolving incidents

For PagerDuty and Alertmanager, cert-watch also closes what it opened. When a
certificate that alerted is renewed, or a policy violation clears, it sends
the matching resolve. It never resolves an incident that was never sent, and a
rescan that finds the same certificate doesn't count as a renewal.

## Digests

| Digest | Sent | Contents |
|---|---|---|
| **Expiry digest** (digest mode only) | Every alert cycle, once per week per recipient | Certificates expiring within the cadence window; a global version and one per owner |
| **Renewal digest** | Weekly | Renewals seen, renewals overdue, and certificates whose replacement has a shorter lifetime |
| **Orphan notice** | Weekly, to administrators | Certificates nobody specific is watching |

Each digest is claimed per recipient and per period. So a restart, a second
process or a changed setting mid-week never sends one twice, and a partial
failure retries only the recipients that didn't get it.

## The renewal webhook

Separate from human-facing alerts, the renewal webhook
(`CERT_WATCH_RENEWAL_WEBHOOK_URL`) posts a machine-readable event when a
certificate is overdue for renewal. Your renewal automation (certbot, acme.sh,
an Ansible play) can act on it without calling cert-watch back:

```json
{
  "event": "renewal_needed",
  "hostname": "www.example.com",
  "port": 443,
  "cert_fingerprint": "…",
  "subject_cn": "www.example.com",
  "san_names": ["www.example.com", "example.com"],
  "issuer": "R3",
  "expiry": "2026-07-10T12:00:00+00:00",
  "days_remaining": 7.0,
  "expected_renewal_at_days": 30.0,
  "days_overdue": 23.0,
  "confidence": "low",
  "automation_hint": "acme",
  "cert_watch_url": "https://certs.example.com/certificates/42"
}
```

`cert_watch_url` is included when `CERT_WATCH_BASE_URL` is set. The event is
sent at most once per endpoint per day and retried with backoff if the
destination fails. It goes through
the address allowlist and never blocks the scan cycle.

## Event forwarding

**Settings → Events** forwards lifecycle events to a webhook as they happen:
certificates added, renewed, expired and changed. This suits a SIEM or a chat
channel that wants a running feed rather than alerts. It is rate-limited and
uses the same webhook formats and allowlist.

## When alerts don't arrive

1. **Activity → Alerts** shows the alert's state and each attempt's outcome and
   reason. That is almost always where the answer is.
2. **Settings → Alerts** has test buttons that send one message through SMTP
   and one through the webhook.
3. `cert-watch routing-report` on a backup shows who the alert should have gone
   to.
4. A long run of *pending* alerts with no attempts means no channel is
   configured, or the scheduler isn't running. For the latter, check `/readyz`
   and [operations.md](operations.md#troubleshooting).
