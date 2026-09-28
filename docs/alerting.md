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
| **Renewal stalled** | A certificate is inside its renewal window (`CERT_WATCH_RENEWAL_WINDOW_DAYS`, 30 by default) and no successor has appeared. | Once per certificate, paused during the first live renewal-attempt lease for that served certificate. The weekly renewal digest is the reminder. |
| **Renewal failed** | Renewal automation reports failure for an endpoint with a current scanned leaf. A failure reported after a deployment warning is recorded on that same renewal cycle and raises this alert alongside the warning. | Once per continuous failure condition. Later started, manual in-progress, or succeeded attempts carry the condition without opening another provider incident. A failure after a manual clear starts a new incident on the same active attempt without changing its renewal state. See the clearing rule below. |
| **Renewal not deployed** | Renewal automation reported success, but a qualifying stored scan still sees the previous certificate or a different certificate than the reported fingerprint. | Once per renewal attempt. It closes when a later scan verifies the successor or the endpoint is deleted. |
| **Policy violation** | A scan finds a critical or warning finding from the posture policy, such as SHA-1, short keys or an old TLS version. | Once while the violation persists. If it clears and comes back, again. |
| **Drift** | A scan sees a high-severity change: a new issuer, a smaller key, a signature downgrade to SHA-1, a TLS version downgrade, or a posture-grade drop. Turn off with `CERT_WATCH_DRIFT_ALERTS=0`. | Each drift is its own alert. |

Every endpoint is tracked separately. A wildcard certificate served by five
hosts produces an alert for each of them, routed to each host's owner.
Marking a renewal **in progress** opens a time-limited attempt. Its first lease
for that endpoint and served certificate suppresses only the renewal-stalled
condition and the automation-facing `renewal_needed` webhook; the overdue event
is still recorded. It never suppresses expiry warnings or expired alerts.
Repeated starts do not extend or re-grant the lease. Renewal completion is
established by observing a successor certificate, not by an operator report.

**A failure condition clears when any of these happens:**

- A scan after the failure report moves the carrying renewal attempt into the
  verified state. Open, verifying, and deployment-warning attempts are eligible
  for this transition under the ordinary renewal rules. The differential test
  runs reports, stored successor leaves, manual clears, and randomized sequences
  against the reducer pinned from the branch's merge base. It compares returned
  state and effect, stored report effect, and every base attempt column. The one
  allowed difference is a failed report carrying the correlation of an already
  verified attempt: it remains `ignored_late`, even after the served leaf
  changes, because that verified run still owns its correlated reports.
- A stored scan sees a certificate other than the attempt's baseline and it
  matches the most recent certificate fingerprint named by a failed or
  succeeded report during this failure condition. If no such fingerprint was
  reported, any non-baseline certificate normally clears the failure. The
  exception is an attempt whose own reported certificate has not yet been
  served: an unrelated certificate does not clear its failure in any state.
  If a later report names a different fingerprint, that newer fingerprint can
  clear the failure while the renewal itself continues to be judged against
  its original claim.
- An operator clears the failure manually.
- The endpoint is deleted.

A scan that still serves the baseline never clears a failure. After a manual
clear, another failure can restart the condition in place only on a
non-terminal attempt; the restart leaves the renewal state and claim intact.
If the previous attempt is already verified, the failure opens a new attempt
whose baseline is the certificate currently being served.

### Renewal verification

A `succeeded` report that enters verification queues one immediate check; repeat
reports cannot move it. Scheduler eligibility keeps every check at least five
minutes after that endpoint's last actual scan. The first check can verify a fast
deployment, but an unchanged result does not count toward an alert until the
configured grace period after the report that entered verification has elapsed
(`CERT_WATCH_RENEWAL_VERIFY_GRACE_MINUTES`,
5 minutes by default, range 5–15). Later checks use the expiry of the leaf that
was serving when the attempt opened:

| Previous certificate has left | Verification checks | Alert after |
|---|---|---|
| 14 days or more | Standard scan or 24 hours, whichever is sooner | First successful unchanged check at or after 24 hours |
| 3–14 days | Every 6 hours or the standard scan, whichever is sooner | First successful unchanged check at or after 12 hours |
| Less than 3 days, or expiry unknown | At the grace boundary, then hourly | First qualifying unchanged check |
| Expired | At the grace boundary, then every 15 minutes | First qualifying unchanged check |

A failed network scan or database store is not verification evidence. It sets
the attempt's blocked timestamp, leaves the state and alert unchanged, and
reschedules using the same band. If evaluating an otherwise stored scan fails,
cert-watch retries with exponential backoff from five minutes up to that band's
cadence. A certificate different from both the baseline and a supplied
replacement fingerprint is a mismatch and raises the same warning only on a
qualifying post-grace scan. The report's free-form message, tool and correlation
identifier are never copied into the alert or its delivery.

#### Renewal verification details

- Any success, whether it addresses the endpoint by hostname or by an explicit
  `cert_fingerprint`, can use the current leaf's predecessor as its baseline
  only when that replacement was observed in the last 24 hours, the current
  leaf has never appeared as an old lineage fingerprint on the endpoint, and
  no earlier attempt has verified or used the current leaf as its baseline.
  This applies after any terminal attempt. Send a replacement fingerprint for
  exact verification. An explicit predecessor target still has a seven-day
  endpoint lookup window, but that wider addressing window does not change the
  baseline rules.
- A verified attempt owns late reports with its correlation. Bare successes
  and new correlations received within 24 hours of its accepted success are
  also duplicates. After that window, or when the report names a leaf
  different from the verified leaf, a success opens a new renewal cycle.
- Reports never move an attempt out of the deployment-warning state. In
  particular, a `failed` report is retained without changing the deployment
  decision. It raises a renewal-failed alert alongside the deployment warning;
  only stored scan evidence for the expected or observed successor verifies
  the attempt and closes both alerts.
- A failure belongs to the endpoint's renewal cycle, not just the attempt row
  that first received it. Any later attempt opened before resolution carries
  the original failure identifier and report time. A `started` report, a live
  lease, a bare success claim, lease expiry, or the compatibility
  legacy pending-status write-through does not clear it. An ordinary stored
  scan can resolve the same provider incident when it satisfies the clearing
  rule above. It does not make a failed or abandoned attempt verified; only
  transitions allowed by the ordinary renewal state machine occur.
- Operators may explicitly clear the condition with
  `POST /hosts/{id}/renewal-failure/clear` or its JSON peer
  `POST /api/hosts/{id}/renewal-failure/clear`. The action requires write
  access to the endpoint's host tags, records an audit event, and closes the
  alert on the next rule pass.
- Failure alert text is fixed server wording with an endpoint-detail link. It
  never contains the report message, tool, correlation identifier, reporting
  key, or recipient identities. An endpoint with no scanned leaf retains its
  attempt history but cannot carry either certificate-bound renewal alert.

### Expiry thresholds

Expiry alerts are raised for leaf certificates, the ones your endpoints
present. A long-lived leaf alerts at **14, 7, 3 and 1 day** before expiry.
Intermediate and root certificates don't raise expiry alerts of their own.

Short-lived certificates (90 days or less) alert at 50 %, 25 % and 10 % of
their lifetime instead: a 90-day certificate at 45, 23 and 9 days, a 47-day
one at 24, 12 and 5. A fixed 14-day warning would be meaningless for them.

You can override the first threshold for a host on its detail page, or for
every certificate in an alert group. cert-watch then alerts at that many days,
half of it, a quarter of it, and 1 day. An alert-group threshold takes
precedence over a host threshold, and when several groups match a certificate,
the most urgent group setting wins.

Only the most urgent newly crossed threshold alerts. A certificate discovered
3 days from expiry produces one "3 days" alert, not four.

### Digest mode

With `ALERT_DIGEST_ONLY=1`, expiry warnings are collected into a digest instead
of one email each. The global recipients receive a summary of everything, and
each host owner receives one listing only their own certificates. Alert-group
recipients don't get a digest of their own. The final countdown is still sent
individually: thresholds of 3 days or less, or a short-lived certificate's last
threshold. So is every other alert type. Digest mode is the better choice for
an estate of any size.

## Who gets an alert

An alert goes to all of these, with duplicates removed:

1. **Global recipients** (`ALERT_RECIPIENTS`), who receive everything.
2. **Alert groups** whose match tags fit the certificate or its host, or to
   which the certificate was assigned by hand. Groups are defined under
   **Settings → Alert groups**, each with recipients, match tags, and
   optionally its own threshold and digest window.
3. **The host's owner**, the owner email on the endpoint's detail page.
4. **Roles.** A scoped role linked to an alert group sends that group's
   recipients alerts for certificates carrying the role's tags. When the host
   owner's email is a role's team email, that role's members are added too.

Group, owner and role recipients are resolved when the alert is raised and
stored with it. If you change a group while an alert is waiting to be
delivered, that alert still goes to the recipients it was raised with; new
alerts use the new routing. The global recipients and the delivery channels
themselves (SMTP relay, webhook URL) are read at send time, so fixing a broken
relay or recipient list takes effect for queued alerts.

A certificate with no specific recipient, meaning no group, owner or role, is
an **orphan**. When there are any, cert-watch emails a weekly list of them to
local accounts with an administrator role and an email address. The
break-glass admin and directory administrators don't receive it, so give at
least one administrator a local account with an email.

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

Generic webhooks do not apply Slack, Discord, or Teams markup escaping. Use the
dedicated channel kind for chat destinations.

Each alert moves through a small set of states, shown in **Activity → Alerts**:

| State | Meaning |
|---|---|
| **Pending** | Waiting to be sent, now or after a backoff. |
| **Sending** | Claimed by the delivery process right now. |
| **Sent** | At least one channel accepted it. |
| **Failed** | cert-watch gave up after 12 delivery attempts. |
| **Cancelled** | The condition went away before it was delivered, e.g. the certificate was replaced. |

Delivery runs every alert cycle, and on demand from **Activity → Alerts →
Flush queue**. Each round retries a failing channel three times. If the alert still
isn't delivered, it waits 1 hour, then 4 hours, then 12 hours between rounds,
and after 12 attempts it is marked failed.

An alert that can't be sent because no channel is configured waits without
using up attempts. Saving an SMTP or webhook channel under Settings makes it
due on the next cycle. A channel configured through environment variables is
picked up on the next scheduled attempt, within an hour.

Delivery is **at least once**. If cert-watch stops in the moment between a
relay accepting an alert and recording that it did, the alert is sent again
after restart. It is never silently dropped.

A failed alert stays failed until someone acts on it. Use **Retry failed** on
the alert once the cause is fixed. `cert_watch_alerts_failed_recent` counts recent
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
| **Expiry digest** (digest mode only) | Once per week per recipient | Certificates expiring within the window (the largest alert-group digest window, 30 days by default); a global version and one per host owner |
| **Renewal digest** | Weekly | Renewals seen, renewals overdue, shorter replacement lifetimes, every **Renewal failed** condition that overlapped the period (including one since cleared), and current **Reported but not deployed** transitions raised during the period |
| **Orphan notice** | Weekly when there are orphans, to local administrator accounts with an email | Certificates nobody specific is watching |

Each digest is claimed per recipient and per period. So a restart, a second
process or a changed setting mid-week never sends one twice, and a partial
failure retries only the recipients that didn't get it.

The two renewal-problem sections read durable attempt transition timestamps,
not Event stream or alert-delivery rows. A carried failure condition appears
once, under the attempt that first reported it, when it was open at any point
in the digest period; verification or manual clearing later in the same period
does not erase that history. A superseding attempt without scan evidence also
does not erase it. Current not-deployed conditions appear once using their
raise time (or their accepted report time for upgraded historical rows). Owner copies use
the endpoint's owner email when the digest is sent; the global copy and delivery
ledger behave like the existing renewal sections. Digest content includes only
the endpoint and transition time, never report text, tool or correlation data,
key identity, tags, or recipient identities.

## The renewal webhook

Separate from human-facing alerts, the renewal webhook
(`CERT_WATCH_RENEWAL_WEBHOOK_URL`) posts a machine-readable event when a
certificate is overdue for renewal. Your renewal automation (certbot, acme.sh,
an Ansible play) can act on it without calling cert-watch back:

```json
{
  "event": "renewal_needed",
  "event_id": "62f138f6b6dd4c0d94318ab4a46dca1e",
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

`event_id` is a unique 32-character hexadecimal id for one webhook emission.
It stays the same across delivery retries, so receivers can use it as an
idempotency key, and is independent of the Event stream's database row id.
`cert_watch_url` is included when `CERT_WATCH_BASE_URL` is set. The event is
sent at most once per endpoint per day and retried with backoff if the
destination fails. Disabling `renewal_overdue` under **Settings → Event
streaming** stops that event from being stored or forwarded but does not
disable this renewal webhook. It goes through
the address allowlist and never blocks the scan cycle.

## Event forwarding

**Settings → Event streaming** forwards lifecycle events to a webhook as they
happen: certificate added and renewed, posture changed, scan failed, policy
violation, alert acknowledged and renewal overdue. This suits a SIEM or a chat
channel that wants a running feed rather than alerts. It is rate-limited and
uses the same webhook formats and allowlist.

## When alerts don't arrive

1. **Activity → Alerts** shows the alert's state and each attempt's outcome and
   reason. That is almost always where the answer is.
2. **Settings → Channels** has a **Send test email** button. For the webhook,
   `POST /api/webhook/test` (as an administrator) sends a test message and
   returns the delivery result.
3. `cert-watch routing-report` on a backup shows who the alert should have gone
   to.
4. A long run of *pending* alerts with no attempts means no channel is
   configured, or the scheduler isn't running. For the latter, check `/readyz`
   and [operations.md](operations.md#troubleshooting).
