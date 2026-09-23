# cert-watch

[![CI](https://github.com/hraedon/cert-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/hraedon/cert-watch/actions/workflows/ci.yml)

cert-watch keeps track of every TLS certificate an organisation depends on,
and tells the right people before one causes an outage.

It is self-hosted and built for small and mid-sized organisations that have
dozens to a few thousand certificates spread across public websites, internal
services, domain controllers, appliances and files nobody remembers. You tell
it where to look, and it answers three questions:

- **What expires, and when?** Every certificate, its expiry, and whether the
  renewal that should have replaced it has actually happened.
- **Is it healthy?** Signature-verified chain validation against your trust
  anchors, a TLS posture grade, and the weak spots: SHA-1, short keys, old
  protocol versions, missing intermediates.
- **Who needs to know?** Alerts routed by tag and ownership to email, Teams,
  Slack, Discord, PagerDuty, Alertmanager or a webhook, with a record of every
  delivery attempt.

## What it does

- **Scans hosts** over TLS, including STARTTLS for SMTP, LDAP and friends, on
  a daily schedule or per-host cadence. It also accepts **certificate files**
  in PEM, DER, PKCS#12 and PKCS#7 for things it can't reach.
- **Tracks renewals.** It links each certificate to its successor, flags
  renewals that stall before they turn into expiries, and can call your
  automation through a renewal webhook.
- **Grades posture** per endpoint and across the fleet, with trends over time
  and a signed compliance report for auditors.
- **Routes alerts** through alert groups matched on tags, with owners, digests
  and retries, and shows the delivery evidence for each alert.
- **Controls access** through LDAP / Active Directory or OAuth / OIDC (Entra ID,
  Google, …), with local accounts, role mapping, per-tag scoping and API keys.
- **Keeps an audit log** of every sign-in and change, and can forward it to
  syslog, Splunk HEC or the Windows Event Log.
- **Runs anywhere** as one process with one SQLite file: in a container, on
  Kubernetes, under systemd, or on Windows behind IIS. Prometheus metrics
  included.

It deliberately does **not** issue or renew certificates, discover assets on
its own, or monitor Certificate Transparency logs. Tools such as Certimate or
cert-manager, your inventory, and Cert Spotter do those better;
[docs/positioning.md](docs/positioning.md) explains where cert-watch fits.

## Try it

```bash
docker run -d --name cert-watch -p 8000:8000 \
  -v cert-watch-data:/var/lib/cert-watch ghcr.io/hraedon/cert-watch:latest
docker exec cert-watch cat /var/lib/cert-watch/initial-admin-password
```

Open <http://localhost:8000>, sign in as `admin`, and add a host with
**Browse → Add host**. The first scan runs immediately.

For anything longer-lived, follow [docs/install.md](docs/install.md). It covers
pinning and verifying a release, and sets out what to configure before
production.

## Documentation

| | |
|---|---|
| [Installing](docs/install.md) | Container, Kubernetes, Linux, Windows / IIS; first start; production checklist |
| [Configuration](docs/configuration.md) | Every setting, with its default and effect |
| [Access control](docs/access-control.md) | Accounts, roles, directory mapping, scoping, API keys |
| [Alerting](docs/alerting.md) | How alerts are raised, routed, delivered and retried |
| [Operations](docs/operations.md) | Monitoring, backups, retention, secrets, troubleshooting |
| [Upgrading](UPGRADING.md) | What changed between versions, and what to do about it |
| [Security](SECURITY.md) and [threat model](docs/threat-model.md) | Reporting a vulnerability; what cert-watch defends against |
| [Architecture](docs/architecture.md) | How the code is organised, for contributors |
| [Contributing](CONTRIBUTING.md) | Development setup, tests, review expectations |
| [Changelog](CHANGELOG.md) | Every release |

## License

MIT. See [LICENSE](LICENSE).
