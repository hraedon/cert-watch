# Security policy

## Supported versions

Security fixes are applied to the latest 1.x release and to `main`. Older
releases do not receive backports; upgrade to the latest 1.x.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Latest `1.x` release | Yes |
| Older releases | No |

Before reporting, upgrade to the latest release in case the behavior is already
fixed.

## Reporting a vulnerability

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/hraedon/cert-watch/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability.

Include the affected version or commit, deployment shape, prerequisites,
reproduction steps, observed impact and any suggested fix. Remove real
credentials, private keys, internal hostnames and personal data from the
report. You should receive an acknowledgement within five business days. The
maintainer coordinates validation, remediation, release timing and public
disclosure with you.

## Security boundaries

The living [threat model](docs/threat-model.md) documents assets, trust
boundaries, attacker capabilities, deployment assumptions and current
controls. Reports are most useful when they show a violation of one of these
properties:

- exposed deployments establish authentication or fail closed;
- state-changing cookie-authenticated requests require CSRF validation;
- sessions, API keys, roles, and tag scopes authorize every protected object and
  operation;
- attacker-influenced network destinations remain within the configured address
  policy across DNS resolution, redirects, and retries;
- uploads, parsers, subprocesses, network reads, and retries remain bounded;
- secrets, trust decisions, audit evidence, and release artifacts retain their
  intended confidentiality and integrity.

Configuration questions, hardening suggestions without a demonstrated boundary
violation, and findings that require prior compromise of the host, identity
provider, external integration, repository maintainer or release authority are
still welcome. They may be handled as ordinary issues once sensitive details
are removed.

## Changes that require security review

A change requires an explicit security review when it affects authentication,
sessions, CSRF, API keys, role or tag scoping, scan address policy, DNS pinning,
redirect handling, trust-anchor authority, upload bounds, secret storage,
reverse-proxy trust, public endpoints, an external sink, or release authority.
The same change must update the threat model when it changes an asset, trust
boundary, attacker capability, deployment assumption, or security objective.
