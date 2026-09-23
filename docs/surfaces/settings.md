# Settings surface brief

## Purpose

Settings is the administrative control plane. It answers: how is access
controlled, where are alerts and events sent, which policy and trust inputs are
active, and what persisted configuration overrides the defaults?

## Structure

**Archetype:** Settings. A persistent section navigation leads to one
single-column section per route: authentication, roles, users, API keys, tags,
channels, alert groups, event export, policy, and trust anchors.

Every control must state its operational effect and whether environment
configuration overrides it. Secret inputs must not echo stored values.
Destructive actions must be separated and state their consequence. Read-only
or unauthorized users must see configuration without being offered writes.

## Ownership and boundaries

Settings owns system-wide configuration and administrative records. It does
not own host-specific metadata, certificate remediation, live triage, or
historical evidence. Those remain on Certificate detail, Posture/Home, and
Activity.
