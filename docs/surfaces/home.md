# Home surface brief

## Purpose

Home is the operator's compact triage surface. It separates certificate expiry
and chain risk from monitoring gaps and alert delivery/routing, then shows where
expiry work lands over the next twelve weeks.

## Structure

**Archetype:** Dashboard (posture at a glance). Three blocks sit side by side on
desktop and stack on phones: Certificate risk, Monitoring gaps, and Delivery &
routing. A clickable twelve-week expiry strip follows them.

Every count and week opens the exact flat Browse population it counts. Expiry
rows are ranked by days. Failed and unconfirmed renewal deployments appear in
Certificate risk after expiry rows, even when the certificate is not near
expiry; their counts link to the matching renewal-filtered Browse population.
Chain-trust problems are collapsed to one row per
issuer instead of competing with expiry. Monitoring rows distinguish failed,
overdue, and never-scanned endpoints, explain failures in plain language, and
state when the problem began. Delivery shows problem channels and scoped
owner/group routing gaps, or one neutral all-delivering line. Empty state
explains how to begin.

## Ownership and boundaries

Home owns read-only triage and monitoring confidence. It does not own inventory,
editing, scan actions, fleet posture, or historical logs; those belong to
Browse, Certificate detail, Posture, Scan history, and Activity. Tag-scoped
users see only scoped counts and rows, and never routing identities or group
names.
