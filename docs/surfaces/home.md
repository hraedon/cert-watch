# Home surface brief

## Purpose

Home is the operator's compact triage surface. It separates certificate risk
(expiry and renewal) from certificate hygiene (chain and trust problems), keeps
monitoring and alert delivery visible without letting them take space while
healthy, and shows where expiry work lands over the next twelve weeks.

## Structure

**Archetype:** Dashboard (posture at a glance). From top to bottom:

1. **Status strip.** While monitoring and delivery are healthy, they share one
   two-cell strip: counts on the first line, scan schedule or delivery state on
   the second. Either one opens into a full block above the strip when it has
   problems (monitoring rows, or a delivery line with a status tone), and the
   strip disappears when both are open.
2. **Certificate risk | Certificate hygiene**, two separate cards side by side
   (stacked below 1100 px). Risk is the only one with status colour.
3. A clickable twelve-week expiry strip.

Every count and week opens the exact flat Browse population it counts. Expiry
rows are ranked by days. Failed and unconfirmed renewal deployments appear in
Certificate risk after expiry rows, even when the certificate is not near
expiry; their counts link to the matching renewal-filtered Browse population.
Risk and monitoring rows share one grammar: state, name and owner on the first
line, with an optional detail line under the name, and state labels aligned
across rows.

Chain-trust problems live in Certificate hygiene, collapsed to one row per
issuer and grouped by the fix they need (invalid chain, missing intermediate or
private CA, self-signed), so each fix's guidance prints once. Hygiene is
neutral: these problems don't get worse with time, though strict clients may
already reject the certificates. A risk row whose chain is also unverified
carries a small broken-chain icon linking to that issuer's unverified
certificates, so the chain can be fixed at renewal. Monitoring rows
distinguish failed, overdue, and never-scanned endpoints, explain failures in
plain language, and state when the problem began. Delivery shows problem
channels and scoped owner/group routing gaps, or one neutral all-delivering
line. Empty state explains how to begin.

## Ownership and boundaries

Home owns read-only triage and monitoring confidence. It does not own inventory,
editing, scan actions, fleet posture, or historical logs; those belong to
Browse, Certificate detail, Posture, Scan history, and Activity. Tag-scoped
users see only scoped counts and rows, and never routing identities or group
names.
