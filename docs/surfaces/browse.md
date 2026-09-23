# Browse surface brief

## Purpose

Browse is the complete certificate and monitored-endpoint inventory. It answers:
which objects match the operator's scope, when they expire, how they renew, who
owns them, and whether the evidence for each monitored endpoint is current.

## Structure

**Archetype:** Inventory (the complete object list). Search, status/source
scopes, grouping, sorting, pagination, and fleet pivots lead directly to the
objects they control.

It must show identity, endpoint/source, expiry and urgency, issuer, renewal
method, ownership, tags, posture grade, chain state, and scan freshness where
available. Issuer, owner, renewal-method, and calendar views must preserve the
same inventory scope and operational counts.

## Ownership and boundaries

Browse owns discovery, filtering, grouping, and navigation to one record. It
does not own the prioritized action queue, detailed remediation, settings, or
activity history. Aggregate counts are controls here, not decorative metrics.
