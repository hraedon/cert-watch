# Home surface brief

## Purpose

Home is the operator's attention queue. It answers, in order: what is already
bad, what needs action next, whether scan coverage is complete enough to trust
that answer, and whether renewal work is clustering in the next twelve weeks.

## Structure

**Archetype:** Dashboard (posture at a glance). The page uses one persistent
grid: operational scopes, expiry horizon, then an urgency-ordered work list.

It must show certificate urgency counts with neutral zeroes, tracked-estate and
scan-coverage counts, the twelve-week expiry horizon with storm counts, and an
actionable queue that identifies endpoint, reason, owner, and evidence
confidence. Empty state must explain how to begin monitoring.

## Ownership and boundaries

Home owns prioritization and coverage confidence. It does not own the complete
inventory, fleet security posture, certificate editing, or historical logs;
those belong to Browse, Posture, Certificate detail, and Activity.
