# Certificate detail surface brief

## Purpose

Certificate detail is the decision-complete view of one certificate or one
pending monitored endpoint. It answers: what is this object, is it valid and
trusted, who owns renewal, what changed, and what action can the operator take
here?

## Structure

**Archetype:** Record detail. The identity header is followed by panels in task
order: validity and endpoint responsibility, posture and chain guidance,
renewal history and drift, metadata, then technical certificate material.

It must show source and endpoint identity, expiry urgency, validity interval,
owner and renewal method, scan confidence, posture findings, current chain
result and remediation, renewal/drift history, tags and notes, SANs,
fingerprint, serial, algorithms, and stored chain certificates. Pending hosts
must show latest scan status and error without pretending a certificate exists.

## Ownership and boundaries

This page owns the single editing controls for endpoint settings, host-scoped
notes, and tags, plus scan/download/delete actions allowed by authorization. It
does not duplicate fleet filtering, global posture trends, alert delivery
history, or system configuration.
