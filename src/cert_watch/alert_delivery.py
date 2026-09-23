"""Alert delivery evidence -- deprecated re-export shim.

Deprecated: plan 058 moved this code into ``cert_watch.alerting``. This module
only re-exports the old names and will be deleted in plan 058 PR 5. Import
from ``cert_watch.alerting`` instead, and patch names where they are looked up
there -- patching this module no longer reaches the moved code.
"""

from __future__ import annotations

from cert_watch.alerting.evidence import (
    FAILURE_LABELS,
    REFUSED_NO_EVIDENCE,
    DeliveryEvidenceUnavailable,
    _active,
    _matching_groups,
    _Observation,
    attempt_delivery,
    observe_exception,
    observe_failure,
    observe_http,
    observe_smtp,
)
from cert_watch.database.delivery_evidence import (
    begin_attempt,
    complete_attempt,
)

__all__ = [
    "FAILURE_LABELS",
    "REFUSED_NO_EVIDENCE",
    "DeliveryEvidenceUnavailable",
    "_Observation",
    "_active",
    "_matching_groups",
    "attempt_delivery",
    "begin_attempt",
    "complete_attempt",
    "observe_exception",
    "observe_failure",
    "observe_http",
    "observe_smtp",
]
