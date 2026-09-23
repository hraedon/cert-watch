"""Renewal and orphan digests -- deprecated re-export shim.

Deprecated: plan 058 moved this code into ``cert_watch.alerting``. This module
only re-exports the old names and will be deleted in plan 058 PR 5. Import
from ``cert_watch.alerting`` instead, and patch names where they are looked up
there -- patching this module no longer reaches the moved code.
"""

from __future__ import annotations

from cert_watch.alerting.digest.engine import (
    _webhook_channel,
)
from cert_watch.alerting.digest.orphan import (
    _admin_emails,
    _build_orphan_message,
    send_orphan_notice,
)
from cert_watch.alerting.digest.pool import (
    _detach_digest_pool,
    _flush_digest_pool,
    _handle_digest_task_completion,
    _submit_digest_task,
    shutdown_digest_pool,
    start_digest_pool,
)
from cert_watch.alerting.digest.renewal import (
    RenewalDigest,
    _build_digest_message,
    _Endpoint,
    _endpoint_label,
    _event_endpoint,
    _fmt_expiry,
    _merge_owner_address_variants,
    _parse_event_payload,
    build_renewal_digest,
    send_renewal_digest,
)

__all__ = [
    "RenewalDigest",
    "_Endpoint",
    "_admin_emails",
    "_build_digest_message",
    "_build_orphan_message",
    "_detach_digest_pool",
    "_endpoint_label",
    "_event_endpoint",
    "_flush_digest_pool",
    "_fmt_expiry",
    "_handle_digest_task_completion",
    "_merge_owner_address_variants",
    "_parse_event_payload",
    "_submit_digest_task",
    "_webhook_channel",
    "build_renewal_digest",
    "send_orphan_notice",
    "send_renewal_digest",
    "shutdown_digest_pool",
    "start_digest_pool",
]
