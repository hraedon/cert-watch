"""Email and webhook alerts -- deprecated re-export shim.

Deprecated: plan 058 moved this code into ``cert_watch.alerting``. This module
only re-exports the old names and will be deleted in plan 058 PR 5. Import
from ``cert_watch.alerting`` instead, and patch names where they are looked up
there -- patching this module no longer reaches the moved code.
"""

from __future__ import annotations

import smtplib

from cert_watch.alerting.digest.engine import (
    _send_claimed_digest_smtp,
)
from cert_watch.alerting.digest.expiry import (
    _build_digest_email,
    _build_digest_message,
    _send_digest_smtp,
    _send_digest_webhook,
    send_expiry_digest,
)
from cert_watch.alerting.dispatch import (
    _attempt_once,
    _Delivery,
    _settle_evidence_deferral,
    process_pending,
)
from cert_watch.alerting.messages import (
    _format_message,
    _format_renewal_message,
)
from cert_watch.alerting.model import (
    ALERT_CYCLE_BUDGET_SECONDS,
    ALERT_MAX_RETRIES,
    ALERT_RETRY_DELAY,
    CHAIN_THRESHOLDS,
    EVIDENCE_DEFERRAL_GIVE_UP_HOURS,
    LEAF_THRESHOLDS,
    SHORT_CERT_LIFETIME_DAYS,
    SHORT_LIFETIME_CHAIN_PCT,
    SHORT_LIFETIME_LEAF_PCT,
    UNDELIVERED_AFTER_HOURS,
    URGENT_THRESHOLD_DAYS,
    AlertConfig,
    WebhookConfig,
    delivery_is_configured,
)
from cert_watch.alerting.resolve import (
    resolve_webhook_for_renewed_cert,
)
from cert_watch.alerting.routing import (
    _load_host_owner_maps,
    _load_role_user_emails,
    _resolve_group_config,
    find_orphan_certs,
    resolve_all_group_recipients,
    resolve_cert_recipients,
    resolve_group_recipients,
    resolve_group_thresholds,
)
from cert_watch.alerting.rules.expiry import (
    effective_thresholds,
    evaluate_all_certs,
    evaluate_thresholds,
)
from cert_watch.alerting.rules.policy import (
    evaluate_policy_alerts,
)
from cert_watch.alerting.rules.renewal import (
    evaluate_renewal_window,
    renewal_window_candidates,
)
from cert_watch.alerting.transports.base import (
    _redact_secret,
)
from cert_watch.alerting.transports.smtp import (
    _check_smtp_ssrf,
    _open_smtp_connection,
    _sanitize_smtp_error,
    _smtp_recipients,
    _validate_email,
    connect_smtp_transport,
    negotiate_starttls,
    send_alert,
)
from cert_watch.alerting.transports.webhook import (
    _adapter_has_build_resolve,
    _sanitize_webhook_error,
    send_webhook,
    send_webhook_resolve,
)
from cert_watch.database import (
    Alert,
    AlertRepository,
)
from cert_watch.http_client import (
    SSRFBlockedError,
    resolve_smtp_host,
    ssrf_safe_urlopen,
    validate_smtp_host,
)
from cert_watch.retry import (
    backoff_range,
)

__all__ = [
    "ALERT_CYCLE_BUDGET_SECONDS",
    "ALERT_MAX_RETRIES",
    "ALERT_RETRY_DELAY",
    "CHAIN_THRESHOLDS",
    "EVIDENCE_DEFERRAL_GIVE_UP_HOURS",
    "LEAF_THRESHOLDS",
    "SHORT_CERT_LIFETIME_DAYS",
    "SHORT_LIFETIME_CHAIN_PCT",
    "SHORT_LIFETIME_LEAF_PCT",
    "UNDELIVERED_AFTER_HOURS",
    "URGENT_THRESHOLD_DAYS",
    "Alert",
    "AlertConfig",
    "AlertRepository",
    "SSRFBlockedError",
    "WebhookConfig",
    "_Delivery",
    "_adapter_has_build_resolve",
    "_attempt_once",
    "_build_digest_email",
    "_build_digest_message",
    "_check_smtp_ssrf",
    "_format_message",
    "_format_renewal_message",
    "_load_host_owner_maps",
    "_load_role_user_emails",
    "_open_smtp_connection",
    "_redact_secret",
    "_resolve_group_config",
    "_sanitize_smtp_error",
    "_sanitize_webhook_error",
    "_send_claimed_digest_smtp",
    "_send_digest_smtp",
    "_send_digest_webhook",
    "_settle_evidence_deferral",
    "_smtp_recipients",
    "_validate_email",
    "backoff_range",
    "connect_smtp_transport",
    "delivery_is_configured",
    "effective_thresholds",
    "evaluate_all_certs",
    "evaluate_policy_alerts",
    "evaluate_renewal_window",
    "evaluate_thresholds",
    "find_orphan_certs",
    "negotiate_starttls",
    "process_pending",
    "renewal_window_candidates",
    "resolve_all_group_recipients",
    "resolve_cert_recipients",
    "resolve_group_recipients",
    "resolve_group_thresholds",
    "resolve_smtp_host",
    "resolve_webhook_for_renewed_cert",
    "send_alert",
    "send_expiry_digest",
    "send_webhook",
    "send_webhook_resolve",
    "smtplib",
    "ssrf_safe_urlopen",
    "validate_smtp_host",
]
