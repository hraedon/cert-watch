"""Alert channel adapters -- deprecated re-export shim.

Deprecated: plan 058 moved this code into ``cert_watch.alerting``. This module
only re-exports the old names and will be deleted in plan 058 PR 5. Import
from ``cert_watch.alerting`` instead, and patch names where they are looked up
there -- patching this module no longer reaches the moved code.
"""

from __future__ import annotations

from cert_watch.alerting.transports.adapters import (
    _ADAPTERS,
    _ALERT_NAMES,
    _PAGERDUTY_EVENTS_URL,
    _WEBHOOK_KIND_LABELS,
    WEBHOOK_KIND_OPTIONS,
    AlertAdapter,
    AlertmanagerAdapter,
    AlertRequest,
    DiscordAdapter,
    GenericAdapter,
    PagerDutyAdapter,
    SlackAdapter,
    TeamsAdapter,
    _alertname,
    _pd_dedup_key,
    _pd_severity,
    _slack_color,
    _status_color,
    _status_urgency,
    get_adapter,
)

__all__ = [
    "WEBHOOK_KIND_OPTIONS",
    "_ADAPTERS",
    "_ALERT_NAMES",
    "_PAGERDUTY_EVENTS_URL",
    "_WEBHOOK_KIND_LABELS",
    "AlertAdapter",
    "AlertRequest",
    "AlertmanagerAdapter",
    "DiscordAdapter",
    "GenericAdapter",
    "PagerDutyAdapter",
    "SlackAdapter",
    "TeamsAdapter",
    "_alertname",
    "_pd_dedup_key",
    "_pd_severity",
    "_slack_color",
    "_status_color",
    "_status_urgency",
    "get_adapter",
]
