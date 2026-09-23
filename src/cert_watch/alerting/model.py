"""Alert configuration, threshold constants and delivery policy constants.

Imports the standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LEAF_THRESHOLDS = (14, 7, 3, 1)

CHAIN_THRESHOLDS = (30, 14, 7)
# In digest mode, per-certificate alerts at or below this many days to expiry
# still fire individually (the final-countdown "3/2/1" alerts); the routine
# heads-up thresholds are left to the weekly digest. See evaluate_thresholds.
URGENT_THRESHOLD_DAYS = 3
SHORT_CERT_LIFETIME_DAYS = 90
SHORT_LIFETIME_LEAF_PCT = (50, 25, 10)
SHORT_LIFETIME_CHAIN_PCT = (50, 25, 10)


@dataclass
class AlertConfig:
    """SMTP configuration. See AC-01."""

    smtp_host: str
    smtp_user: str
    smtp_password: str
    from_addr: str
    recipients: list[str] = field(default_factory=list)
    smtp_port: int = 587
    # SSRF policy for the SMTP host (BC-116 SMTP parity). Defaults mirror
    # Settings.allow_private / CERT_WATCH_ALLOW_PRIVATE_IPS=1 so the common
    # case of an internal relay is unaffected; populated from Settings by
    # Settings.build_alert_config.
    allow_private: bool = True
    allowed_subnets: tuple[str, ...] = ()


@dataclass
class WebhookConfig:
    """Webhook/Slack alert configuration."""

    url: str
    kind: str = "generic"
    routing_key: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 15
    template: str = ""
    allow_private: bool = False
    allowed_subnets: tuple[str, ...] = ()


ALERT_MAX_RETRIES = 3
ALERT_RETRY_DELAY = 2  # seconds between retries

# Wall-clock ceiling on one process_pending cycle. The scheduler calls the
# alert phase synchronously, so whatever this costs, the rest of the cycle --
# scanning above all -- waits for it. That matters most precisely when delivery
# is failing, which is when an operator least wants scanning to stop.
#
# Generous by design: a healthy 100-alert queue clears in well under a second,
# and 1000 in a few, so this only engages when something is actually wrong.
# Alerts left unattempted stay pending and go out on the next cycle.
ALERT_CYCLE_BUDGET_SECONDS = 300.0

# How long an alert may sit `pending` before the estate treats it as undelivered.
# One full daily cycle plus slack: anything older has missed a send it should
# have caught. Read by the health check and the Activity view, which must agree
# -- two different ideas of "overdue" is how one surface reassures an operator
# the other is trying to warn.
UNDELIVERED_AFTER_HOURS = 24

# How long delivery may keep being deferred because the evidence store refuses
# the write that must precede a send, before the alert is marked failed. The
# clock is ``alerts.deferred_since`` (migration 0033): stamped at the first
# deferred cycle, kept across later ones, restarted by any recorded attempt and
# cleared by every status change. ``created_at`` is the wrong clock, because
# ``evaluate_all_certs`` resets a failed alert to pending with its original
# ``created_at``, so one transient lock on an old alert would read as a
# days-long outage and flip-flop forever (#38). Three daily cycles: the health
# check and Activity view already flag the alert as undelivered after
# UNDELIVERED_AFTER_HOURS, so this only has to make a persistent outage
# terminate visibly, not detect it first.
EVIDENCE_DEFERRAL_GIVE_UP_HOURS = 72


def delivery_is_configured(settings: Any) -> bool:
    """Whether any transport exists for ``process_pending`` to try.

    ``process_pending`` returns immediately when neither SMTP nor a webhook is
    configured, so on a dashboard-only install every alert stays ``pending``
    for ever, by design and not by fault. The surfaces that call an old pending
    alert *undelivered* -- the health counter and the Activity chip -- mean
    "should have been sent and was not", so they must ask this first or they
    accuse a deliberately configured estate of an outage it is not having.

    Mirrors the choice the flush route makes when it builds the two configs, so
    the warning and the delivery path cannot disagree about what is configured.
    """
    return bool(getattr(settings, "smtp_host", None) or getattr(settings, "webhook_url", None))
