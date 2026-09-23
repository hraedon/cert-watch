"""Alert transports: SMTP, webhooks and the per-provider webhook adapters."""

from cert_watch.alerting.transports.base import Transport
from cert_watch.alerting.transports.smtp import SmtpTransport
from cert_watch.alerting.transports.webhook import WebhookTransport

__all__ = ["SmtpTransport", "Transport", "WebhookTransport"]
