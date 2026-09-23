"""Alerting: rules, routing, transports, delivery and digests (plan 058).

The package is being assembled in stages. This first stage only moves the code
that used to live in ``cert_watch.alerts``, ``alert_delivery``,
``alert_adapters`` and ``digest`` into the modules plan 058 assigns it to; the
facade grows as the later stages introduce ``Dispatcher`` and
``DigestEngine``. Callers may import from this facade or from its public
submodules.
"""

from __future__ import annotations

from cert_watch.alerting.model import AlertConfig, WebhookConfig

__all__ = ["AlertConfig", "WebhookConfig"]
