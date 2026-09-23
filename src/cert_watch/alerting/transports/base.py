"""Helpers shared by every transport."""

from __future__ import annotations

import re
from typing import Protocol

from cert_watch.alerting.model import OutboundMessage, SendResult


class Transport(Protocol):
    """A destination capable of sending one transport-ready message."""

    channel: str
    destination_id: str

    def send(self, msg: OutboundMessage) -> SendResult: ...


def _redact_secret(msg: str, secret: str) -> str:
    """Redact a secret from a diagnostic message.

    For secrets >= 4 chars, a plain substring replace is safe. For shorter
    secrets (B4: the previous ``>= 4`` gate leaked 1-3 char passwords/routing
    keys into operator messages and WARNING logs), use word-boundary
    regex so a 1-char password like ``p`` redacts the standalone token ``p``
    but does not corrupt common substrings like ``nope`` or ``smtp``.
    """
    if not secret:
        return msg
    if len(secret) >= 4:
        return msg.replace(secret, "***")
    return re.sub(rf"(?<!\w){re.escape(secret)}(?!\w)", "***", msg)
