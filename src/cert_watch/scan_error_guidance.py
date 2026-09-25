"""Explain a stored scan error in plain language, with a next step.

Scan errors are stored as the text the scanner produced: Python ``ssl`` /
OpenSSL reasons (``[SSL: WRONG_VERSION_NUMBER] ...``), socket errors, or
cert-watch's own messages. Operators need to know what probably happened and
what to try; the raw text stays available beside the explanation, since a
guess is only a guess.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanErrorGuidance:
    cause: str
    next_step: str


# Ordered: the first matching needle wins. Needles are matched against the
# lower-cased stored message.
_RULES: tuple[tuple[tuple[str, ...], ScanErrorGuidance], ...] = (
    (
        ("dns resolution failed", "could not resolve hostname", "name or service not known",
         "nodename nor servname"),
        ScanErrorGuidance(
            "The host name does not resolve in DNS.",
            "Check the spelling. If the host was retired, remove it here; if it moved, "
            "update its DNS record or the host name.",
        ),
    ),
    (
        ("blocked address", "outside the configured cert_watch_allowed_subnets"),
        ScanErrorGuidance(
            "The host resolves to an address cert-watch is not allowed to scan.",
            "If the address is expected, an administrator can allow its range "
            "(CERT_WATCH_ALLOWED_SUBNETS or CERT_WATCH_ALLOW_PRIVATE_IPS). "
            "Loopback and link-local addresses are never scanned.",
        ),
    ),
    (
        ("connection refused",),
        ScanErrorGuidance(
            "Nothing is accepting connections on this port.",
            "Check that the service is running and listening on this port, and that "
            "the port number is right.",
        ),
    ),
    (
        ("timed out", "timeout"),
        ScanErrorGuidance(
            "The host did not answer in time.",
            "Check that the host is up and that a firewall allows cert-watch to reach "
            "this port.",
        ),
    ),
    (
        ("network is unreachable", "network unreachable", "no route to host"),
        ScanErrorGuidance(
            "cert-watch has no network route to the host.",
            "Check routing and firewall rules between cert-watch and the host.",
        ),
    ),
    (
        ("wrong_version_number", "wrong version number"),
        ScanErrorGuidance(
            "The port answered, but not with TLS: it may be a plain-text port, or a "
            "service that needs STARTTLS first.",
            "Check the port number. A mail, LDAP or similar service that upgrades "
            "with STARTTLS needs the host added with that TLS mode.",
        ),
    ),
    (
        ("unexpected_eof", "eof occurred in violation of protocol", "connection reset",
         "connection aborted"),
        ScanErrorGuidance(
            "The server closed the connection during the TLS handshake.",
            "The TLS service may be down or overloaded, or a proxy or firewall may be "
            "cutting the connection. Check the service's own logs, then scan again.",
        ),
    ),
    (
        ("tlsv1_alert_protocol_version", "unsupported protocol", "no protocols available"),
        ScanErrorGuidance(
            "The server and cert-watch share no TLS version.",
            "The server may only offer outdated TLS versions. Enable TLS 1.2 or later "
            "on the server.",
        ),
    ),
    (
        ("handshake_failure", "handshake failure", "handshake failed", "no shared cipher"),
        ScanErrorGuidance(
            "The server rejected the TLS handshake.",
            "The server may require a client certificate, a specific server name, or "
            "ciphers cert-watch does not offer. Check the server's TLS configuration.",
        ),
    ),
    (
        ("no certificate presented",),
        ScanErrorGuidance(
            "The TLS handshake finished without the server presenting a certificate.",
            "Check that a certificate is bound to this port and host name.",
        ),
    ),
)


def describe_scan_error(message: str | None) -> ScanErrorGuidance | None:
    """Return a plain-language cause and next step, or ``None`` when the error
    is not one cert-watch recognises (the raw text is then all there is)."""
    if not message:
        return None
    text = message.lower()
    for needles, guidance in _RULES:
        if any(needle in text for needle in needles):
            return guidance
    return None
