"""Syntactic validation for hostnames persisted by cert-watch."""

from __future__ import annotations

import ipaddress
import re
import unicodedata

MAX_HOSTNAME_OCTETS = 253


def hostname_is_valid(hostname: str) -> bool:
    """Validate an IP literal or an RFC 1035 hostname after IDNA encoding."""
    # Bound the input before doing any codec work.  IDNA2003 (the codec in the
    # standard library) maps some characters away, so checking only the
    # encoded result would allow an arbitrarily large string of ignored
    # characters through the IP and hostname paths.
    if len(hostname) > MAX_HOSTNAME_OCTETS + 1:
        return False
    if any(ord(char) <= 32 or ord(char) == 127 for char in hostname):
        return False
    name = hostname[:-1] if hostname.endswith(".") else hostname
    if not name or len(name) > MAX_HOSTNAME_OCTETS:
        return False
    try:
        address = ipaddress.ip_address(name)
        # Scoped IPv6 literals (for example ``fe80::1%eth0``) are socket
        # interface references, not portable DNS/TLS host identifiers.
        return not (
            isinstance(address, ipaddress.IPv6Address)
            and address.scope_id is not None
        )
    except ValueError:
        pass
    try:
        encoded = name.encode("idna")
    except UnicodeError:
        return False
    if len(encoded) > MAX_HOSTNAME_OCTETS:
        return False
    normalized = unicodedata.normalize("NFC", name)
    original_labels = normalized.split(".")
    encoded_labels = encoded.split(b".")
    if len(original_labels) != len(encoded_labels):
        return False
    for original_label, encoded_label in zip(
        original_labels, encoded_labels, strict=True
    ):
        if not (
            1 <= len(encoded_label) <= 63
            and not encoded_label.startswith(b"-")
            and not encoded_label.endswith(b"-")
            and re.fullmatch(rb"[A-Za-z0-9-]+", encoded_label) is not None
        ):
            return False
        # ASCII A-labels (including valid ``xn--`` labels) are already in the
        # canonical wire form and cannot be compared to the decoded Unicode
        # label directly.
        if all(ord(char) < 128 for char in original_label):
            continue
        # Reject IDNA mappings that silently remove or replace input
        # characters (e.g. zero-width characters or IDNA2003's ``ß`` ->
        # ``ss`` mapping).  Canonically equivalent Unicode forms remain
        # accepted after NFC normalization.
        try:
            decoded_label = encoded_label.decode("idna")
        except UnicodeError:
            return False
        if decoded_label.lower() != original_label.lower():
            return False
    return True
