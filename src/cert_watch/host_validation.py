"""Syntactic validation for hostnames persisted by cert-watch."""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata

MAX_HOSTNAME_OCTETS = 253


def hostname_is_valid(hostname: str) -> bool:
    """Validate an IP literal or an RFC 1035 hostname after IDNA encoding."""
    try:
        canonical_hostname(hostname)
    except ValueError:
        return False
    return True


def legacy_ipv4_dotted_quad(name: str) -> str | None:
    """The dotted quad the resolver reads *name* as, for the legacy numeric
    IPv4 forms ``inet_aton`` accepts (octal or hex octets, fewer than four
    parts, a bare integer); ``None`` for anything else, including any name
    with a character outside ``[0-9a-fA-FxX.]``."""
    if not re.fullmatch(r"[0-9a-fA-FxX.]+", name):
        return None
    try:
        packed = socket.inet_aton(name)
    except OSError:
        return None
    return socket.inet_ntoa(packed)


def canonical_hostname(hostname: str) -> str:
    """Return the one canonical spelling of a host identifier, or raise ValueError.

    Every spelling of an endpoint must map to one stored string, because the
    ``hosts(hostname, port)`` uniqueness rule, the scope check on an existing
    endpoint and every ``(hostname, port)`` join are textual:

    - an IP literal becomes ``ipaddress.ip_address(...).compressed`` (so
      ``2001:0db8:0:0:0:0:0:1`` and ``[2001:db8::1]`` are ``2001:db8::1``);
    - a DNS name becomes its lower-case IDNA A-label form with no trailing dot
      (so ``VICTIM.example.test.`` is ``victim.example.test`` and
      ``café.example.test`` is ``xn--caf-dma.example.test``).

    The validation is :func:`hostname_is_valid`'s; the canonical form of a
    valid name is itself valid and canonicalizes to itself.
    """
    # Bound the input before doing any codec work.  IDNA2003 (the codec in the
    # standard library) maps some characters away, so checking only the
    # encoded result would allow an arbitrarily large string of ignored
    # characters through the IP and hostname paths.
    if len(hostname) > MAX_HOSTNAME_OCTETS + 1:
        raise ValueError("hostname too long")
    if any(ord(char) <= 32 or ord(char) == 127 for char in hostname):
        raise ValueError("hostname contains whitespace or control characters")
    name = hostname[:-1] if hostname.endswith(".") else hostname
    if not name or len(name) > MAX_HOSTNAME_OCTETS:
        raise ValueError("hostname is empty or too long")
    literal = name[1:-1] if name.startswith("[") and name.endswith("]") else name
    try:
        address = ipaddress.ip_address(literal)
    except ValueError:
        pass
    else:
        # Scoped IPv6 literals (for example ``fe80::1%eth0``) are socket
        # interface references, not portable DNS/TLS host identifiers.
        if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
            raise ValueError("scoped IPv6 literals are not portable host identifiers")
        return address.compressed
    if legacy_ipv4_dotted_quad(literal) is not None:
        # ``010.010.010.010``, ``8.8.2056``, ``134744072``, ``0x08080808``:
        # not an address to ``ipaddress`` but one to the resolver, so it would
        # be stored as a "DNS name" that is really another spelling of an
        # IPv4 endpoint (#116 review). No real DNS name has this shape.
        raise ValueError("IPv4 literals must be written as a dotted quad")
    try:
        encoded = name.encode("idna")
    except UnicodeError as exc:
        raise ValueError("hostname is not a valid IDNA name") from exc
    if len(encoded) > MAX_HOSTNAME_OCTETS:
        raise ValueError("hostname exceeds 253 octets after IDNA encoding")
    normalized = unicodedata.normalize("NFC", name)
    original_labels = normalized.split(".")
    encoded_labels = encoded.split(b".")
    if len(original_labels) != len(encoded_labels):
        raise ValueError("hostname labels do not survive IDNA encoding")
    for original_label, encoded_label in zip(
        original_labels, encoded_labels, strict=True
    ):
        if not (
            1 <= len(encoded_label) <= 63
            and not encoded_label.startswith(b"-")
            and not encoded_label.endswith(b"-")
            and re.fullmatch(rb"[A-Za-z0-9-]+", encoded_label) is not None
        ):
            raise ValueError("hostname label is not a valid LDH label")
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
        except UnicodeError as exc:
            raise ValueError("hostname label does not round-trip through IDNA") from exc
        if decoded_label.lower() != original_label.lower():
            raise ValueError("IDNA mapping changes the hostname")
    # ToASCII leaves an all-ASCII label as written, so the case fold is explicit.
    return encoded.decode("ascii").lower()
