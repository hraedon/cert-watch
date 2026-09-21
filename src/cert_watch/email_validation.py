"""Validation for email addresses stored or passed to delivery code."""

from __future__ import annotations

from email.utils import parseaddr


def is_safe_email_address(address: str) -> bool:
    """Accept one syntactically plausible address without header delimiters."""
    if not address:
        return False
    if any(char in address for char in (",", ";", "\r", "\n", "\t")):
        return False
    if any(ord(char) < 32 for char in address):
        return False
    _real_name, parsed = parseaddr(address)
    return bool(parsed and "@" in parsed)
