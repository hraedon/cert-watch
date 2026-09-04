"""Direct regression coverage for persisted hostname validation."""

from __future__ import annotations

import pytest

from cert_watch.host_validation import hostname_is_valid


@pytest.mark.parametrize(
    "hostname",
    [
        "faß.example",
        "example\u200b.com",
        "example\u3002com",
        "fe80::1%eth0",
        "fe80::1%" + "x" * 1000,
        "a" + "\u200b" * 1000 + ".example",
    ],
)
def test_rejects_nonportable_idna_and_scoped_ip_inputs(hostname: str) -> None:
    assert hostname_is_valid(hostname) is False


def test_accepts_unicode_dns_after_strict_idna_round_trip() -> None:
    assert hostname_is_valid("münchen.example") is True
    assert hostname_is_valid("MÜNCHEN.example") is True
    assert hostname_is_valid("xn--mnchen-3ya.example") is True


def test_rejects_overlong_input_before_ip_or_idna_processing() -> None:
    assert hostname_is_valid("x" * 10000) is False


@pytest.mark.parametrize("hostname", ["192.0.2.1", "2001:db8::1"])
def test_accepts_unscoped_ip_literals(hostname: str) -> None:
    assert hostname_is_valid(hostname) is True
