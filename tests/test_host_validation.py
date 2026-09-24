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


# ---------------------------------------------------------------------------
# One canonical spelling per endpoint (#116 review)
# ---------------------------------------------------------------------------

from cert_watch.host_validation import canonical_hostname  # noqa: E402


@pytest.mark.parametrize(
    ("spelling", "canonical"),
    [
        ("victim.example.test", "victim.example.test"),
        ("VICTIM.example.test", "victim.example.test"),
        ("victim.example.test.", "victim.example.test"),
        ("Victim.Example.TEST.", "victim.example.test"),
        ("café.example.test", "xn--caf-dma.example.test"),
        ("CAFÉ.example.test", "xn--caf-dma.example.test"),
        ("XN--CAF-DMA.example.test", "xn--caf-dma.example.test"),
        ("münchen.example", "xn--mnchen-3ya.example"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
        ("2001:0DB8::1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("192.0.2.1", "192.0.2.1"),
    ],
)
def test_every_spelling_of_an_endpoint_has_one_canonical_form(
    spelling: str, canonical: str
) -> None:
    assert canonical_hostname(spelling) == canonical
    # The canonical form is a fixed point, and valid.
    assert canonical_hostname(canonical) == canonical
    assert hostname_is_valid(canonical)


@pytest.mark.parametrize(
    "hostname",
    ["", ".", "faß.example", "example​.com", "fe80::1%eth0", "a b.example",
     "[example.test]", "x" * 10000, "-bad.example", "bad-.example"],
)
def test_canonical_hostname_rejects_what_validation_rejects(hostname: str) -> None:
    with pytest.raises(ValueError):
        canonical_hostname(hostname)
    assert hostname_is_valid(hostname) is False
