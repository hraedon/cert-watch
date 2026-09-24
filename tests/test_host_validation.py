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


def _numeric_ipv4_forms(quad: str) -> list[str]:
    """The legacy spellings the resolver reads as *quad*: bare integer, hex,
    three-part, two-part, and octal octets."""
    import ipaddress

    a, b, c, d = (int(x) for x in quad.split("."))
    n = int(ipaddress.IPv4Address(quad))
    return [
        str(n), hex(n), f"{a}.{b}.{c * 256 + d}", f"{a}.{b * 65536 + c * 256 + d}",
        f"0{a:o}.0{b:o}.0{c:o}.0{d:o}",
    ]


@pytest.mark.parametrize("form", _numeric_ipv4_forms("192.0.2.8"))
def test_legacy_numeric_ipv4_spellings_are_rejected(form: str) -> None:
    """``ipaddress`` rejects them but libc resolves them, so accepted as a
    "DNS name" they would be a second spelling of an IPv4 endpoint."""
    from cert_watch.host_validation import legacy_ipv4_dotted_quad

    assert legacy_ipv4_dotted_quad(form) == "192.0.2.8"
    assert hostname_is_valid(form) is False
    with pytest.raises(ValueError):
        canonical_hostname(form)
    assert legacy_ipv4_dotted_quad("victim.example.test") is None
    assert canonical_hostname("192.0.2.8") == "192.0.2.8"
