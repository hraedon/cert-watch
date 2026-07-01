"""Focused tests for cert_watch.auth.session signing helpers."""

from __future__ import annotations

import pytest

from cert_watch.auth.session import _parse_ts, _sign_state, _verify_state
from cert_watch.security import SecurityContext


@pytest.fixture
def security():
    return SecurityContext(signing_key="a" * 64, csrf_secret="b" * 64)


def test_sign_and_verify_state_roundtrip(security):
    signed = _sign_state("raw-state", security=security, nonce="nonce0")
    assert _verify_state(signed, security=security) == ("raw-state", "nonce0", None)


def test_sign_state_with_pkce_code_verifier(security):
    signed = _sign_state(
        "raw-state", security=security, nonce="nonce0", code_verifier="verifier123"
    )
    assert _verify_state(signed, security=security) == ("raw-state", "nonce0", "verifier123")


def test_verify_state_rejects_legacy_and_tampered(security):
    assert _verify_state("legacy:sig", security=security) is None
    assert _verify_state("raw-state:nonce0:" + "0" * 64, security=security) is None
    assert _verify_state("", security=security) is None


def test_parse_ts_invalid_returns_zero():
    assert _parse_ts(["a", "b", "c", "not-a-number"], start=3) == 0
    assert _parse_ts(["a", "b"], start=3) == 0
    assert _parse_ts(["a", "b", "c", "0"], start=3) == 0
    assert _parse_ts(["a", "b", "c", "999"], start=3) == 999
