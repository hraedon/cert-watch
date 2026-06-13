"""Tests for integer config range validation (WI-033).

Out-of-range values must raise ValueError at startup rather than silently
misbehaving (e.g. CERT_WATCH_SCHED_HOUR=25 crashing the scheduler).
"""

from __future__ import annotations

import pytest

from cert_watch.config.helpers import _parse_int, _validate_range

# ---------- _validate_range unit tests ----------


def test_validate_range_passes_within_bounds():
    assert _validate_range(5, "X", min_value=0, max_value=10) == 5


def test_validate_range_raises_below_min():
    with pytest.raises(ValueError, match="X=-1 is below minimum 0"):
        _validate_range(-1, "X", min_value=0, max_value=10)


def test_validate_range_raises_above_max():
    with pytest.raises(ValueError, match="X=25 exceeds maximum 23"):
        _validate_range(25, "X", min_value=0, max_value=23)


def test_validate_range_min_only():
    assert _validate_range(5, "X", min_value=1) == 5
    with pytest.raises(ValueError, match="below minimum"):
        _validate_range(0, "X", min_value=1)


def test_validate_range_max_only():
    assert _validate_range(50, "X", max_value=100) == 50
    with pytest.raises(ValueError, match="exceeds maximum"):
        _validate_range(101, "X", max_value=100)


def test_validate_range_no_bounds():
    assert _validate_range(999999, "X") == 999999


# ---------- _parse_int range tests ----------


def test_parse_int_in_range():
    assert _parse_int("5", 0, "X", min_value=0, max_value=10) == 5


def test_parse_int_out_of_range_raises():
    with pytest.raises(ValueError, match="SCHED_HOUR=25 exceeds maximum 23"):
        _parse_int("25", 6, "SCHED_HOUR", min_value=0, max_value=23)


def test_parse_int_below_min_raises():
    with pytest.raises(ValueError, match="RENEWAL_WINDOW=0 is below minimum 1"):
        _parse_int("0", 30, "RENEWAL_WINDOW", min_value=1, max_value=365)


def test_parse_int_invalid_still_returns_default():
    assert _parse_int("abc", 6, "X", min_value=0, max_value=23) == 6


def test_parse_int_no_range_still_works():
    assert _parse_int("42", 0, "X") == 42


# ---------- Settings.from_env() integration tests ----------


def _from_env(monkeypatch, tmp_path, **env_overrides):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    for k, v in env_overrides.items():
        monkeypatch.setenv(k, v)
    from cert_watch.config import Settings
    return Settings.from_env()


def test_sched_hour_25_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SCHED_HOUR=25 exceeds maximum 23"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_HOUR="25")


def test_sched_hour_negative_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SCHED_HOUR=-1 is below minimum 0"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_HOUR="-1")


def test_sched_min_60_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SCHED_MIN=60 exceeds maximum 59"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_MIN="60")


def test_sched_min_negative_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SCHED_MIN=-1 is below minimum 0"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_MIN="-1")


def test_smtp_port_zero_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SMTP_PORT=0 is below minimum 1"):
        _from_env(monkeypatch, tmp_path, SMTP_PORT="0")


def test_smtp_port_70000_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SMTP_PORT=70000 exceeds maximum 65535"):
        _from_env(monkeypatch, tmp_path, SMTP_PORT="70000")


def test_ldap_connect_timeout_zero_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="LDAP_CONNECT_TIMEOUT=0 is below minimum 1"):
        _from_env(monkeypatch, tmp_path, LDAP_CONNECT_TIMEOUT="0")


def test_audit_retention_days_negative_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="AUDIT_RETENTION_DAYS=-1 is below minimum 0"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_AUDIT_RETENTION_DAYS="-1")


def test_history_retention_days_zero_ok(monkeypatch, tmp_path):
    s = _from_env(monkeypatch, tmp_path, CERT_WATCH_HISTORY_RETENTION_DAYS="0")
    assert s.history_retention_days == 0


def test_renewal_window_zero_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="RENEWAL_WINDOW_DAYS=0 is below minimum 1"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_RENEWAL_WINDOW_DAYS="0")


def test_scan_retries_negative_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SCAN_RETRIES=-1 is below minimum 0"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SCAN_RETRIES="-1")


def test_scan_retries_11_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SCAN_RETRIES=11 exceeds maximum 10"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SCAN_RETRIES="11")


def test_scan_max_output_bytes_below_min_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SCAN_MAX_OUTPUT_BYTES=512 is below minimum 1024"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SCAN_MAX_OUTPUT_BYTES="512")


def test_session_ttl_below_min_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SESSION_TTL=30 is below minimum 60"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SESSION_TTL="30")


def test_session_ttl_above_max_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="SESSION_TTL=9999999 exceeds maximum 2592000"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_SESSION_TTL="9999999")


def test_jwks_cache_ttl_below_min_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="JWKS_CACHE_TTL=10 is below minimum 60"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_JWKS_CACHE_TTL="10")


def test_jwks_cache_ttl_above_max_raises(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="JWKS_CACHE_TTL=999999 exceeds maximum 604800"):
        _from_env(monkeypatch, tmp_path, CERT_WATCH_JWKS_CACHE_TTL="999999")


# ---------- Valid boundary values accepted ----------


def test_sched_hour_boundary_values(monkeypatch, tmp_path):
    s0 = _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_HOUR="0")
    assert s0.sched_hour == 0
    s23 = _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_HOUR="23")
    assert s23.sched_hour == 23


def test_sched_min_boundary_values(monkeypatch, tmp_path):
    s0 = _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_MIN="0")
    assert s0.sched_min == 0
    s59 = _from_env(monkeypatch, tmp_path, CERT_WATCH_SCHED_MIN="59")
    assert s59.sched_min == 59


def test_smtp_port_boundary_values(monkeypatch, tmp_path):
    s1 = _from_env(monkeypatch, tmp_path, SMTP_PORT="1")
    assert s1.smtp_port == 1
    s65535 = _from_env(monkeypatch, tmp_path, SMTP_PORT="65535")
    assert s65535.smtp_port == 65535


def test_jwks_cache_ttl_valid(monkeypatch, tmp_path):
    s = _from_env(monkeypatch, tmp_path, CERT_WATCH_JWKS_CACHE_TTL="300")
    assert s.jwks_cache_ttl == 300
