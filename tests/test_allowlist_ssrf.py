"""CERT_WATCH_ALLOWED_SUBNETS allowlist + _kv_bool env-precedence (BC-076)."""

import ipaddress

from cert_watch.scan import _is_blocked_ip


def _ip(s):
    return ipaddress.ip_address(s)


# ── _is_blocked_ip allowlist semantics ──────────────────────────────────────


def test_public_ip_always_allowed():
    assert not _is_blocked_ip(_ip("8.8.8.8"))
    # an allowlist scoping private ranges does not block public hosts
    assert not _is_blocked_ip(_ip("8.8.8.8"), allowed_subnets=("10.0.0.0/8",))


def test_loopback_and_metadata_always_blocked():
    assert _is_blocked_ip(_ip("127.0.0.1"))
    # cloud metadata endpoint (link-local) is blocked regardless of policy
    assert _is_blocked_ip(_ip("169.254.169.254"))
    # ...and cannot be re-enabled via the allowlist
    assert _is_blocked_ip(
        _ip("169.254.169.254"), allow_private=True, allowed_subnets=("169.254.0.0/16",)
    )


def test_private_governed_by_allow_private_when_no_allowlist():
    assert not _is_blocked_ip(_ip("10.1.2.3"), allow_private=True)
    assert _is_blocked_ip(_ip("10.1.2.3"), allow_private=False)


def test_allowlist_scopes_private_ranges():
    nets = ("10.0.0.0/8",)
    assert not _is_blocked_ip(_ip("10.1.2.3"), allowed_subnets=nets)  # inside allowlist
    assert _is_blocked_ip(_ip("192.168.1.1"), allowed_subnets=nets)  # private, not listed


def test_allowlist_overrides_allow_private_false_for_listed_ranges():
    # An explicit allowlist permits its ranges even when allow_private is off.
    assert not _is_blocked_ip(
        _ip("10.1.2.3"), allow_private=False, allowed_subnets=("10.0.0.0/8",)
    )


def test_allowlist_ignores_invalid_cidr_entries():
    assert not _is_blocked_ip(_ip("10.1.2.3"), allowed_subnets=("not-a-cidr", "10.0.0.0/8"))
    # with only an invalid entry, the (empty) parsed list blocks all private
    assert _is_blocked_ip(_ip("10.1.2.3"), allowed_subnets=("garbage",))


# ── config: env parsing + kv merge ──────────────────────────────────────────


def test_allowed_subnets_parsed_from_env(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_ALLOWED_SUBNETS", "10.0.0.0/8, 192.168.0.0/16")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.allowed_subnets == ("10.0.0.0/8", "192.168.0.0/16")


def test_allowed_subnets_merged_from_kv(tmp_path, monkeypatch):
    monkeypatch.delenv("CERT_WATCH_ALLOWED_SUBNETS", raising=False)
    from cert_watch.config import Settings
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "allowed_subnets", "172.16.0.0/12")
    s = Settings.from_env_with_kv(db)
    assert s.allowed_subnets == ("172.16.0.0/12",)


# ── #9 / BC-076: _kv_bool env precedence ────────────────────────────────────


def test_explicit_env_false_overrides_kv_true(tmp_path, monkeypatch):
    """An operator's explicit LDAP_START_TLS=0 must win over a kv_store '1'."""
    from cert_watch.config import Settings
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "ldap_start_tls", "1")
    monkeypatch.setenv("LDAP_START_TLS", "0")
    s = Settings.from_env_with_kv(db)
    assert s.ldap_start_tls is False


def test_kv_bool_used_when_env_unset(tmp_path, monkeypatch):
    from cert_watch.config import Settings
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    monkeypatch.delenv("LDAP_START_TLS", raising=False)
    kv_set(db, "ldap_start_tls", "1")
    s = Settings.from_env_with_kv(db)
    assert s.ldap_start_tls is True
