"""LDAP filter validation, and config failures surfacing past the composite.

Upgrading from 0.9.x applies a saved LDAP user filter that 0.9.x ignored. A
malformed one (here the shape an operator actually had saved) made every
directory sign-in fail with ldap3's "malformed filter", reported to the user as
"invalid credentials".
"""

from __future__ import annotations

import logging
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

ldap3 = pytest.importorskip("ldap3")

from ldap3.operation.search import parse_filter  # noqa: E402

from cert_watch.auth.ldap_provider import (  # noqa: E402
    LDAP_MISCONFIGURED,
    LDAPAuthProvider,
    group_filter_error,
    normalize_group_filter,
    normalize_user_filter,
    user_filter_error,
)
from cert_watch.auth.local_admin import (  # noqa: E402
    LocalAdminProvider,
    _CompositeProvider,
    _scrypt_hash,
)

# A real saved value: misspelled attribute, (username) instead of {username}.
SAVED_BAD_FILTER = "(sAMAAccountName=(username))"
GROUP_DN = "CN=CertWatch Admins,OU=Groups,DC=example,DC=com"


def _parses(search_filter: str) -> bool:
    parse_filter(search_filter, None, auto_escape=True, auto_encode=True,
                 validator=None, check_names=False)
    return True


# ---------- normalization ----------


@pytest.mark.parametrize(("raw", "expected"), [
    ("(sAMAccountName={username})", "(sAMAccountName={username})"),
    ("sAMAccountName={username}", "(sAMAccountName={username})"),
    ("  (uid={username})  ", "(uid={username})"),
    ("(&(objectClass=user)(sAMAccountName={username}))",
     "(&(objectClass=user)(sAMAccountName={username}))"),
    # Starts and ends with parentheses but is two filters, so it gets wrapped
    # (and then fails validation as the invalid filter it is).
    ("(a={username})(b=1)", "((a={username})(b=1))"),
])
def test_normalize_user_filter(raw, expected):
    assert normalize_user_filter(raw) == expected


@pytest.mark.parametrize(("raw", "expected"), [
    ("", ""),
    ("member={group}", "member={group}"),
    ("(member={group})", "member={group}"),
    ("(&(objectClass=group)(member={group}))", "&(objectClass=group)(member={group})"),
    ("(a={group})(b=1)", "(a={group})(b=1)"),
])
def test_normalize_group_filter(raw, expected):
    assert normalize_group_filter(raw) == expected


# ---------- validation ----------


@pytest.mark.parametrize("template", [
    "(sAMAccountName={username})",
    "sAMAccountName={username}",
    "(userPrincipalName={username})",
    "(&(objectClass=user)(sAMAccountName={username}))",
])
def test_user_filter_accepts_working_filters(template):
    assert user_filter_error(template) is None


@pytest.mark.parametrize(("template", "reason"), [
    (SAVED_BAD_FILTER, "{username}"),
    ("(sAMAccountName=jdoe)", "{username}"),
    ("(&(objectClass=user)(sAMAccountName={username})", "not a valid LDAP filter"),
    ("(a={username})(b=1)", "not a valid LDAP filter"),
])
def test_user_filter_rejects_broken_filters(template, reason):
    error = user_filter_error(template)
    assert error is not None and reason in error


@pytest.mark.parametrize("template", [
    "", "member={group}", "(member={group})",
    "(&(objectClass=group)(member={group}))",
])
def test_group_filter_accepts_working_filters(template):
    assert group_filter_error(template) is None


@pytest.mark.parametrize(("template", "reason"), [
    ("member=CN=x", "{group}"),
    ("member={group}))", "not a valid LDAP filter"),
])
def test_group_filter_rejects_broken_filters(template, reason):
    error = group_filter_error(template)
    assert error is not None and reason in error


# ---------- provider ----------


def _no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("a misconfigured provider must not contact the directory")

    monkeypatch.setattr(ldap3, "Connection", refuse)


def test_bad_saved_filter_is_reported_at_build_and_refused_at_sign_in(monkeypatch, caplog):
    _no_network(monkeypatch)
    with caplog.at_level(logging.ERROR, logger="cert_watch.auth"):
        provider = LDAPAuthProvider(
            "ldaps://dc.example.com", "DC=example,DC=com",
            user_search_filter=SAVED_BAD_FILTER, required_groups=[GROUP_DN],
        )
    assert provider.config_error is not None
    assert any(SAVED_BAD_FILTER in r.getMessage() for r in caplog.records)

    result = provider.authenticate("jdoe", "pw")
    assert result.success is False
    assert result.unavailable is True
    assert result.error == LDAP_MISCONFIGURED


def test_plaintext_refusal_is_a_configuration_failure(monkeypatch):
    _no_network(monkeypatch)
    primary = LDAPAuthProvider("ldap://dc.example.com", "DC=example,DC=com")
    result = primary.authenticate("jdoe", "pw")
    assert result.unavailable is True
    assert "Insecure LDAP simple bind refused" in result.error
    # Before 1.2.2 the composite replaced it with "invalid credentials".
    assert _composite(primary).authenticate("jdoe", "pw").error == result.error


class _ParsingConnection:
    """Accepts any bind, parses the search filter exactly as ldap3 would send it."""

    searched: ClassVar[list[str]] = []

    def __init__(self, _server, user=None, password=None, **_k):
        self.user = user
        self.entries: list[object] = []

    def start_tls(self):
        return True

    def bind(self):
        return True

    def unbind(self):
        return True

    def search(self, _base, search_filter, **_k):
        _parses(search_filter)  # raises LDAPInvalidFilterError like the real call
        type(self).searched.append(search_filter)


@pytest.mark.parametrize("group_filter", ["member={group}", "(member={group})"])
def test_group_filter_works_with_or_without_outer_parentheses(monkeypatch, group_filter):
    _ParsingConnection.searched = []
    monkeypatch.setattr(ldap3, "Connection", _ParsingConnection)
    provider = LDAPAuthProvider(
        "ldaps://dc.example.com", "DC=example,DC=com",
        required_groups=[GROUP_DN], group_filter=group_filter,
    )
    assert provider.config_error is None
    result = provider.authenticate("jdoe", "pw")
    # The fake directory has no such user; reaching that answer proves the
    # filter parsed instead of raising "malformed filter".
    assert result.error == "user not found or not in required group(s)"
    assert result.unavailable is False
    assert _ParsingConnection.searched and "(member=" in _ParsingConnection.searched[0]


def test_user_filter_without_parentheses_now_works(monkeypatch):
    _ParsingConnection.searched = []
    monkeypatch.setattr(ldap3, "Connection", _ParsingConnection)
    provider = LDAPAuthProvider(
        "ldaps://dc.example.com", "DC=example,DC=com",
        user_search_filter="sAMAccountName={username}", required_groups=[GROUP_DN],
    )
    assert provider.authenticate("jdoe", "pw").error.startswith("user not found")
    assert _ParsingConnection.searched[0].startswith("(&(sAMAccountName=jdoe)(|")


# ---------- composite: local account first, then the directory ----------


def _composite(primary):
    local = LocalAdminProvider("admin", _scrypt_hash("localpw", n=2**4, r=1, p=1))
    return _CompositeProvider(local, primary)


def test_composite_surfaces_directory_misconfiguration(monkeypatch):
    _no_network(monkeypatch)
    primary = LDAPAuthProvider(
        "ldaps://dc.example.com", "DC=example,DC=com", user_search_filter=SAVED_BAD_FILTER,
    )
    result = _composite(primary).authenticate("jdoe", "pw")
    assert result.error == LDAP_MISCONFIGURED  # was "invalid credentials"


def test_composite_still_masks_ordinary_directory_failures(monkeypatch):
    """Directory answers that vary by username stay hidden (no enumeration)."""
    _ParsingConnection.searched = []
    monkeypatch.setattr(ldap3, "Connection", _ParsingConnection)
    primary = LDAPAuthProvider("ldaps://dc.example.com", "DC=example,DC=com")
    assert primary.authenticate("jdoe", "pw").error == "user not found"
    assert _composite(primary).authenticate("jdoe", "pw").error == "invalid credentials"


def test_composite_local_account_still_signs_in_when_directory_is_broken(monkeypatch):
    _no_network(monkeypatch)
    primary = LDAPAuthProvider(
        "ldaps://dc.example.com", "DC=example,DC=com", user_search_filter=SAVED_BAD_FILTER,
    )
    result = _composite(primary).authenticate("admin", "localpw")
    assert result.success is True


# ---------- Settings → Sign-in ----------


def test_saving_a_malformed_user_filter_is_refused(reload_app, tmp_path):
    from cert_watch.database import init_schema, kv_get

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/auth",
            data={
                "auth_provider": "ldap",
                "ldap_server": "ldaps://dc1.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_user_filter": SAVED_BAD_FILTER,
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error=" in r.headers["location"] and "saved=1" not in r.headers["location"]
    assert "%7Busername%7D" in r.headers["location"]
    # Nothing from the refused form was stored.
    assert kv_get(db, "ldap_user_filter") is None
    assert kv_get(db, "ldap_server") is None


def test_saving_a_working_user_filter_is_accepted(reload_app, tmp_path):
    from cert_watch.database import init_schema, kv_get

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/auth",
            data={
                "auth_provider": "",
                "ldap_user_filter": "(userPrincipalName={username})",
            },
            follow_redirects=False,
        )
    assert "saved=1" in r.headers["location"]
    assert kv_get(db, "ldap_user_filter") == "(userPrincipalName={username})"


def test_ldap_probe_reports_a_malformed_user_filter(reload_app, monkeypatch):
    _no_network(monkeypatch)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldaps://dc1.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_user_filter": SAVED_BAD_FILTER,
            },
        )
    body = r.json()
    assert body["ok"] is False
    assert "User search filter" in body["error"]
