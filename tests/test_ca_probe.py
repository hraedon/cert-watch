"""Tests for CA probe URL parsing, including IPv6 bracket handling."""

from __future__ import annotations

from cert_watch.routes.settings.ca_probe import _parse_ldap_url, _parse_ldaps_url


def test_parse_ldaps_url_basic():
    assert _parse_ldaps_url("ldaps://dc.example.com:636") == ("dc.example.com", 636)


def test_parse_ldaps_url_default_port():
    assert _parse_ldaps_url("ldaps://dc.example.com") == ("dc.example.com", 636)


def test_parse_ldap_url_basic():
    assert _parse_ldap_url("ldap://dc.example.com:389") == ("dc.example.com", 389)


def test_parse_ldap_url_default_port():
    assert _parse_ldap_url("ldap://dc.example.com") == ("dc.example.com", 389)


def test_parse_ldaps_url_ipv6():
    assert _parse_ldaps_url("ldaps://[::1]:636") == ("::1", 636)


def test_parse_ldap_url_ipv6():
    assert _parse_ldap_url("ldap://[::1]:389") == ("::1", 389)


def test_parse_ldaps_url_ipv6_no_port():
    assert _parse_ldaps_url("ldaps://[::1]") == ("::1", 636)


def test_parse_ldap_url_ipv6_no_port():
    assert _parse_ldap_url("ldap://[::1]") == ("::1", 389)


def test_parse_ldaps_url_ipv6_custom_port():
    assert _parse_ldaps_url("ldaps://[fe80::1]:1636") == ("fe80::1", 1636)


def test_parse_ldaps_url_invalid_scheme():
    assert _parse_ldaps_url("https://dc.example.com") is None


def test_parse_ldap_url_invalid_scheme():
    assert _parse_ldap_url("ldaps://dc.example.com") is None


def test_parse_ldaps_url_empty_host():
    assert _parse_ldaps_url("ldaps://") is None


def test_parse_ldaps_url_invalid_port():
    assert _parse_ldaps_url("ldaps://dc.example.com:abc") is None


def test_parse_ldaps_url_out_of_range_port():
    assert _parse_ldaps_url("ldaps://dc.example.com:99999") is None


def test_parse_ldap_url_invalid_port():
    assert _parse_ldap_url("ldap://dc.example.com:abc") is None


def test_parse_ldaps_url_cross_scheme():
    assert _parse_ldaps_url("ldap://dc.example.com") is None


def test_parse_ldap_url_cross_scheme():
    assert _parse_ldap_url("ldaps://dc.example.com") is None
