"""Tests for the custom-nameserver resolver (CERT_WATCH_DNS_SERVERS).

The resolver delegates to dnspython; these tests mock ``dns.resolver.Resolver``
so they exercise our wiring (record shapes, nameserver passthrough, and the
fall-back-to-system semantics) without real network I/O.
"""

from __future__ import annotations

import socket


class _FakeRdata:
    def __init__(self, address: str):
        self.address = address


class _FakeAnswer:
    def __init__(self, addresses):
        self._rdatas = [_FakeRdata(a) for a in addresses]

    def __iter__(self):
        return iter(self._rdatas)


def _make_fake_resolver(mapping, *, record=None):
    """Build a fake ``dns.resolver.Resolver``.

    ``mapping`` maps qtype ("A"/"AAAA") to a list of addresses; a missing or
    empty entry raises (mimicking NXDOMAIN/NoAnswer). When ``record`` is given,
    each ``resolve()`` call appends ``(hostname, qtype, nameservers)``.
    """

    class _FakeResolver:
        def __init__(self, configure=True):
            self.nameservers: list[str] = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, hostname, qtype):
            if record is not None:
                record.append((hostname, qtype, tuple(self.nameservers)))
            addrs = mapping.get(qtype)
            if not addrs:
                raise Exception(f"no {qtype} record")
            return _FakeAnswer(addrs)

    return _FakeResolver


def test_resolve_with_dns_returns_a_records(monkeypatch):
    import dns.resolver

    from cert_watch import scan

    monkeypatch.setattr(dns.resolver, "Resolver", _make_fake_resolver({"A": ["10.0.0.5"]}))
    results = scan._resolve_with_dns("host.internal", 443, ("10.0.0.1",))
    assert (socket.AF_INET, ("10.0.0.5", 443)) in results


def test_resolve_with_dns_returns_aaaa_as_four_tuple(monkeypatch):
    import dns.resolver

    from cert_watch import scan

    monkeypatch.setattr(dns.resolver, "Resolver", _make_fake_resolver({"AAAA": ["fd00::1"]}))
    results = scan._resolve_with_dns("host.internal", 443, ("10.0.0.1",))
    # AAAA sockaddr must be a 4-tuple so the AF_INET6 socket can connect.
    assert (socket.AF_INET6, ("fd00::1", 443, 0, 0)) in results


def test_resolve_with_dns_empty_on_failure(monkeypatch):
    import dns.resolver

    from cert_watch import scan

    monkeypatch.setattr(dns.resolver, "Resolver", _make_fake_resolver({}))
    assert scan._resolve_with_dns("nope.internal", 443, ("10.0.0.1",)) == []


def test_resolve_with_dns_uses_configured_nameservers(monkeypatch):
    import dns.resolver

    from cert_watch import scan

    record: list = []
    monkeypatch.setattr(
        dns.resolver, "Resolver", _make_fake_resolver({"A": ["10.0.0.5"]}, record=record)
    )
    scan._resolve_with_dns("host.internal", 443, ("10.0.0.1", "10.0.0.2"))
    assert record, "resolve() was never called"
    assert record[0][2] == ("10.0.0.1", "10.0.0.2")


def test_resolve_hostname_falls_back_to_system(monkeypatch):
    from cert_watch.scan import resolve_hostname

    called = False

    def fake_getaddrinfo(host, port, **kw):
        nonlocal called
        called = True
        return [(socket.AF_INET, 1, 0, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    results = resolve_hostname("example.com", 443)
    assert called
    assert results[0][1][0] == "93.184.216.34"


def test_resolve_hostname_uses_custom_dns(monkeypatch):
    import dns.resolver

    from cert_watch.scan import resolve_hostname

    system_called = False

    def fake_getaddrinfo(host, port, **kw):
        nonlocal system_called
        system_called = True
        return [(socket.AF_INET, 1, 0, "", ("1.1.1.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(dns.resolver, "Resolver", _make_fake_resolver({"A": ["10.0.0.1"]}))

    results = resolve_hostname("host.internal", 443, dns_servers=("10.0.0.53",))
    assert not system_called
    assert results[0][1][0] == "10.0.0.1"


def test_resolve_hostname_custom_empty_falls_back_to_system(monkeypatch):
    """When the configured nameservers yield nothing, fall back to the system
    resolver (preserves prior behaviour)."""
    import dns.resolver

    from cert_watch.scan import resolve_hostname

    system_called = False

    def fake_getaddrinfo(host, port, **kw):
        nonlocal system_called
        system_called = True
        return [(socket.AF_INET, 1, 0, "", ("1.1.1.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(dns.resolver, "Resolver", _make_fake_resolver({}))

    results = resolve_hostname("host.internal", 443, dns_servers=("10.0.0.53",))
    assert system_called
    assert results[0][1][0] == "1.1.1.1"
