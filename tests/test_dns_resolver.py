"""Tests for the stdlib DNS resolver (CERT_WATCH_DNS_SERVERS)."""

from __future__ import annotations

import socket
import struct


def test_build_dns_query_valid():
    from cert_watch.scan import _build_dns_query

    pkt = _build_dns_query("example.com", 1)
    assert len(pkt) > 12
    qdcount = struct.unpack("!H", pkt[4:6])[0]
    assert qdcount == 1
    assert b"example" in pkt
    assert b"com" in pkt


def test_parse_dns_name_simple():
    from cert_watch.scan import _parse_dns_name

    data = b"\x07example\x03com\x00"
    name, offset = _parse_dns_name(data, 0)
    assert name == "example.com"
    assert offset == len(data)


def test_parse_dns_name_pointer():
    from cert_watch.scan import _parse_dns_name

    base = b"\x03www\x07example\x03com\x00"
    pointer = struct.pack("!H", 0xC000 | 4)
    data = base + b"\x03foo" + pointer
    name, offset = _parse_dns_name(data, len(base))
    assert name == "foo.example.com"


def test_resolve_with_dns_builds_packet(monkeypatch):
    from cert_watch.scan import _resolve_with_dns

    class FakeSock:
        def __init__(self):
            self._query_data = None

        def settimeout(self, v):
            pass

        def sendto(self, data, addr):
            self._query_data = data

        def recvfrom(self, bufsize):
            qid = self._query_data[:2]
            hdr = qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
            question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
            name_ptr = struct.pack("!H", 0xC00C)
            rd_data = socket.inet_aton("93.184.216.34")
            answer = name_ptr + struct.pack("!HHIH", 1, 1, 300, 4) + rd_data
            return hdr + question + answer, ("1.2.3.4", 53)

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSock())

    results = _resolve_with_dns("example.com", 443, ("1.2.3.4",))
    assert any(sockaddr[0] == "93.184.216.34" for _, sockaddr in results)


def test_resolve_with_dns_timeout(monkeypatch):
    from cert_watch.scan import _resolve_with_dns

    class TimeoutSock:
        def settimeout(self, v):
            pass

        def sendto(self, data, addr):
            pass

        def recvfrom(self, bufsize):
            raise TimeoutError

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: TimeoutSock())
    results = _resolve_with_dns("example.com", 443, ("1.2.3.4",))
    assert results == []


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
    from cert_watch.scan import resolve_hostname

    system_called = False

    def fake_getaddrinfo(host, port, **kw):
        nonlocal system_called
        system_called = True
        return [(socket.AF_INET, 1, 0, "", ("1.1.1.1", port))]

    class FakeSock:
        def __init__(self):
            self._query_data = None

        def settimeout(self, v):
            pass

        def sendto(self, data, addr):
            self._query_data = data

        def recvfrom(self, bufsize):
            qid = self._query_data[:2]
            hdr = qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
            question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
            name_ptr = struct.pack("!H", 0xC00C)
            rd_data = socket.inet_aton("10.0.0.1")
            answer = name_ptr + struct.pack("!HHIH", 1, 1, 300, 4) + rd_data
            return hdr + question + answer, ("10.0.0.1", 53)

        def close(self):
            pass

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSock())

    results = resolve_hostname("example.com", 443, dns_servers=("10.0.0.1",))
    assert not system_called
    assert results[0][1][0] == "10.0.0.1"
