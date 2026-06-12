"""DNS resolution and SSRF/IP validation for TLS scanning."""

from __future__ import annotations

import ipaddress
import logging
import socket
from functools import lru_cache

logger = logging.getLogger("cert_watch.scan")

_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
]

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


@lru_cache(maxsize=64)
def _parse_allowed_subnets(allowed_subnets: tuple[str, ...]) -> tuple:
    """Parse a tuple of CIDR strings into ip_network objects (invalid entries skipped)."""
    nets = []
    for cidr in allowed_subnets:
        try:
            nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            logging.getLogger("cert_watch.scan").warning(
                "ignoring invalid CERT_WATCH_ALLOWED_SUBNETS entry: %r", cidr
            )
    return tuple(nets)


def _is_blocked_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> bool:
    """Return True if *ip* must not be scanned (SSRF guard).

    - Loopback (127.0.0.0/8, ::1), link-local / cloud metadata (169.254.169.254),
      unspecified, and other always-blocked ranges are ALWAYS blocked, regardless
      of policy.
    - Public IPs are allowed (scanning public certs is the baseline function).
    - Private (RFC 1918 / ULA) IPs: when ``allowed_subnets`` is configured, a
      private IP is allowed only if it falls inside one of those CIDRs (the
      explicit-allowlist model); otherwise governed by ``allow_private``.
    """
    check_ip = (
        ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped
        else ip
    )
    if any(check_ip in net for net in _ALWAYS_BLOCKED_NETWORKS):
        return True
    if not any(check_ip in net for net in _PRIVATE_NETWORKS):
        return False  # public — allowed
    if allowed_subnets:
        nets = _parse_allowed_subnets(tuple(allowed_subnets))
        return not any(check_ip in net for net in nets)
    return not allow_private


def _resolve_with_dns(
    hostname: str, port: int, dns_servers: tuple[str, ...], timeout: float = 5.0
) -> list[tuple[int, tuple]]:
    """Resolve A/AAAA for *hostname* against the configured nameservers.

    Uses dnspython rather than a hand-rolled packet parser. dnspython validates
    each response against the outstanding query (transaction id + question) and
    transparently retries over TCP when a UDP answer is truncated (the TC bit) —
    two gaps in the previous implementation: it was UDP-only with a fixed 4 KiB
    buffer (large internal AD responses could silently truncate), and its
    question check had to be retrofitted after a blind-spoof finding (resolved
    BC-079). The same dnspython dependency already backs the CAA lookup.

    Returns the same ``(family, sockaddr)`` shape as :func:`socket.getaddrinfo`
    so callers (``resolve_hostname`` / ``_resolve_host``) are unchanged. Returns
    an empty list on any resolution failure, letting ``resolve_hostname`` fall
    back to the system resolver.
    """
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(dns_servers)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    results: list[tuple[int, tuple]] = []
    for qtype, family in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
        try:
            answer = resolver.resolve(hostname, qtype)
        except (dns.exception.DNSException, OSError):
            continue
        for rdata in answer:
            ip_str = rdata.address
            if family == socket.AF_INET6:
                results.append((family, (ip_str, port, 0, 0)))
            else:
                results.append((family, (ip_str, port)))
    return results


def resolve_hostname(
    hostname: str, port: int, *, dns_servers: tuple[str, ...] = ()
) -> list[tuple[int, tuple]]:
    """Resolve hostname to sockaddr list. Uses custom DNS servers when configured.

    Returns list of (family, sockaddr) tuples from socket.getaddrinfo.
    """
    if dns_servers:
        custom = _resolve_with_dns(hostname, port, dns_servers)
        if custom:
            return custom
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return [(f, s) for f, _t, _p, _c, s in infos]


def resolve_and_validate_host(
    hostname: str,
    port: int = 443,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (),
) -> tuple[str | None, str | None]:
    """SSRF pre-check: resolve hostname and validate all returned IPs.

    Returns (error_message_or_None, pinned_ip_or_None).  When no error is
    found the pinned_ip is the first allowed address so the subsequent scan
    can connect to the same IP (prevents DNS rebinding).
    """
    infos = resolve_hostname(hostname, port, dns_servers=dns_servers)
    if not infos:
        return None, None
    pinned_ip = None
    blocked_info = None
    for _family, sockaddr in infos:
        ip_str = sockaddr[0]
        if ip_str is None:
            continue
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            check_ip = (
                ip.ipv4_mapped
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped
                else ip
            )
            is_private = any(check_ip in net for net in _PRIVATE_NETWORKS)
            blocked_info = (ip, is_private)
            continue
        pinned_ip = ip_str
        break
    if pinned_ip is None:
        if blocked_info is not None:
            ip, is_private = blocked_info
            if is_private and allowed_subnets:
                return (
                    f"hostname resolves to private address {ip}, which is outside the "
                    f"configured CERT_WATCH_ALLOWED_SUBNETS. Add its range to scan it.",
                    None,
                )
            if is_private and not allow_private:
                return (
                    f"hostname resolves to blocked address {ip}. "
                    f"Set CERT_WATCH_ALLOW_PRIVATE_IPS=1 to allow scanning private IPs.",
                    None,
                )
            return f"hostname resolves to blocked address {ip}", None
        return None, None
    return None, pinned_ip


def _resolve_host(
    hostname: str, port: int, *, allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (),
) -> tuple[int, tuple]:
    """Resolve hostname and check all IPs against the SSRF blocklist.

    Returns a (family, sockaddr) tuple for the first allowed address.
    Raises OSError if every resolved IP is blocked.
    """
    infos = resolve_hostname(hostname, port, dns_servers=dns_servers)
    if not infos:
        raise OSError(f"DNS resolution failed for {hostname}")
    err, pinned_ip = resolve_and_validate_host(
        hostname,
        port,
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
        dns_servers=dns_servers,
    )
    if err:
        raise OSError(err)
    if pinned_ip:
        for family, sockaddr in infos:
            if sockaddr[0] == pinned_ip:
                return family, sockaddr
    for family, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return family, sockaddr
    raise OSError(f"hostname {hostname} resolves only to blocked addresses")
