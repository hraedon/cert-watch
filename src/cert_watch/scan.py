"""TLS scanning. See spec wi_fr02_tls_scan.md."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import random
import re
import socket
import ssl
import struct
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import init_schema, replace_scanned

DEFAULT_TIMEOUT = 10.0

# Always blocked: loopback, link-local, unspecified
_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
]

# Private RFC 1918 / ULA — blocked unless allow_private=True
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_blocked_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool = True
) -> bool:
    check_ip = (
        ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped
        else ip
    )
    if any(check_ip in net for net in _ALWAYS_BLOCKED_NETWORKS):
        return True
    return not allow_private and any(check_ip in net for net in _PRIVATE_NETWORKS)


@dataclass
class ScanError:
    hostname: str
    port: int
    error_message: str


@dataclass
class ScannedEntry:
    host: str
    port: int
    leaf: Certificate
    chain: list[Certificate] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _build_dns_query(name: str, qtype: int) -> bytes:
    header = struct.pack(
        "!HHHHHH",
        random.randint(0, 65535),
        0x0100,
        1,
        0,
        0,
        0,
    )
    question = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00" + struct.pack("!HH", qtype, 1)
    return header + question


def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    parts: list[str] = []
    original = offset
    jumped = False
    max_offset = original
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                max_offset = offset + 2
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            continue
        offset += 1
        parts.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(parts), max_offset if jumped else offset


_QTYPE_A = 1
_QTYPE_AAAA = 28


def _resolve_with_dns(
    hostname: str, port: int, dns_servers: tuple[str, ...], timeout: float = 5.0
) -> list[tuple[int, tuple]]:
    results: list[tuple[int, tuple]] = []
    for qtype, family in [(_QTYPE_A, socket.AF_INET), (_QTYPE_AAAA, socket.AF_INET6)]:
        query = _build_dns_query(hostname, qtype)
        for server in dns_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(query, (server, 53))
                response, _ = sock.recvfrom(4096)
                sock.close()
            except (TimeoutError, OSError):
                continue
            if len(response) < 12:
                continue
            ancount = struct.unpack("!H", response[6:8])[0]
            offset = 12
            qdcount = struct.unpack("!H", response[4:6])[0]
            for _ in range(qdcount):
                _, offset = _parse_dns_name(response, offset)
                offset += 4
            for _ in range(ancount):
                _, offset = _parse_dns_name(response, offset)
                rtype, rclass, _, rdlength = struct.unpack(
                    "!HHIH", response[offset : offset + 10]
                )
                offset += 10
                if rtype == _QTYPE_A and rdlength == 4 and rclass == 1:
                    ip_str = socket.inet_ntoa(response[offset : offset + 4])
                    addr = (ip_str, port, 0, 0) if family == socket.AF_INET6 else (ip_str, port)
                    results.append((family, addr))
                elif rtype == _QTYPE_AAAA and rdlength == 16 and rclass == 1:
                    ip_str = socket.inet_ntop(socket.AF_INET6, response[offset : offset + 16])
                    results.append((family, (ip_str, port, 0, 0)))
                offset += rdlength
            break
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


def _resolve_host(
    hostname: str, port: int, *, allow_private: bool = True,
    dns_servers: tuple[str, ...] = (),
) -> tuple[int, tuple]:
    """Resolve hostname and check all IPs against the SSRF blocklist.

    Returns a (family, sockaddr) tuple for the first allowed address.
    Raises OSError if every resolved IP is blocked.
    """
    infos = resolve_hostname(hostname, port, dns_servers=dns_servers)
    if not infos:
        raise OSError(f"DNS resolution failed for {hostname}")
    for family, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(ip, allow_private=allow_private):
            continue
        return family, sockaddr
    raise OSError(f"hostname {hostname} resolves only to blocked addresses")


def _open_tls_connection(
    hostname: str, port: int, timeout: float, *, verify: bool = False,
    allow_private: bool = True, dns_servers: tuple[str, ...] = (),
):
    """Open a TLS connection and return the SSLSocket. Separated so tests can monkeypatch."""
    ctx = ssl.create_default_context()
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    _family, sockaddr = _resolve_host(
        hostname, port, allow_private=allow_private, dns_servers=dns_servers,
    )
    sock = socket.socket(_family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(sockaddr)
    return ctx.wrap_socket(sock, server_hostname=hostname)


def _get_chain_der(ssl_sock, hostname: str = "") -> list[bytes]:
    """
    Return DER bytes for every certificate the peer presented.
    Uses SSLSocket.getpeercert(True) for the leaf and (when available)
    get_unverified_chain/get_verified_chain for the full chain.

    On Python 3.12 those methods don't exist, so we fall back to
    openssl s_client to extract the full chain.
    """
    leaf = ssl_sock.getpeercert(binary_form=True)
    chain: list[bytes] = []
    if leaf:
        chain.append(leaf)
    # Python 3.13+ exposes get_verified_chain / get_unverified_chain. Try both.
    for method in ("get_unverified_chain", "get_verified_chain"):
        getter = getattr(ssl_sock, method, None)
        if getter:
            try:
                items = getter()
            except Exception:  # noqa: BLE001
                continue
            chain = []
            for c in items:
                # Newer cryptography returns _Certificate-like with public_bytes,
                # cpython returns bytes-like via .public_bytes() on Certificate objects
                try:
                    der = c.public_bytes(_der_enc())
                except AttributeError:
                    der = bytes(c)
                chain.append(der)
            break

    # If we only have the leaf, try openssl s_client for the full chain
    if len(chain) <= 1:
        openssl_chain = _get_chain_via_openssl(ssl_sock, hostname)
        if openssl_chain:
            chain = openssl_chain

    return chain


_PEM_CERT_PATTERN = re.compile(
    b"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL,
)


def _get_chain_via_openssl(ssl_sock, hostname: str) -> list[bytes]:
    """Extract the full certificate chain using openssl s_client.

    This is a fallback for Python 3.12 where SSLSocket lacks
    get_unverified_chain() / get_verified_chain().
    """
    if not hostname:
        return []

    try:
        peer_addr = ssl_sock.getpeername()
    except (OSError, AttributeError):
        return []

    host = peer_addr[0]
    port = peer_addr[1]

    try:
        proc = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{host}:{port}",
                "-servername", hostname,
                "-showcerts",
            ],
            input=b"Q\n",
            capture_output=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []

    if proc.returncode not in (0, 1):
        return []

    pem_output = proc.stdout
    matches = _PEM_CERT_PATTERN.findall(pem_output)
    if not matches:
        return []

    result: list[bytes] = []
    for pem_b64 in matches:
        try:
            der = base64.b64decode(pem_b64)
            result.append(der)
        except Exception:
            continue

    return result if len(result) > 1 else []


def _der_enc():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def scan_host(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    allow_private: bool = True,
    dns_servers: tuple[str, ...] = (),
) -> ScannedEntry | ScanError:
    """Perform a TLS handshake and return ScannedEntry or ScanError. See AC-01..AC-06."""
    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=verify, allow_private=allow_private,
            dns_servers=dns_servers,
        )
    except TimeoutError as exc:
        return ScanError(hostname=hostname, port=port, error_message=f"timeout: {exc}")
    except OSError as exc:
        return ScanError(hostname=hostname, port=port, error_message=str(exc))
    except Exception as exc:  # noqa: BLE001
        return ScanError(hostname=hostname, port=port, error_message=str(exc))

    try:
        der_chain = _get_chain_der(ssl_sock, hostname)
    finally:
        with contextlib.suppress(Exception):
            ssl_sock.close()

    if not der_chain:
        return ScanError(
            hostname=hostname, port=port, error_message="no certificate presented"
        )

    leaf_parsed = parse_certificate(der_chain[0])
    if not isinstance(leaf_parsed, Certificate):
        return ScanError(
            hostname=hostname, port=port, error_message=leaf_parsed.message
        )

    chain_certs: list[Certificate] = []
    for der in der_chain[1:]:
        cp = parse_certificate(der)
        if isinstance(cp, Certificate):
            cp.is_leaf = False
            chain_certs.append(cp)

    return ScannedEntry(
        host=hostname,
        port=port,
        leaf=leaf_parsed,
        chain=chain_certs,
        scanned_at=datetime.now(UTC),
    )


def store_scanned(entry: ScannedEntry, repo_path_or_repo) -> str:
    """
    Persist leaf + chain. Accepts either an existing CertificateRepository OR a path
    (so callers can pass the db path directly and we wire up source/hostname/port).
    Removes any previous leaf + chain certs for the same (hostname, port) first to
    avoid accumulation on repeated scans. See AC-07.
    """
    if isinstance(repo_path_or_repo, str | Path):
        init_schema(repo_path_or_repo)
        return replace_scanned(
            repo_path_or_repo,
            hostname=entry.host,
            port=entry.port,
            leaf=entry.leaf,
            chain=entry.chain,
            chain_valid=None,  # computed inside replace_scanned
        )

    repo = repo_path_or_repo
    leaf_id = repo.add(entry.leaf)
    for chain_cert in entry.chain:
        repo.add(chain_cert)
    return leaf_id
