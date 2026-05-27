"""TLS scanning. See spec wi_fr02_tls_scan.md."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import re
import socket
import ssl
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
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool = False
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


def _resolve_host(hostname: str, port: int, *, allow_private: bool = False) -> tuple[int, tuple]:
    """Resolve hostname and check all IPs against the SSRF blocklist.

    Returns a (family, sockaddr) tuple for the first allowed address.
    Raises OSError if every resolved IP is blocked.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise OSError(f"DNS resolution failed for {hostname}: {exc}") from exc
    for family, _type, _proto, _canonname, sockaddr in infos:
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
    hostname: str, port: int, timeout: float, *, verify: bool = False, allow_private: bool = False,
):
    """Open a TLS connection and return the SSLSocket. Separated so tests can monkeypatch."""
    ctx = ssl.create_default_context()
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    _family, sockaddr = _resolve_host(hostname, port, allow_private=allow_private)
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
    allow_private: bool = False,
) -> ScannedEntry | ScanError:
    """Perform a TLS handshake and return ScannedEntry or ScanError. See AC-01..AC-06."""
    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=verify, allow_private=allow_private
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
