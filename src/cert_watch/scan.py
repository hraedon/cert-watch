"""TLS scanning. See spec wi_fr02_tls_scan.md."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import re
import secrets
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
SCAN_RETRIES = 2
SCAN_RETRY_BACKOFF = 1.0
HSTS_TIMEOUT = 5.0

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


def _probe_hsts(hostname: str, port: int, pinned_ip: str | None = None) -> bool | None:
    """Check if an HTTPS server sends Strict-Transport-Security.

    Returns True if HSTS header found, False if not found, None on error.
    When pinned_ip is provided, connects to that IP with SNI=hostname
    (prevents DNS rebinding).
    """
    if port != 443:
        return None
    try:
        import http.client

        ctx = ssl.create_default_context()
        if pinned_ip:
            sock = socket.create_connection((pinned_ip, port), timeout=HSTS_TIMEOUT)
            try:
                ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            except Exception:
                sock.close()
                raise
            conn = http.client.HTTPSConnection(hostname, port, timeout=HSTS_TIMEOUT, context=ctx)
            conn.sock = ssl_sock
        else:
            conn = http.client.HTTPSConnection(
                hostname, port, timeout=HSTS_TIMEOUT, context=ctx,
            )
        try:
            conn.request("HEAD", "/", headers={"Host": hostname})
            resp = conn.getresponse()
            hsts_header = resp.getheader("Strict-Transport-Security")
        finally:
            conn.close()
        return hsts_header is not None
    except Exception:
        return None


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
    protocol_version: str = ""
    hsts: bool | None = None
    tls_verified: bool | None = None


def _build_dns_query(name: str, qtype: int) -> bytes:
    header = struct.pack(
        "!HHHHHH",
        secrets.randbelow(65536),
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
    seen_offsets: set[int] = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                max_offset = offset + 2
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            if pointer in seen_offsets:
                break
            seen_offsets.add(pointer)
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
        query_id = struct.unpack("!H", query[:2])[0]
        for server in dns_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                try:
                    sock.sendto(query, (server, 53))
                    response, _ = sock.recvfrom(4096)
                finally:
                    sock.close()
            except (TimeoutError, OSError):
                continue
            if len(response) < 12:
                continue
            resp_id = struct.unpack("!H", response[:2])[0]
            if resp_id != query_id:
                continue
            flags = struct.unpack("!H", response[2:4])[0]
            rcode = flags & 0x000F
            if rcode != 0:
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
    pinned_ip: str | None = None,
):
    """Open a TLS connection and return the SSLSocket. Separated so tests can monkeypatch."""
    ctx = ssl.create_default_context()
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if pinned_ip:
        import ipaddress as _ip

        ip = _ip.ip_address(pinned_ip)
        family = socket.AF_INET6 if isinstance(ip, _ip.IPv6Address) else socket.AF_INET
        sockaddr = (pinned_ip, port, 0, 0) if family == socket.AF_INET6 else (pinned_ip, port)
        if _is_blocked_ip(ip, allow_private=allow_private):
            raise OSError(f"pinned IP {pinned_ip} is a blocked address")
    else:
        _family, sockaddr = _resolve_host(
            hostname, port, allow_private=allow_private, dns_servers=dns_servers,
        )
    sock = socket.socket(family if pinned_ip else _family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(sockaddr)
        return ctx.wrap_socket(sock, server_hostname=hostname)
    except Exception:
        sock.close()
        raise


def _get_chain_der(ssl_sock, hostname: str = "") -> list[bytes]:
    """
    Return DER bytes for every certificate the peer presented.
    Uses SSLSocket.getpeercert(True) for the leaf and (when available)
    get_unverified_chain/get_verified_chain for the full chain.

    On Python < 3.13 those methods don't exist, so we fall back to
    openssl s_client to extract the full chain. To avoid opening a
    second TLS connection (which could hit a different backend behind
    a load balancer), the openssl fallback is invoked as a standalone
    scan — see _scan_via_openssl().
    """
    leaf = ssl_sock.getpeercert(binary_form=True)
    chain: list[bytes] = []
    if leaf:
        chain.append(leaf)
    for method in ("get_unverified_chain", "get_verified_chain"):
        getter = getattr(ssl_sock, method, None)
        if getter:
            try:
                items = getter()
            except Exception:  # noqa: BLE001
                continue
            chain = []
            for c in items:
                try:
                    der = c.public_bytes(_der_enc())
                except AttributeError:
                    der = bytes(c)
                chain.append(der)
            break

    return chain


_PEM_CERT_PATTERN = re.compile(
    b"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL,
)


_PROTOCOL_RE = re.compile(rb"Protocol\s*:\s*(TLSv[\d.]+|SSLv[\d.]+)", re.IGNORECASE)


def _scan_via_openssl(
    hostname: str, port: int, timeout: float, *, allow_private: bool = True,
    dns_servers: tuple[str, ...] = (), pinned_ip: str | None = None,
) -> tuple[list[bytes], str]:
    """Extract the full certificate chain and protocol version using a single
    openssl s_client call.

    Returns (der_chain, protocol_version). protocol_version is e.g.
    'TLSv1.3' or empty string if not detected.
    """
    try:
        if pinned_ip:
            import ipaddress as _ip

            ip = _ip.ip_address(pinned_ip)
            if _is_blocked_ip(ip, allow_private=allow_private):
                return [], ""
            host = pinned_ip
        else:
            _family, sockaddr = _resolve_host(
                hostname, port, allow_private=allow_private, dns_servers=dns_servers,
            )
            host = sockaddr[0]
    except OSError:
        return [], ""
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
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return [], ""

    if proc.returncode not in (0, 1):
        return [], ""

    protocol_version = ""
    proto_match = _PROTOCOL_RE.search(proc.stdout)
    if proto_match:
        protocol_version = proto_match.group(1).decode("ascii", errors="replace")

    pem_output = proc.stdout
    matches = _PEM_CERT_PATTERN.findall(pem_output)
    if not matches:
        return [], protocol_version

    result: list[bytes] = []
    for pem_b64 in matches:
        try:
            der = base64.b64decode(pem_b64)
            result.append(der)
        except Exception:
            continue

    return result, protocol_version


def _has_native_chain_api() -> bool:
    """Check if the current Python supports native chain extraction (3.13+)."""
    return hasattr(ssl.SSLSocket, "get_unverified_chain") or hasattr(
        ssl.SSLSocket, "get_verified_chain"
    )


def _der_enc():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _friendly_scan_error(exc: BaseException) -> str:
    """Translate raw socket/TLS exceptions into human-friendly messages."""
    msg = str(exc)
    import errno as _errno
    if isinstance(exc, ConnectionRefusedError) or _errno.ECONNREFUSED in (
        getattr(exc, "errno", None),
    ):
        return "Connection refused — the host is not accepting connections on this port"
    if isinstance(exc, TimeoutError):
        return "Connection timed out — the host did not respond in time"
    if isinstance(exc, OSError):
        if "DNS resolution failed" in msg or "Name or service not known" in msg:
            return f"Could not resolve hostname: {msg}"
        if "blocked address" in msg.lower():
            return msg
        if "timed out" in msg.lower():
            return "Connection timed out — the host did not respond in time"
        if "Network is unreachable" in msg:
            return "Network unreachable — no route to the host"
        return f"Connection failed: {msg}"
    return msg


def scan_host(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    allow_private: bool = True,
    dns_servers: tuple[str, ...] = (),
    retries: int = SCAN_RETRIES,
    pinned_ip: str | None = None,
) -> ScannedEntry | ScanError:
    """Perform a TLS handshake and return ScannedEntry or ScanError. See AC-01..AC-06.

    When pinned_ip is None, the hostname is resolved once per attempt and the
    resulting IP is pinned for the entire scan (DNS-rebinding hardening, BC-063).
    """
    last_error: ScanError | None = None
    for attempt in range(1 + retries):
        result = _scan_host_once(
            hostname, port, timeout=timeout, verify=verify,
            allow_private=allow_private, dns_servers=dns_servers,
            pinned_ip=pinned_ip,
        )
        if isinstance(result, ScannedEntry):
            return result
        last_error = result
        if attempt < retries:
            import time
            time.sleep(SCAN_RETRY_BACKOFF * (2 ** attempt))
    return last_error


def _scan_host_once(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    allow_private: bool = True,
    dns_servers: tuple[str, ...] = (),
    pinned_ip: str | None = None,
) -> ScannedEntry | ScanError:
    """Single TLS handshake attempt — no retry logic.

    When pinned_ip is not supplied, resolves the hostname once and pins the
    resulting IP for the entire scan (prevents DNS-rebinding TOCTOU, BC-063).

    On Python < 3.13, native chain extraction is unavailable. Rather than
    opening a second TLS connection to the same host (which can hit a
    different backend behind a load balancer), we use openssl s_client
    as the primary connection, getting both leaf and chain from one call.
    """
    if pinned_ip is None:
        try:
            _fam, _saddr = _resolve_host(
                hostname, port, allow_private=allow_private,
                dns_servers=dns_servers,
            )
            pinned_ip = _saddr[0]
        except OSError:
            pass

    if not _has_native_chain_api():
        return _scan_host_via_openssl(
            hostname, port, timeout=timeout,
            allow_private=allow_private, dns_servers=dns_servers,
            pinned_ip=pinned_ip, verify=verify,
        )

    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=verify, allow_private=allow_private,
            dns_servers=dns_servers, pinned_ip=pinned_ip,
        )
    except (TimeoutError, OSError) as exc:
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))
    except Exception as exc:  # noqa: BLE001
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))

    protocol_version = ""
    with contextlib.suppress(Exception):
        protocol_version = ssl_sock.version() or ""

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

    hsts = _probe_hsts(hostname, port, pinned_ip=pinned_ip)

    return ScannedEntry(
        host=hostname,
        port=port,
        leaf=leaf_parsed,
        chain=chain_certs,
        scanned_at=datetime.now(UTC),
        protocol_version=protocol_version,
        hsts=hsts,
        tls_verified=verify,
    )


def _scan_host_via_openssl(
    hostname: str,
    port: int,
    *,
    timeout: float,
    allow_private: bool,
    dns_servers: tuple[str, ...],
    pinned_ip: str | None = None,
    verify: bool = False,
) -> ScannedEntry | ScanError:
    """Scan using openssl s_client only — one connection for both leaf and chain.

    Used on Python < 3.13 where SSLSocket lacks native chain methods.
    If openssl is unavailable or fails, falls back to the Python TLS
    connection (leaf-only, no chain).
    """
    der_chain, protocol_version = _scan_via_openssl(
        hostname, port, timeout, allow_private=allow_private, dns_servers=dns_servers,
        pinned_ip=pinned_ip,
    )

    if der_chain:
        leaf_parsed = parse_certificate(der_chain[0])
        if isinstance(leaf_parsed, Certificate):
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
                protocol_version=protocol_version,
                hsts=_probe_hsts(hostname, port, pinned_ip=pinned_ip),
                tls_verified=False,
            )

    # Fallback: try Python TLS connection for leaf-only scan
    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=False,
            allow_private=allow_private, dns_servers=dns_servers,
            pinned_ip=pinned_ip,
        )
    except (TimeoutError, OSError) as exc:
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))
    except Exception as exc:  # noqa: BLE001
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))

    protocol_version_fb = ""
    with contextlib.suppress(Exception):
        protocol_version_fb = ssl_sock.version() or ""

    try:
        leaf = ssl_sock.getpeercert(binary_form=True)
    finally:
        with contextlib.suppress(Exception):
            ssl_sock.close()

    if not leaf:
        return ScanError(
            hostname=hostname, port=port, error_message="no certificate presented"
        )

    leaf_parsed = parse_certificate(leaf)
    if not isinstance(leaf_parsed, Certificate):
        return ScanError(
            hostname=hostname, port=port, error_message=leaf_parsed.message
        )

    return ScannedEntry(
        host=hostname,
        port=port,
        leaf=leaf_parsed,
        chain=[],
        scanned_at=datetime.now(UTC),
        protocol_version=protocol_version_fb,
        hsts=_probe_hsts(hostname, port, pinned_ip=pinned_ip),
        tls_verified=False,
    )


def store_scanned(entry: ScannedEntry, repo_path_or_repo) -> str:
    """
    Persist leaf + chain. Accepts either an existing CertificateRepository OR a path
    (so callers can pass the db path directly and we wire up source/hostname/port).
    Removes any previous leaf + chain certs for the same (hostname, port) first to
    avoid accumulation on repeated scans. Also evaluates and stores TLS posture.
    See AC-07.
    """
    if isinstance(repo_path_or_repo, str | Path):
        init_schema(repo_path_or_repo)
        leaf_id = replace_scanned(
            repo_path_or_repo,
            hostname=entry.host,
            port=entry.port,
            leaf=entry.leaf,
            chain=entry.chain,
            chain_valid=None,
        )
        posture_grade = ""
        try:
            posture_grade = _evaluate_and_store_posture(
                repo_path_or_repo, leaf_id, entry,
            )
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger("cert_watch.scan").debug(
                "posture evaluation skipped for %s:%s", entry.host, entry.port,
                exc_info=True,
            )
        try:
            from cert_watch.database.queries import (
                _extract_key_algo,
                _extract_sig_algo,
                create_drift_alert,
                detect_drift,
            )
            key_algo = _extract_key_algo(entry.leaf.raw_der) if entry.leaf.raw_der else ""
            sig_algo = _extract_sig_algo(entry.leaf.raw_der) if entry.leaf.raw_der else ""
            drift_events = detect_drift(
                repo_path_or_repo,
                hostname=entry.host,
                port=entry.port,
                new_leaf=entry.leaf,
                posture_grade=posture_grade,
                protocol_version=entry.protocol_version,
                key_algo=key_algo,
                sig_algo=sig_algo,
            )
            if drift_events:
                try:
                    import cert_watch.config as _cfg
                    _s = _cfg.Settings.from_env()
                    if _s.drift_alerts:
                        create_drift_alert(
                            repo_path_or_repo,
                            cert_id=leaf_id,
                            hostname=entry.host,
                            port=entry.port,
                            events=drift_events,
                        )
                except Exception:  # noqa: BLE001
                    import logging
                    logging.getLogger("cert_watch.scan").debug(
                        "drift alert creation skipped for %s:%s", entry.host, entry.port,
                        exc_info=True,
                    )
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger("cert_watch.scan").debug(
                "drift detection skipped for %s:%s", entry.host, entry.port,
                exc_info=True,
            )
        try:
            from cert_watch.database.queries import record_cert_history
            record_cert_history(
                repo_path_or_repo,
                hostname=entry.host,
                port=entry.port,
                leaf=entry.leaf,
                posture_grade=posture_grade,
                protocol_version=entry.protocol_version,
            )
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger("cert_watch.scan").debug(
                "cert_history write skipped for %s:%s", entry.host, entry.port,
                exc_info=True,
            )
        return leaf_id

    repo = repo_path_or_repo
    leaf_id = repo.add(entry.leaf)
    for chain_cert in entry.chain:
        repo.add(chain_cert)
    return leaf_id


def _evaluate_and_store_posture(
    db_path: str | Path,
    cert_id: str,
    entry: ScannedEntry,
) -> str:
    """Evaluate TLS posture and store the result. Returns the grade string."""
    from cert_watch.cert_chain import chain_status
    from cert_watch.certificate_model import Certificate as _Cert
    from cert_watch.database import SqliteTrustAnchorRepository
    from cert_watch.database.queries import store_scan_posture
    from cert_watch.posture import evaluate_posture

    cert = entry.leaf
    chain = entry.chain

    init_schema(db_path)
    anchors = [_Cert(
        subject=a.subject, issuer=a.issuer,
        not_before=a.not_before, not_after=a.not_after,
        san_dns_names=a.san_dns_names,
        fingerprint_sha256=a.fingerprint_sha256,
        raw_der=a.raw_der,
    ) for a in SqliteTrustAnchorRepository(db_path).list_entries()]

    cs = chain_status(cert, chain, anchors) if chain else None

    # Read revocation check toggle from config
    try:
        import cert_watch.config as _cfg
        _s = _cfg.Settings.from_env()
        _check_revocation = _s.check_revocation
    except Exception:
        _check_revocation = False

    result = evaluate_posture(
        cert=cert,
        protocol_version=entry.protocol_version or None,
        chain_status=cs,
        hsts=entry.hsts,
        check_revocation=_check_revocation,
    )

    store_scan_posture(
        db_path=db_path,
        cert_id=cert_id,
        hostname=entry.host,
        port=entry.port,
        grade=result.grade,
        findings=result.findings,
        protocol_version=result.protocol_version,
        ocsp_stapling=result.ocsp_stapling,
        hsts=result.hsts,
        must_staple=result.must_staple,
        tls_verified=entry.tls_verified,
    )
    return result.grade
