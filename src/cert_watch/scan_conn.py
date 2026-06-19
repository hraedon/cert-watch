"""TLS connection and certificate chain extraction for scanning."""

from __future__ import annotations

import base64
import contextlib
import http.client
import logging
import re
import socket
import ssl
import subprocess
import threading
import time

from cert_watch.scan_resolver import _is_blocked_ip, _resolve_host

logger = logging.getLogger("cert_watch.scan")

HSTS_TIMEOUT = 5.0
DEFAULT_SCAN_MAX_OUTPUT_BYTES = 1024 * 1024


class ScanOutputTooLargeError(Exception):
    """Raised when an openssl subprocess produces more output than the configured cap."""


def _format_connect_host(host: str) -> str:
    """Format a host string for openssl's ``-connect`` argument.

    IPv6 address literals must be wrapped in brackets
    (e.g. ``[::1]:443``); IPv4 and hostnames are returned as-is.
    """
    import ipaddress as _ip

    try:
        addr = _ip.ip_address(host)
    except ValueError:
        return host
    if isinstance(addr, _ip.IPv6Address):
        return f"[{host}]"
    return host


def _probe_hsts(
    hostname: str,
    port: int,
    pinned_ip: str | None = None,
    *,
    require_443: bool = True,
    verify: bool = False,
    timeout: float = HSTS_TIMEOUT,
) -> bool | None:
    """Check if an HTTPS server sends Strict-Transport-Security.

    Returns True if HSTS header found, False if not found, None on error.
    When pinned_ip is provided, connects to that IP with SNI=hostname
    (prevents DNS rebinding).

    Precondition: *pinned_ip* must already be validated against
    :func:`_is_blocked_ip` by the caller (typically :func:`_resolve_host`).

    By default, the check is skipped for non-443 ports because HSTS is only
    meaningful on the standard HTTPS port during production scans. Pass
    ``require_443=False`` to override this for testing or special cases.
    """
    if require_443 and port != 443:
        return None
    try:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if pinned_ip:
            sock = socket.create_connection((pinned_ip, port), timeout=timeout)
            try:
                ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            except Exception:  # cleanup: close raw socket on SSL wrap failure, then re-raise
                sock.close()
                raise
            conn = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=ctx)
            conn.sock = ssl_sock
        else:
            conn = http.client.HTTPSConnection(
                hostname, port, timeout=timeout, context=ctx,
            )
        try:
            conn.request("HEAD", "/", headers={"Host": hostname})
            resp = conn.getresponse()
            hsts_header = resp.getheader("Strict-Transport-Security")
        finally:
            conn.close()
        return hsts_header is not None
    except (OSError, ValueError, http.client.HTTPException):
        return None


def _open_tls_connection(
    hostname: str, port: int, timeout: float, *, verify: bool = False,
    allow_private: bool = True, allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (),
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
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            raise OSError(f"pinned IP {pinned_ip} is a blocked address")
    else:
        _family, sockaddr = _resolve_host(
            hostname, port, allow_private=allow_private,
            allowed_subnets=allowed_subnets, dns_servers=dns_servers,
        )
    sock = socket.socket(family if pinned_ip else _family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(sockaddr)
        return ctx.wrap_socket(sock, server_hostname=hostname)
    except Exception:  # cleanup: close socket on connection/TLS failure, then re-raise
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
    try:
        leaf = ssl_sock.getpeercert(binary_form=True)
    except (AttributeError, ValueError):
        leaf = None
    chain: list[bytes] = []
    if leaf:
        chain.append(leaf)
    for method in ("get_unverified_chain", "get_verified_chain"):
        getter = getattr(ssl_sock, method, None)
        if getter:
            try:
                items = getter()
            except Exception:  # noqa: BLE001 — Python 3.13+ chain APIs; error modes not fully known, fall through to next method
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


def _run_openssl(
    cmd: list[str],
    input_data: bytes,
    max_output_bytes: int,
    timeout: float,
) -> tuple[bytes, bytes, int]:
    """Run an openssl subprocess with bounded stdout and overall timeout.

    Raises FileNotFoundError, OSError, TimeoutError, or
    ScanOutputTooLargeError. On normal completion returns
    (stdout, stderr, returncode).
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        if proc.stdin is not None:
            try:
                proc.stdin.write(input_data)
                proc.stdin.flush()
                proc.stdin.close()
            except BrokenPipeError:
                pass

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        too_large = False

        def _reader() -> None:
            nonlocal too_large
            accumulated = 0
            chunk_size = 65536
            while True:
                chunk = proc.stdout.read(chunk_size)  # type: ignore[union-attr]
                if not chunk:
                    break
                accumulated += len(chunk)
                if accumulated > max_output_bytes:
                    too_large = True
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    break
                stdout_chunks.append(chunk)

        def _err_reader(deadline: float) -> None:
            accumulated = 0
            chunk_size = 4096
            max_stderr = 65536
            while True:
                if time.monotonic() >= deadline:
                    break
                chunk = proc.stderr.read(chunk_size)  # type: ignore[union-attr]
                if not chunk:
                    break
                accumulated += len(chunk)
                if accumulated > max_stderr:
                    # Stop appending; also stop draining the pipe so a
                    # misbehaving child cannot stall us forever. Closing the
                    # read end gives the child a broken pipe instead of a full
                    # stderr buffer.
                    with contextlib.suppress(Exception):
                        proc.stderr.close()  # type: ignore[union-attr]
                    break
                stderr_chunks.append(chunk)

        reader = threading.Thread(target=_reader)
        deadline = time.monotonic() + timeout
        err_reader = threading.Thread(target=_err_reader, args=(deadline,))
        reader.start()
        err_reader.start()

        for t in (reader, err_reader):
            remaining = deadline - time.monotonic()
            t.join(timeout=max(remaining, 0))
            if t.is_alive():
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                reader.join(timeout=1)
                err_reader.join(timeout=1)
                if too_large:
                    break
                raise TimeoutError("openssl subprocess timed out")

        if too_large:
            reader.join(timeout=1)
            err_reader.join(timeout=1)
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except ProcessLookupError:
                    pass
            raise ScanOutputTooLargeError(
                f"openssl output exceeded {max_output_bytes} bytes"
            )

        if proc.poll() is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=1)
        return b"".join(stdout_chunks), b"".join(stderr_chunks), proc.returncode

    finally:
        if proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.kill()
                proc.wait(timeout=1)


def _scan_via_openssl(
    hostname: str, port: int, timeout: float, *, allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (), pinned_ip: str | None = None,
    max_output_bytes: int = DEFAULT_SCAN_MAX_OUTPUT_BYTES,
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
            if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
                return [], ""
            host = pinned_ip
        else:
            _family, sockaddr = _resolve_host(
                hostname, port, allow_private=allow_private,
                allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            )
            host = sockaddr[0]
    except OSError:
        return [], ""
    if hostname.startswith("-"):
        return [], ""
    connect_host = _format_connect_host(host)
    try:
        stdout, stderr, returncode = _run_openssl(
            [
                "openssl", "s_client",
                "-connect", f"{connect_host}:{port}",
                "-servername", hostname,
                "-showcerts",
            ],
            b"Q\n",
            max_output_bytes=max_output_bytes,
            timeout=timeout,
        )
    except (TimeoutError, FileNotFoundError, OSError):
        return [], ""

    if returncode not in (0, 1):
        logging.getLogger("cert_watch.scan").debug(
            "openssl s_client for %s:%s exited %s: %s",
            hostname, port, returncode,
            stderr.decode("utf-8", errors="replace")[:500] if stderr else "",
        )
        return [], ""

    protocol_version = ""
    proto_match = _PROTOCOL_RE.search(stdout)
    if proto_match:
        protocol_version = proto_match.group(1).decode("ascii", errors="replace")

    pem_output = stdout
    matches = _PEM_CERT_PATTERN.findall(pem_output)
    if not matches:
        return [], protocol_version

    result: list[bytes] = []
    for pem_b64 in matches:
        try:
            der = base64.b64decode(pem_b64)
            result.append(der)
        except (ValueError, TypeError):
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
