"""SSRF-guarded HTTP client — resolves and pins the IP for each URL (initial and
redirect targets) before the request proceeds, eliminating the DNS-rebinding
TOCTOU window.

Every hop is resolved once via ``getaddrinfo``, validated against the scan
blocklist, and the connection is pinned to the validated IP (with the
``Host`` header / SNI set to the original hostname).  Redirects are validated
and pinned independently at each hop.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import socket
import ssl
import typing
import urllib.request
from http.client import HTTPMessage, HTTPResponse
from typing import IO
from urllib.parse import urlparse, urlunparse

from cert_watch.scan_resolver import _is_blocked_ip

logger = logging.getLogger("cert_watch.http_client")


class SSRFBlockedError(Exception):
    """Raised when an HTTP request targets a blocked address."""


def _validate_url(
    url: str,
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> str:
    """Resolve and validate *url* against the SSRF blocklist.

    Returns the resolved (or literal) IP address for DNS-rebinding protection.
    The caller should pin the connection to this IP (via :func:`_pin_url`) so
    that urllib does not re-resolve the hostname independently.

    Raises ``SSRFBlockedError`` when the resolved IP is blocked.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"disallowed scheme: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL has no hostname")
    # Literal IP — validate and return
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            raise SSRFBlockedError(f"blocked IP: {ip}")
        return str(ip)
    except ValueError:
        pass
    # Hostname — resolve and validate all returned IPs
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise SSRFBlockedError(f"cannot resolve hostname: {hostname}") from None
    first_allowed: str | None = None
    for _fam, _type, _proto, _canon, sockaddr in infos:
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_blocked_ip(resolved, allow_private=allow_private, allowed_subnets=allowed_subnets):
            raise SSRFBlockedError(f"blocked resolved IP: {resolved} for hostname {hostname}")
        if first_allowed is None:
            first_allowed = str(resolved)
    if first_allowed is None:
        raise SSRFBlockedError(f"no allowed addresses for hostname {hostname}")
    return first_allowed


def _pin_url(url: str, pinned_ip: str) -> tuple[str, str, str]:
    """Replace the hostname in *url* with *pinned_ip*.

    Returns ``(pinned_url, original_hostname, host_header_value)``.

    The *host_header_value* includes the port when non-standard so it can be
    used directly as the ``Host`` header.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port

    # Build the Host header value: original hostname + port (non-standard only)
    if port and not (
        (parsed.scheme == "http" and port == 80)
        or (parsed.scheme == "https" and port == 443)
    ):
        host_header = f"{hostname}:{port}"
    else:
        host_header = hostname

    # Build new netloc with pinned IP (bracket IPv6)
    ip_host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    netloc = f"{ip_host}:{port}" if port else ip_host

    pinned = urlunparse(parsed._replace(netloc=netloc))
    return pinned, hostname, host_header


class _PinnedRequest(urllib.request.Request):
    """Request subclass declaring the SSRF pinning attributes that
    ``_PinnedHTTPSHandler`` reads back via ``getattr``."""

    _pinned_ip: str | None
    _pinned_hostname: str | None


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS handler that connects to the pinned IP with SNI = original hostname.

    Reads ``_pinned_ip`` and ``_pinned_hostname`` from the request object
    (set by :func:`ssrf_safe_urlopen` and the redirect handler).  When those
    attributes are missing (e.g. the opener is used without pinning), falls
    back to the default connection behaviour.
    """

    # stdlib HTTPSHandler stores the SSLContext here but typeshed doesn't expose it.
    _context: ssl.SSLContext

    def https_open(self, req: urllib.request.Request) -> typing.Any:
        pinned_ip = getattr(req, "_pinned_ip", None)
        original_hostname = getattr(req, "_pinned_hostname", None)

        if not pinned_ip or not original_hostname:
            # No pinning info — fall back to default behaviour
            return self.do_open(http.client.HTTPSConnection, req)

        parsed = urlparse(req.get_full_url())
        original_port = parsed.port or 443
        ctx = self._context

        # Capture for the closure
        _pinned_ip = pinned_ip
        _hostname = original_hostname
        _port = original_port

        class _Conn(http.client.HTTPSConnection):
            """HTTPSConnection that TCP-connects to the pinned IP."""

            # Declared so mypy accepts the attribute access below.  These are
            # inherited from HTTPConnection / HTTPSConnection but typeshed
            # doesn't expose all of them as instance attributes.
            _pinned_ip: str
            _tunnel_host: str | None
            source_address: tuple[str, int] | None

            def __init__(conn_self, host: str, **kwargs: typing.Any) -> None:
                super().__init__(_hostname, port=_port, context=ctx, **kwargs)
                conn_self._pinned_ip = _pinned_ip
                conn_self.server_hostname = _hostname

            def connect(conn_self) -> None:
                # socket.create_connection() takes a 2-tuple (host, port) and
                # resolves IP literals itself. Passing the 4-tuple sockaddr form
                # used by socket.connect() raises "too many values to unpack",
                # which previously broke ALL HTTPS delivery to IPv6 targets
                # (webhooks, HEC, scans). An IPv6 literal connects fine via the
                # 2-tuple; only scope-bearing link-local addresses would need the
                # scope_id, and those are always SSRF-blocked upstream.
                conn_self.sock = socket.create_connection(
                    (conn_self._pinned_ip, conn_self.port),
                    conn_self.timeout, conn_self.source_address,
                )
                if conn_self._tunnel_host:
                    conn_self._tunnel_host = None
                conn_self.sock = ctx.wrap_socket(
                    conn_self.sock, server_hostname=conn_self.server_hostname,
                )

        return self.do_open(_Conn, req)


def _ssrf_safe_redirect_handler(
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> urllib.request.HTTPRedirectHandler:
    """Build a redirect handler that validates and pins each redirect target."""

    class _Handler(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self, req: urllib.request.Request, fp: IO[bytes], code: int,
            msg: str, headers: HTTPMessage, newurl: str,
        ) -> urllib.request.Request | None:
            pinned_ip = _validate_url(
                newurl,
                allow_private=allow_private,
                allowed_subnets=allowed_subnets,
            )
            new_req = super().redirect_request(
                req, fp, code, msg, headers, newurl,
            )
            if new_req is None:
                return None
            pinned_url, original_hostname, host_header = _pin_url(newurl, pinned_ip)
            new_req.full_url = pinned_url
            new_req.add_unredirected_header("Host", host_header)
            # urllib's redirect handler creates plain Request objects; we
            # attach the pinning attributes so _PinnedHTTPSHandler can read
            # them back on the next hop.
            pinned_req = typing.cast("_PinnedRequest", new_req)
            pinned_req._pinned_ip = pinned_ip
            pinned_req._pinned_hostname = original_hostname
            return pinned_req

    return _Handler()


def ssrf_safe_urlopen(
    url: str,
    *,
    data: bytes | None = None,
    timeout: int = 15,
    method: str | None = None,
    headers: dict[str, str] | None = None,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> HTTPResponse:
    """Open a URL with SSRF validation and IP pinning on every hop.

    The hostname is resolved once, validated, and the connection is pinned to
    that IP (with the ``Host`` header / SNI set to the original hostname).
    This eliminates the DNS-rebinding TOCTOU window.

    Returns the final response object (caller must close it). Raises
    ``SSRFBlockedError`` when a hop resolves to a blocked address.
    """
    pinned_ip = _validate_url(
        url, allow_private=allow_private, allowed_subnets=allowed_subnets,
    )
    pinned_url, original_hostname, host_header = _pin_url(url, pinned_ip)

    redirect_handler = _ssrf_safe_redirect_handler(
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
    )
    https_handler = _PinnedHTTPSHandler()
    opener = urllib.request.build_opener(redirect_handler, https_handler)

    req = _PinnedRequest(pinned_url, data=data, method=method)
    req.add_unredirected_header("Host", host_header)
    req._pinned_ip = pinned_ip
    req._pinned_hostname = original_hostname
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    return typing.cast("HTTPResponse", opener.open(req, timeout=timeout))


def validate_webhook_url(
    url: str,
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> str | None:
    """Validate a webhook URL for SSRF safety.

    Returns an error message string if blocked, or None if valid.
    """
    try:
        _validate_url(url, allow_private=allow_private, allowed_subnets=allowed_subnets)
    except SSRFBlockedError as exc:
        return str(exc)
    return None


def validate_smtp_host(
    host: str,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> str | None:
    """Validate an SMTP host for SSRF safety (BC-116 SMTP parity).

    Resolves *host* and validates every returned IP against the scan
    blocklist. Returns an error message string if a resolved IP is blocked,
    or None if valid.

    Unlike :func:`validate_webhook_url`, a *resolution failure* is **not**
    treated as a block: when the host cannot be resolved no blocked IP is
    reachable, so ``smtplib`` is allowed to fail naturally on its own. This
    also preserves the common test pattern of mocking ``smtplib`` against
    non-resolving fake hostnames, and matches the threat model where
    ``smtp_host`` is admin-configured (not an attacker-controlled URL).

    The ``allow_private`` default is True because
    ``CERT_WATCH_ALLOW_PRIVATE_IPS`` defaults to ``1`` and legitimate SMTP
    relays are very often internal (10.x / 192.168.x).
    """
    # Literal IP — validate directly
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return f"blocked IP: {ip}"
        return None
    except ValueError:
        pass
    # Hostname — resolve and validate; resolution failure is not a block
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    for _fam, _type, _proto, _canon, sockaddr in infos:
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_blocked_ip(resolved, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return f"blocked resolved IP: {resolved} for hostname {host}"
    return None
