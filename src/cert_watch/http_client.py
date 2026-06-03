"""SSRF-guarded HTTP client — resolves and checks the initial URL and every
redirect target against the scan blocklist before the request proceeds.

Residual limitation (deliberate, documented): validation resolves the hostname
with ``getaddrinfo`` and rejects the request if *any* returned address is
blocked, but urllib re-resolves independently when it connects. A hostname whose
DNS flips between the check and the connect (DNS rebinding) therefore retains a
narrow window. Closing it fully requires pinning the resolved IP and connecting
to it with SNI (as ``scan.py`` does for the TLS scanner); that is a follow-up.
This guard is a large improvement over unvalidated ``urlopen`` — it is not an
airtight pin.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.request
from http.client import HTTPResponse
from urllib.parse import urlparse

from cert_watch.scan import _is_blocked_ip

logger = logging.getLogger("cert_watch.http_client")


class SSRFBlockedError(Exception):
    """Raised when an HTTP request targets a blocked address."""


def _validate_url(
    url: str,
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> None:
    """Resolve and validate *url* against the SSRF blocklist.

    Raises ``SSRFBlockedError`` when the resolved IP is blocked.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"disallowed scheme: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL has no hostname")
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            raise SSRFBlockedError(f"blocked IP: {ip}")
        return
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise SSRFBlockedError(f"cannot resolve hostname: {hostname}") from None
    for _fam, _type, _proto, _canon, sockaddr in infos:
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_blocked_ip(resolved, allow_private=allow_private, allowed_subnets=allowed_subnets):
            raise SSRFBlockedError(f"blocked resolved IP: {resolved} for hostname {hostname}")


def _ssrf_safe_redirect_handler(
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> urllib.request.HTTPRedirectHandler:
    """Build a redirect handler that validates each redirect target."""

    class _Handler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            _validate_url(
                newurl,
                allow_private=allow_private,
                allowed_subnets=allowed_subnets,
            )
            return super().redirect_request(req, fp, code, msg, headers, newurl)

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
    """Open a URL with SSRF validation on the initial URL and each redirect hop.

    Returns the final response object (caller must close it). Raises
    ``SSRFBlockedError`` when a hop resolves to a blocked address at check time.
    See the module docstring for the residual DNS-rebinding limitation.
    """
    _validate_url(url, allow_private=allow_private, allowed_subnets=allowed_subnets)

    redirect_handler = _ssrf_safe_redirect_handler(
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
    )
    opener = urllib.request.build_opener(redirect_handler)

    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    return opener.open(req, timeout=timeout)


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
