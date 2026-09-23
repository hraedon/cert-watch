"""Host-header validation for deliberately unauthenticated deployments."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from fastapi import Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import PlainTextResponse, Response

from cert_watch.auth import NoAuthProvider


def _hostname_from_host_header(value: str) -> str | None:
    if not value or value != value.strip() or any(char.isspace() for char in value):
        return None
    try:
        parsed = urlsplit(f"//{value}")
        _ = parsed.port  # Force validation of a malformed/non-numeric port.
    except ValueError:
        return None
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    return parsed.hostname.rstrip(".").casefold()


def _host_is_allowed(value: str, base_url: str) -> bool:
    hostname = _hostname_from_host_header(value)
    if hostname is None:
        return False
    if hostname == "localhost":
        return True
    try:
        if ipaddress.ip_address(hostname).is_loopback:
            return True
    except ValueError:
        pass
    configured = urlsplit(base_url).hostname if base_url else None
    return bool(configured and hostname == configured.rstrip(".").casefold())


async def open_mode_host_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Reject DNS-rebinding Host values while authentication is disabled."""
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is not None and not isinstance(auth, NoAuthProvider):
        return await call_next(request)

    host_values = request.headers.getlist("host")
    settings = getattr(request.app.state, "settings", None)
    base_url = getattr(settings, "base_url", "") if settings else ""
    if len(host_values) != 1 or not _host_is_allowed(host_values[0], base_url):
        return PlainTextResponse("invalid Host header", status_code=400)
    return await call_next(request)
