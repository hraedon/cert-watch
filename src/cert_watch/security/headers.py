"""Per-request CSP nonce (pure ASGI) and the security response headers."""

from __future__ import annotations

import logging
import secrets
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("cert_watch.middleware")

# HSTS is emitted only for HTTPS deployments (same switch as the Secure flag
# on the session and CSRF cookies).
_COOKIE_SECURE = True  # Direct-call/test fallback; request paths use Settings.


def _cookie_secure(request: Request | None = None) -> bool:
    if not _COOKIE_SECURE:
        return False
    app = request.scope.get("app") if request is not None else None
    settings = getattr(getattr(app, "state", None), "settings", None)
    configured = getattr(settings, "cookie_secure", True)
    return configured if isinstance(configured, bool) else _COOKIE_SECURE


def _build_csp(nonce: str, report_uri: str = "") -> str:
    """Build the Content-Security-Policy header for a request.

    ``script-src`` uses a per-request nonce — inline ``on*=`` event-handler
    attributes have been fully converted to ``data-*`` + delegated
    ``addEventListener`` (BC-075).

    ``style-src`` is ``'self'`` only: the 2026-08 redesign removed every
    inline ``style=`` attribute (dynamic values live in SVG geometry
    attributes and tone classes), enforced by tests/test_no_inline_styles.py.

    ``report-uri`` is appended when ``CERT_WATCH_CSP_REPORT_URI`` is set.
    """
    policy = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    if report_uri:
        parsed = urlparse(report_uri)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            policy += f"; report-uri {report_uri}"
        else:
            logger.warning(
                "CERT_WATCH_CSP_REPORT_URI is not a valid http(s) URL, ignoring"
            )
    return policy


class CSPNonceMiddleware:
    """Pure-ASGI middleware that issues a per-request CSP nonce into
    ``scope['state']`` before anything else runs.

    Done as raw ASGI (not ``BaseHTTPMiddleware``) deliberately: ``request.state``
    set inside a ``BaseHTTPMiddleware`` does not propagate to the endpoint /
    template render (task isolation), but ``scope['state']`` written here is
    shared with the downstream request — so both the templates
    (``{{ request.state.csp_nonce }}``) and ``security_headers_middleware`` (for
    the eventual header flip) read the same value. See BC-075.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope.setdefault("state", {})["csp_nonce"] = secrets.token_urlsafe(16)
        await self.app(scope, receive, send)


def _apply_security_headers(
    response: Response,
    nonce: str,
    *,
    report_uri: str = "",
    cookie_secure: bool = _COOKIE_SECURE,
) -> None:
    """Apply security headers to a response (shared by normal + error paths)."""
    response.headers["Content-Security-Policy"] = _build_csp(nonce, report_uri)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if cookie_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )


async def security_headers_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Add security response headers (CSP, X-Content-Type-Options, etc.).

    The per-request CSP nonce is issued upstream by :class:`CSPNonceMiddleware`
    (``request.state.csp_nonce``) and consumed here by ``_build_csp(nonce)``: the
    emitted ``script-src`` is ``'self' 'nonce-{nonce}'`` with no ``'unsafe-inline'``
    (BC-075 flip done) and ``style-src`` is ``'self'`` with no ``'unsafe-inline'``
    (2026-08 redesign: zero inline style attributes remain).

    M7: wraps ``call_next`` in try/except so security headers are applied even
    when the handler raises (Starlette's ``ServerErrorMiddleware`` returns a 500
    that bypasses this middleware without the try/except).
    """
    nonce = getattr(request.state, "csp_nonce", "")
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled exception in request handler")
        response = JSONResponse(
            content={"detail": "Internal Server Error"},
            status_code=500,
        )
    settings = getattr(request.app.state, "settings", None)
    _apply_security_headers(
        response,
        nonce,
        report_uri=getattr(settings, "csp_report_uri", ""),
        cookie_secure=_cookie_secure(request),
    )
    return response
