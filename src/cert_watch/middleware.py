"""HTTP middleware wiring.

Each concern lives in its own module; this one only installs them, in order:

- :mod:`cert_watch.security.headers` -- CSP nonce + security headers
- :mod:`cert_watch.security.csrf` -- the ``cw_sid`` CSRF session cookie
- :func:`setup_redirect_middleware` (here) -- first-run redirect to /setup
- :mod:`cert_watch.auth.request_context` -- session / API-key authentication
- :mod:`cert_watch.security.ratelimit` -- the ``/api/*`` rate limit

Authorization is not middleware: it is the guard dependency each route
declares (:mod:`cert_watch.auth.guards`).
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from cert_watch.auth.request_context import auth_middleware, is_public_path
from cert_watch.security.csrf import csrf_session_middleware
from cert_watch.security.headers import CSPNonceMiddleware, security_headers_middleware
from cert_watch.security.ratelimit import rate_limit_headers_middleware


async def setup_redirect_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Redirect all HTML page requests to /setup when the app needs first-run configuration.

    Detected via app.state.needs_setup flag set during lifespan.
    Public paths, /setup itself, and API paths are never redirected.
    API requests without auth will get 401 from auth_middleware regardless.
    """
    needs_setup = getattr(request.app.state, "needs_setup", False)
    if not needs_setup:
        return await call_next(request)
    path = request.url.path
    if is_public_path(path) or path.startswith("/setup") or path.startswith("/api/"):
        return await call_next(request)
    return RedirectResponse(url="/setup", status_code=303)


def install_middleware(application: FastAPI) -> None:
    """Register the HTTP middleware stack on *application*."""
    # Order matters: last registered = first executed.
    application.middleware("http")(security_headers_middleware)
    application.middleware("http")(csrf_session_middleware)
    application.middleware("http")(setup_redirect_middleware)
    application.middleware("http")(auth_middleware)
    application.middleware("http")(rate_limit_headers_middleware)
    # Outermost (runs first): issue the per-request CSP nonce into scope state
    # before any other middleware/endpoint, so the template context processor and
    # security_headers_middleware share it (BC-075).
    application.add_middleware(CSPNonceMiddleware)
