"""Browser-facing 404 page (#126 S2).

An unknown path used to answer every client with FastAPI's JSON body
``{"detail": "Not Found"}``, so a browser showed a bare page with no language,
title or ``<main>`` landmark. Browsers (``Accept: text/html``) now get a small
standalone HTML page; API paths and every other client keep the JSON body.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from cert_watch.routes._deps import get_templates


def _wants_html(request: Request) -> bool:
    if request.url.path == "/api" or request.url.path.startswith("/api/"):
        return False
    return "text/html" in request.headers.get("accept", "")


async def _not_found_handler(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, StarletteHTTPException)
    if exc.status_code == 404 and _wants_html(request):
        return get_templates().TemplateResponse(
            request=request, name="not_found.html", context={}, status_code=404
        )
    return await http_exception_handler(request, exc)


def install_not_found_handler(application: FastAPI) -> None:
    """Serve the HTML 404 page to browsers; everything else is unchanged."""
    application.add_exception_handler(StarletteHTTPException, _not_found_handler)
