"""Clean request-validation failures for certificate upload adapters."""

from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.responses import Response

logger = logging.getLogger("cert_watch.routes.upload_validation")

_UPLOAD_PATHS = frozenset({"/upload", "/api/certificates/upload"})
_INVALID_UPLOAD_MESSAGE = "upload must include a certificate file"


async def _upload_validation_error(
    request: Request, exc: Exception
) -> Response:
    assert isinstance(exc, RequestValidationError)
    if request.url.path not in _UPLOAD_PATHS:
        return await request_validation_exception_handler(request, exc)

    # Keep framework diagnostics in the server log without recording submitted
    # field values (the multipart form may also contain a certificate password).
    details = [
        {key: value for key, value in error.items() if key not in {"input", "ctx"}}
        for error in exc.errors()
    ]
    logger.warning("invalid certificate upload request on %s: %s", request.url.path, details)
    if request.url.path == "/upload":
        return RedirectResponse(
            url=f"/?error={quote(_INVALID_UPLOAD_MESSAGE)}", status_code=303
        )
    return JSONResponse(status_code=422, content={"error": _INVALID_UPLOAD_MESSAGE})


def install_upload_validation_handler(application: FastAPI) -> None:
    """Install the upload-specific wrapper around FastAPI's default handler."""
    application.add_exception_handler(RequestValidationError, _upload_validation_error)
