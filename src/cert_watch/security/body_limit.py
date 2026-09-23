"""ASGI request-body size enforcement before framework body parsing."""

from __future__ import annotations

import logging

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_MAX_REQUEST_BODY_BYTES = 12 * 1024 * 1024
logger = logging.getLogger("cert_watch.security")


class RequestBodyLimitMiddleware:
    """Reject oversized HTTP bodies by declaration and by received bytes.

    This is pure ASGI middleware so the receive stream is bounded before
    Starlette's multipart parser can spool uploaded parts to disk.
    """

    def __init__(
        self, app: ASGIApp, max_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes

    def _log_oversized_request(self, scope: Scope) -> None:
        client = scope.get("client")
        client_host = client[0] if client else "unknown"
        logger.warning(
            "Request body rejected: method=%s path=%s client=%s limit=%d",
            scope.get("method", "unknown"),
            scope.get("path", "unknown"),
            client_host,
            self.max_bytes,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        lengths: list[int] = []
        for name, value in scope.get("headers", []):
            if name.lower() != b"content-length":
                continue
            try:
                lengths.append(int(value))
            except ValueError:
                response = PlainTextResponse("invalid Content-Length", status_code=400)
                await response(scope, receive, send)
                return
        if any(length < 0 for length in lengths) or len(set(lengths)) > 1:
            response = PlainTextResponse("invalid Content-Length", status_code=400)
            await response(scope, receive, send)
            return
        if lengths and lengths[0] > self.max_bytes:
            self._log_oversized_request(scope)
            response = PlainTextResponse("request body too large", status_code=413)
            await response(scope, receive, send)
            return

        received = 0
        response_started = False
        exceeded = False

        async def limited_receive() -> Message:
            nonlocal exceeded, received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if exceeded:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded:
            if response_started:
                return
            self._log_oversized_request(scope)
            response = PlainTextResponse("request body too large", status_code=413)
            await response(scope, receive, send)
