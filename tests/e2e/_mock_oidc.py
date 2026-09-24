"""A minimal OpenID Connect provider for browser tests (#98).

Serves discovery, ``/authorize``, ``/token`` and ``/jwks`` on 127.0.0.1 so a
cert-watch instance reached as ``localhost`` sees its IdP on a different
*site* (SameSite compares registrable domains, and ``localhost`` and
``127.0.0.1`` are distinct). That makes the IdP's redirect back to
``/auth/callback`` a real cross-site navigation in the browser.

``/authorize`` has two modes:

- ``silent``: answers with a 302 straight back to the callback, the way an IdP
  with a live session does. The navigation chain was started by the app's own
  page, so it is same-site at both ends with a cross-site hop in the middle.
- ``interactive``: renders a page with a "Continue" link, the way an IdP that
  asks for credentials does. The click on that page starts a navigation whose
  initiator is the IdP, so the callback request is cross-site outright.

ID tokens are RS256, signed with a key generated per server. Nothing here is a
credential: the client secret is generated at runtime and never checked beyond
equality.
"""

from __future__ import annotations

import contextlib
import html
import json
import secrets
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from joserfc import jwt
from joserfc.jwk import RSAKey


@dataclass
class MockOIDC:
    """State shared between the server thread and the test."""

    client_id: str
    mode: str = "silent"
    username: str = "oidc-user@idp.test"
    key: RSAKey = field(default_factory=lambda: RSAKey.generate_key(2048, {"kid": "k1"}))
    # code -> nonce captured at /authorize
    codes: dict[str, str] = field(default_factory=dict)
    issuer: str = ""

    def id_token(self, nonce: str) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": "oidc-user",
            "preferred_username": self.username,
            "email": self.username,
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        }
        return jwt.encode({"alg": "RS256", "kid": "k1"}, claims, self.key)


def _send(handler: BaseHTTPRequestHandler, status: int, body: bytes, ctype: str,
          headers: dict[str, str] | None = None) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    for k, v in (headers or {}).items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


def _json(handler: BaseHTTPRequestHandler, payload: dict[str, Any]) -> None:
    _send(handler, 200, json.dumps(payload).encode(), "application/json")


def _handler_for(idp: MockOIDC) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path == "/.well-known/openid-configuration":
                _json(self, {
                    "issuer": idp.issuer,
                    "authorization_endpoint": f"{idp.issuer}/authorize",
                    "token_endpoint": f"{idp.issuer}/token",
                    "jwks_uri": f"{idp.issuer}/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"],
                })
            elif url.path == "/jwks":
                _json(self, {"keys": [idp.key.as_dict(private=False)]})
            elif url.path == "/authorize":
                self._authorize(query)
            else:
                _send(self, 404, b"not found", "text/plain")

        def _authorize(self, query: dict[str, str]) -> None:
            if query.get("client_id") != idp.client_id or "redirect_uri" not in query:
                _send(self, 400, b"bad authorize request", "text/plain")
                return
            code = secrets.token_urlsafe(16)
            idp.codes[code] = query.get("nonce", "")
            back = f"{query['redirect_uri']}?{urlencode({'code': code, 'state': query['state']})}"
            if idp.mode == "silent":
                _send(self, 302, b"", "text/plain", {"Location": back})
                return
            page = (
                "<!doctype html><title>Mock IdP</title>"
                f'<a id="idp-continue" href="{html.escape(back)}">Continue</a>'
            )
            _send(self, 200, page.encode(), "text/html; charset=utf-8")

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/token":
                _send(self, 404, b"not found", "text/plain")
                return
            length = int(self.headers.get("Content-Length", 0))
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
            nonce = idp.codes.pop(form.get("code", ""), None)
            if nonce is None:
                _send(self, 400, b'{"error":"invalid_grant"}', "application/json")
                return
            _json(self, {
                "access_token": secrets.token_urlsafe(16),
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": idp.id_token(nonce),
            })

    return Handler


@contextlib.contextmanager
def mock_oidc_server(client_id: str, mode: str = "silent") -> Iterator[MockOIDC]:
    idp = MockOIDC(client_id=client_id, mode=mode)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(idp))
    idp.issuer = f"http://127.0.0.1:{srv.server_address[1]}"
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield idp
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=3)
