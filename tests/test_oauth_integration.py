"""Integration tests for OAuth provider OIDC discovery and JWKS fetching.

These tests use a local HTTP server as the identity provider and exercise the
SSRF-guarded HTTP paths inside ``OAuthProvider``.
"""

from __future__ import annotations

import json
import socket
from http.server import BaseHTTPRequestHandler

from cert_watch.auth.oauth_provider import OAuthConfig, OAuthProvider
from tests._integration_servers import allow_loopback_transport, http_server


def _json_response(handler: BaseHTTPRequestHandler, payload: dict) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _oauth_router():
    def _route(handler: BaseHTTPRequestHandler) -> None:
        # The SSRF opener sends the original hostname in the Host header.
        base = f"http://{handler.headers.get('Host')}"
        if handler.path == "/.well-known/openid-configuration":
            _json_response(handler, {
                "authorization_endpoint": f"{base}/auth",
                "token_endpoint": f"{base}/token",
                "userinfo_endpoint": f"{base}/userinfo",
                "jwks_uri": f"{base}/jwks",
                "id_token_signing_alg_values_supported": ["RS256"],
            })
            return
        if handler.path == "/jwks":
            _json_response(handler, {
                "keys": [
                    {"kty": "RSA", "kid": "test-key-1", "use": "sig"},
                ],
            })
            return
        handler.send_response(404)
        handler.end_headers()

    return _route


def _fake_getaddrinfo_factory(real_getaddrinfo, ip: str, port: int):
    def _fake(host, *args, **kwargs):
        if host == "idp.local":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port))]
        return real_getaddrinfo(host, *args, **kwargs)

    return _fake


def test_oauth_discover_local_idp_with_transport_override(monkeypatch):
    """OIDC discovery can fetch a local .well-known doc with transport override."""
    real_getaddrinfo = socket.getaddrinfo

    with allow_loopback_transport(monkeypatch), http_server(_oauth_router()) as srv:
        _host, port = srv.server_address
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            _fake_getaddrinfo_factory(real_getaddrinfo, "127.0.0.1", port),
        )

        config = OAuthConfig(
            client_id="client",
            client_secret="secret",
            issuer_url=f"http://idp.local:{port}",
            allow_private=True,
        )
        provider = OAuthProvider(config)
        endpoints = provider._discover()

        assert endpoints["authorization_endpoint"] == f"http://idp.local:{port}/auth"
        assert endpoints["token_endpoint"] == f"http://idp.local:{port}/token"
        assert endpoints["jwks_uri"] == f"http://idp.local:{port}/jwks"


def test_oauth_discover_fallback_when_loopback_blocked(monkeypatch):
    """OIDC discovery falls back to configured endpoints when loopback is blocked."""
    real_getaddrinfo = socket.getaddrinfo

    with http_server(_oauth_router()) as srv:
        _host, port = srv.server_address
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            _fake_getaddrinfo_factory(real_getaddrinfo, "127.0.0.1", port),
        )

        config = OAuthConfig(
            client_id="client",
            client_secret="secret",
            issuer_url=f"http://idp.local:{port}",
            authorization_endpoint="http://configured/auth",
            token_endpoint="http://configured/token",
            allow_private=True,
        )
        provider = OAuthProvider(config)
        endpoints = provider._discover()

        # Discovery failed because of SSRF block (loopback always blocked),
        # so configured endpoints remain.
        assert endpoints["authorization_endpoint"] == "http://configured/auth"
        assert endpoints["token_endpoint"] == "http://configured/token"


def test_oauth_fetch_jwks_local_idp_with_transport_override(monkeypatch):
    """JWKS can be fetched from a local IdP with transport override."""
    real_getaddrinfo = socket.getaddrinfo

    with allow_loopback_transport(monkeypatch), http_server(_oauth_router()) as srv:
        _host, port = srv.server_address
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            _fake_getaddrinfo_factory(real_getaddrinfo, "127.0.0.1", port),
        )

        issuer = f"http://idp.local:{port}"
        config = OAuthConfig(
            client_id="client",
            client_secret="secret",
            issuer_url=issuer,
            allow_private=True,
        )
        provider = OAuthProvider(config)
        jwks = provider._fetch_jwks()

        assert jwks is not None
        assert "keys" in jwks
        assert jwks["keys"][0]["kid"] == "test-key-1"
