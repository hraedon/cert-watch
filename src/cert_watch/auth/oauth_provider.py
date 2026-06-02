"""OAuth 2.0 / OIDC authentication provider (Entra, Google, etc.)."""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import dataclass

from .protocol import AuthProvider, AuthResult
from .session import _sign_state, _verify_state

logger = logging.getLogger("cert_watch.auth")


@dataclass
class OAuthConfig:
    client_id: str
    client_secret: str
    issuer_url: str  # e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
    scope: str = "openid profile email"
    # Pre-computed endpoints (auto-discovered if not set)
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""


class OAuthProvider(AuthProvider):
    """OAuth 2.0 / OIDC authentication. Works with Entra ID, Google, etc.

    Security note (BC-071): full session binding of the authenticated identity
    relies on the IdP returning a signed ``id_token`` (OIDC-compliant). The
    ``id_token`` carries the audience/nonce binding that proves the credential
    was minted for *this* relying party and flow. The userinfo-endpoint
    fallback (used only when no ``id_token`` is present) authenticates with the
    access token via bearer auth and therefore cannot, on its own, prove the
    token belongs to the current session. OIDC-compliant IdPs MUST return an
    ``id_token``; deployments that depend on the userinfo fallback run a weaker
    security path that is logged at WARNING level whenever it is taken.
    """

    def __init__(self, config: OAuthConfig) -> None:
        self.config = config
        self._discovered: dict[str, str] = {}
        self._jwks: dict | None = None
        self._jwks_fetched_at: float = 0.0
        self._jwks_ttl: int = int(os.environ.get("CERT_WATCH_JWKS_CACHE_TTL", "86400"))
        try:
            from authlib.integrations.requests_client import OAuth2Session  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "OAuth auth requires the 'authlib' package. "
                "Install it with: pip install cert-watch[auth-oauth]"
            ) from None

    def _discover(self) -> dict[str, str]:
        """OIDC discovery — fetches endpoints from issuer's .well-known URL."""
        if self._discovered:
            return self._discovered
        if self.config.authorization_endpoint and self.config.token_endpoint:
            self._discovered = {
                "authorization_endpoint": self.config.authorization_endpoint,
                "token_endpoint": self.config.token_endpoint,
                "userinfo_endpoint": self.config.userinfo_endpoint,
                "jwks_uri": self.config.jwks_uri,
                "id_token_signing_alg_values_supported": "RS256",
            }
            return self._discovered
        import urllib.request

        well_known = self.config.issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        try:
            req = urllib.request.Request(well_known, headers={"User-Agent": "cert-watch"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            self._discovered = {
                "authorization_endpoint": data["authorization_endpoint"],
                "token_endpoint": data["token_endpoint"],
                "userinfo_endpoint": data.get("userinfo_endpoint", ""),
                "jwks_uri": data.get("jwks_uri", self.config.jwks_uri),
                "id_token_signing_alg_values_supported": ",".join(
                    data.get("id_token_signing_alg_values_supported", ["RS256"])
                ),
            }
        except Exception as exc:
            logger.warning("OIDC discovery failed: %s", exc)
            self._discovered = {
                "authorization_endpoint": self.config.authorization_endpoint,
                "token_endpoint": self.config.token_endpoint,
                "userinfo_endpoint": self.config.userinfo_endpoint,
                "jwks_uri": self.config.jwks_uri,
                "id_token_signing_alg_values_supported": "RS256",
            }
        return self._discovered

    def _fetch_jwks(self, *, force: bool = False) -> dict | None:
        """Fetch and cache JWKS from the IdP's jwks_uri."""
        if (
            self._jwks is not None
            and not force
            and (time.monotonic() - self._jwks_fetched_at) < self._jwks_ttl
        ):
            return self._jwks
        endpoints = self._discover()
        jwks_uri = endpoints.get("jwks_uri", "")
        if not jwks_uri:
            return None
        import urllib.request

        try:
            req = urllib.request.Request(jwks_uri, headers={"User-Agent": "cert-watch"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                self._jwks = json.loads(resp.read())
                self._jwks_fetched_at = time.monotonic()
        except Exception as exc:
            logger.warning("JWKS fetch failed: %s", exc)
            return None
        return self._jwks

    def _verify_id_token(
        self,
        id_token: str,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> dict | None:
        """Verify an OIDC ID token using JWKS. Returns validated claims or None."""
        try:
            from joserfc import jwt as _jwt
            from joserfc.jwk import KeySet
        except ImportError:
            try:
                from authlib.jose import jwt as _jwt
                KeySet = None
            except ImportError:
                logger.warning("Neither joserfc nor authlib.jose available for JWT verification")
                return None

        jwks = self._fetch_jwks()
        if jwks is None:
            logger.warning("JWKS unavailable — cannot verify ID token signature")
            return None

        endpoints = self._discover()
        alg_values = endpoints.get(
            "id_token_signing_alg_values_supported", "RS256"
        ).split(",")

        issuer = self.config.issuer_url.rstrip("/")

        try:
            if KeySet is not None:
                key_set = KeySet.import_key_set(jwks)
                token = _jwt.decode(id_token, key=key_set, algorithms=alg_values)
                raw_claims = token.claims
            else:
                from authlib.jose import JsonWebKey
                key_set = JsonWebKey.import_key_set(jwks)
                data = _jwt.decode(id_token, key=key_set)
                raw_claims = data

            claims_options = {
                "iss": {"essential": True, "value": issuer},
                "aud": {"essential": True, "value": self.config.client_id},
            }
            claims_params: dict = {"client_id": self.config.client_id}
            if nonce:
                claims_params["nonce"] = nonce

            try:
                from authlib.oidc.core import CodeIDToken

                oidt = CodeIDToken(raw_claims, {}, claims_options, claims_params)
                if access_token:
                    oidt.params["access_token"] = access_token
                oidt.validate(leeway=120)
            except ImportError:
                _validate_claims_manual(raw_claims, issuer, self.config.client_id, nonce)

            return dict(raw_claims)
        except Exception as exc:
            if KeySet is not None:
                try:
                    from joserfc.errors import InvalidKeyIdError
                    if isinstance(exc, InvalidKeyIdError):
                        fresh_jwks = self._fetch_jwks(force=True)
                        if fresh_jwks:
                            key_set = KeySet.import_key_set(fresh_jwks)
                            token = _jwt.decode(id_token, key=key_set, algorithms=alg_values)
                            raw_claims = token.claims
                            claims_options = {
                                "iss": {"essential": True, "value": issuer},
                                "aud": {"essential": True, "value": self.config.client_id},
                            }
                            claims_params = {"client_id": self.config.client_id}
                            if nonce:
                                claims_params["nonce"] = nonce
                            try:
                                from authlib.oidc.core import CodeIDToken
                                oidt = CodeIDToken(raw_claims, {}, claims_options, claims_params)
                                if access_token:
                                    oidt.params["access_token"] = access_token
                                oidt.validate(leeway=120)
                            except ImportError:
                                _validate_claims_manual(
                                    raw_claims, issuer,
                                    self.config.client_id, nonce,
                                )
                            return dict(raw_claims)
                except Exception:
                    pass
            logger.warning("ID token verification failed: %s", exc)
            return None

    def authenticate(self, username: str, password: str) -> AuthResult:
        return AuthResult(
            success=False,
            error="Use OAuth login for this provider",
            redirect_url="/auth/login",
        )

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        try:
            from authlib.integrations.requests_client import OAuth2Session
        except ImportError:
            return AuthResult(success=False, error="authlib not installed")
        endpoints = self._discover()
        client = OAuth2Session(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            scope=self.config.scope,
        )
        authorization_endpoint = endpoints.get("authorization_endpoint", "")
        if not authorization_endpoint:
            return AuthResult(success=False, error="authorization_endpoint not configured")
        nonce = secrets.token_urlsafe(16)
        uri, state = client.create_authorization_url(
            authorization_endpoint, redirect_uri=redirect_uri,
            nonce=nonce,
        )
        return AuthResult(
            success=True, redirect_url=uri,
            oauth_state=_sign_state(state, nonce=nonce),
        )

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        try:
            from authlib.integrations.requests_client import OAuth2Session
        except ImportError:
            return AuthResult(success=False, error="authlib not installed")
        # BC-009: verify state parameter before exchanging code
        if not state:
            return AuthResult(success=False, error="missing OAuth state parameter")
        verify_result = _verify_state(state)
        if verify_result is None:
            return AuthResult(success=False, error="invalid OAuth state")
        expected_state, nonce = verify_result
        endpoints = self._discover()
        token_endpoint = endpoints.get("token_endpoint", "")
        if not token_endpoint:
            return AuthResult(success=False, error="token_endpoint not configured")
        try:
            client = OAuth2Session(
                client_id=self.config.client_id,
                client_secret=self.config.client_secret,
            )
            token = client.fetch_token(
                token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
            )
            username = ""
            id_token_str = token.get("id_token")
            if id_token_str:
                try:
                    claims = self._verify_id_token(
                        id_token_str,
                        access_token=token.get("access_token"),
                        nonce=nonce,
                    )
                    if claims:
                        username = (
                            claims.get("preferred_username")
                            or claims.get("email")
                            or claims.get("sub", "")
                        )
                    else:
                        return AuthResult(
                            success=False,
                            error="ID token verification failed; refusing userinfo fallback",
                        )
                except Exception as exc:
                    logger.warning("ID token verification error: %s", exc)
                    return AuthResult(
                        success=False,
                        error="ID token verification failed",
                    )
            if not username:
                userinfo_endpoint = endpoints.get("userinfo_endpoint", "")
                if userinfo_endpoint:
                    # BC-071: weaker security path. We only reach here when the
                    # IdP returned no id_token, so we have no signed audience/
                    # nonce binding proving the access token belongs to *this*
                    # login flow — only that the code exchange succeeded. There
                    # is no nonce available in this flow to verify against (the
                    # nonce would have to be persisted across the redirect, which
                    # requires route-layer changes). Surface the degraded path so
                    # operators notice. OIDC-compliant IdPs return an id_token and
                    # take the verified path above.
                    logger.warning(
                        "OAuth: no id_token returned by IdP — falling back to the "
                        "userinfo endpoint. This path has no nonce/audience binding "
                        "(BC-071); the access token is trusted on the strength of the "
                        "code exchange alone. Configure an OIDC-compliant IdP that "
                        "returns an id_token for full session binding."
                    )
                    resp = client.get(userinfo_endpoint)
                    if resp.status_code == 200:
                        info = resp.json()
                        username = (
                            info.get("preferred_username")
                            or info.get("email")
                            or info.get("sub", "")
                        )
            if not username:
                return AuthResult(success=False, error="could not determine username from token")
            return AuthResult(success=True, username=username)
        except Exception as exc:
            logger.warning("OAuth token exchange failed: %s", exc)
            return AuthResult(success=False, error="OAuth authentication failed")

    @property
    def provider_name(self) -> str:
        return "oauth"

    @property
    def supports_form_login(self) -> bool:
        return False


def _validate_claims_manual(
    claims: dict, expected_issuer: str, expected_audience: str, nonce: str | None,
) -> None:
    """Manual OIDC claim validation for environments without authlib.oidc.core."""
    import time

    iss = claims.get("iss", "").rstrip("/")
    if iss != expected_issuer:
        raise ValueError(f"issuer mismatch: {iss} != {expected_issuer}")
    aud = claims.get("aud", "")
    aud_list = aud if isinstance(aud, list) else [aud]
    if expected_audience not in aud_list:
        raise ValueError(f"audience mismatch: {aud} does not contain {expected_audience}")
    exp = claims.get("exp")
    if exp and exp < time.time() - 120:
        raise ValueError("ID token has expired")
    if nonce and claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
