"""OAuth 2.0 / OIDC authentication provider (Entra, Google, etc.)."""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass

from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen

from .protocol import AuthProvider, AuthResult
from .session import _sign_state, _verify_state

logger = logging.getLogger("cert_watch.auth")

# Asymmetric signature algorithms only. The IdP's discovery document advertises
# its supported algs, but we never let that list widen ours: `none` (unsigned)
# and the HS* family (symmetric — vulnerable to the RS/HS key-confusion attack,
# since the verification "key" is the *public* JWKS key) must never be accepted
# for an ID token, no matter what a malicious or misconfigured IdP advertises.
_ALLOWED_JWT_ALGS = (
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
)


def _safe_algs(advertised: list[str]) -> list[str]:
    """Intersect IdP-advertised algs with our asymmetric allowlist.

    Falls back to ``["RS256"]`` if the IdP advertised nothing we accept, so a
    hostile ``["none"]`` can never reduce the verifier to accepting unsigned
    tokens.
    """
    filtered = [a for a in advertised if a in _ALLOWED_JWT_ALGS]
    return filtered or ["RS256"]


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
    # SSRF policy (must match the scanner's allowlist so private IdPs work)
    allow_private: bool = False
    allowed_subnets: tuple[str, ...] = ()
    jwks_cache_ttl: int = 86400


_JWKS_MAX_BYTES = 256 * 1024  # 256 KiB — a JWKS response should be a few KB


class OAuthProvider(AuthProvider):
    """OAuth 2.0 / OIDC authentication. Works with Entra ID, Google, etc.

    Security note (BC-071): full session binding of the authenticated identity
    relies on the IdP returning a signed ``id_token`` (OIDC-compliant). The
    ``id_token`` carries the audience/nonce binding that proves the credential
    was minted for *this* relying party and flow. The userinfo-endpoint
    fallback (used only when no ``id_token`` is present) checks for a ``nonce``
    claim in the userinfo response (OIDC Core §5.3.2) and verifies it against
    the nonce from the authorization request — restoring binding when the IdP
    cooperates. When the userinfo response omits the nonce, the path degrades
    to trusting the access token on the code exchange alone; this is logged at
    WARNING level. OIDC-compliant IdPs SHOULD return an ``id_token``.
    """

    def __init__(self, config: OAuthConfig) -> None:
        self.config = config
        self._discovered: dict[str, str] = {}
        self._jwks: dict | None = None
        self._jwks_fetched_at: float = 0.0
        self._jwks_ttl: int = config.jwks_cache_ttl
        self._allow_private = config.allow_private
        self._allowed_subnets = config.allowed_subnets
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
        well_known = self.config.issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        try:
            resp = ssrf_safe_urlopen(
                well_known,
                headers={"User-Agent": "cert-watch"},
                timeout=10,
                allow_private=self._allow_private,
                allowed_subnets=self._allowed_subnets,
            )
            data = json.loads(resp.read(_JWKS_MAX_BYTES))
            resp.close()
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
        try:
            resp = ssrf_safe_urlopen(
                jwks_uri,
                headers={"User-Agent": "cert-watch"},
                timeout=10,
                allow_private=self._allow_private,
                allowed_subnets=self._allowed_subnets,
            )
            self._jwks = json.loads(resp.read(_JWKS_MAX_BYTES))
            self._jwks_fetched_at = time.monotonic()
            resp.close()
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
        alg_values = _safe_algs(
            endpoints.get("id_token_signing_alg_values_supported", "RS256").split(",")
        )

        issuer = self.config.issuer_url.rstrip("/")

        try:
            if KeySet is not None:
                key_set = KeySet.import_key_set(jwks)
                token = _jwt.decode(id_token, key=key_set, algorithms=alg_values)
                raw_claims = token.claims
            else:
                from authlib.jose import JsonWebKey, JsonWebToken
                key_set = JsonWebKey.import_key_set(jwks)
                # authlib's module-level jwt.decode allows a broad default alg
                # set; pin it to our asymmetric allowlist instead.
                restricted = JsonWebToken(alg_values)
                data = restricted.decode(id_token, key=key_set)
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
            roles: list[str] = []
            groups: list[str] = []
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
                        # Entra emits app-role values in `roles` and security-group
                        # object IDs (GUIDs) in `groups`. Surface both so the authz
                        # gate (check_authz) can act on them (Plan 034 / bug 2b).
                        roles = [str(r) for r in (claims.get("roles") or [])]
                        groups = [str(g) for g in (claims.get("groups") or [])]
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
                    try:
                        userinfo_resp = ssrf_safe_urlopen(
                            userinfo_endpoint,
                            headers={
                                "Authorization": f"Bearer {token.get('access_token', '')}",
                                "User-Agent": "cert-watch",
                                "Accept": "application/json",
                            },
                            timeout=10,
                            allow_private=self._allow_private,
                            allowed_subnets=self._allowed_subnets,
                        )
                        with userinfo_resp:
                            if 200 <= userinfo_resp.status < 300:
                                info = json.loads(userinfo_resp.read())
                            else:
                                logger.warning(
                                    "OAuth userinfo endpoint returned %s",
                                    userinfo_resp.status,
                                )
                                info = {}
                    except SSRFBlockedError as exc:
                        logger.warning("OAuth userinfo endpoint blocked by SSRF policy: %s", exc)
                        return AuthResult(
                            success=False,
                            error="OAuth userinfo endpoint blocked by SSRF policy",
                        )
                    # BC-071: verify nonce claim if the userinfo response
                    # includes one (OIDC Core §5.3.2 — userinfo MAY include
                    # the nonce). This restores the audience/nonce binding
                    # that the id_token path provides. When the IdP omits
                    # the nonce, log a warning so operators know the path is
                    # degraded.
                    if nonce:
                        userinfo_nonce = info.get("nonce")
                        if userinfo_nonce and userinfo_nonce == nonce:
                            logger.info(
                                "OAuth: userinfo response includes verified nonce claim; "
                                "nonce binding intact."
                            )
                        elif userinfo_nonce:
                            logger.warning(
                                "OAuth: userinfo nonce claim mismatch "
                                "(expected %s, got %s); rejecting.",
                                nonce, userinfo_nonce,
                            )
                            return AuthResult(
                                success=False,
                                error="OAuth userinfo nonce mismatch",
                            )
                        else:
                            logger.warning(
                                "OAuth: no id_token and userinfo response lacks nonce "
                                "claim — access token trusted on code exchange alone "
                                "(BC-071). Configure an OIDC-compliant IdP that returns "
                                "an id_token for full session binding."
                            )
                    username = (
                        info.get("preferred_username")
                        or info.get("email")
                        or info.get("sub", "")
                    )
                    roles = [str(r) for r in (info.get("roles") or [])]
                    groups = [str(g) for g in (info.get("groups") or [])]
            if not username:
                return AuthResult(success=False, error="could not determine username from token")
            return AuthResult(success=True, username=username, roles=roles, groups=groups)
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
