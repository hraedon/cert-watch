"""Authentication providers: LDAP/AD, OAuth/OIDC (Entra), and local break-glass.

When AUTH_PROVIDER is unset, NoAuthProvider allows all requests (backward compat).
Local break-glass admin is activated by setting CERT_WATCH_LOCAL_ADMIN_USER and
CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH — it evaluates before the primary provider
and works regardless of external provider availability.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from cert_watch.config import read_secret

logger = logging.getLogger("cert_watch.auth")

# Session cookie config
SESSION_COOKIE = "cw_auth"
SESSION_TTL = 8 * 3600  # 8 hours, matches CSRF token TTL
_signing_key = read_secret("CERT_WATCH_AUTH_SECRET") or None
if not _signing_key:
    _signing_key = secrets.token_hex(32)
    logger.warning(
        "CERT_WATCH_AUTH_SECRET is not set; using an ephemeral random value. "
        "Sessions will be invalidated on every restart. Set CERT_WATCH_AUTH_SECRET in production."
    )


def _sign_state(state: str) -> str:
    sig = hmac.new(_signing_key.encode(), state.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{state}:{sig}"


def _verify_state(token: str) -> str | None:
    if not token or ":" not in token:
        return None
    last_colon = token.rfind(":")
    state = token[:last_colon]
    sig = token[last_colon + 1 :]
    expected = hmac.new(_signing_key.encode(), state.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None
    return state


# ---------- Session helpers ----------


def _sign_session(data: str) -> str:
    sig = hmac.new(_signing_key.encode(), data.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{data}:{sig}"


def create_session(username: str) -> str:
    """Create a signed session token for the given username."""
    payload = f"{username}:{int(time.time())}:{secrets.token_hex(8)}"
    return _sign_session(payload)


def validate_session(token: str) -> str | None:
    """Validate a session token and return the username, or None if invalid."""
    if not token or ":" not in token:
        return None
    # Split last ':' to get the signature
    last_colon = token.rfind(":")
    if last_colon < 0:
        return None
    payload = token[:last_colon]
    sig = token[last_colon + 1 :]
    expected = hmac.new(_signing_key.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None
    parts = payload.split(":")
    if len(parts) < 2:
        return None
    username = parts[0]
    try:
        ts = int(parts[1])
    except ValueError:
        return None
    if (time.time() - ts) > SESSION_TTL:
        return None
    return username


# ---------- Auth provider protocol ----------


@dataclass
class AuthResult:
    success: bool
    username: str = ""
    error: str = ""
    redirect_url: str = ""  # For OAuth: URL to redirect user to
    oauth_state: str = ""  # Signed OAuth state for callback verification (BC-045)
    groups: list[str] | None = None
    roles: list[str] | None = None


class AuthProvider(ABC):
    @abstractmethod
    def authenticate(self, username: str, password: str) -> AuthResult:
        """Authenticate with username/password (LDAP form login)."""

    @abstractmethod
    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        """Begin OAuth flow; returns redirect URL in AuthResult."""

    @abstractmethod
    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        """Complete OAuth flow with authorization code; returns username."""

    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @property
    @abstractmethod
    def supports_form_login(self) -> bool:
        """Whether this provider supports username/password form login."""


# ---------- No-auth provider ----------


class NoAuthProvider(AuthProvider):
    """Default: no authentication required. All requests pass through."""

    def authenticate(self, username: str, password: str) -> AuthResult:
        return AuthResult(success=True, username=username or "anonymous")

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="OAuth not configured")

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return AuthResult(success=False, error="OAuth not configured")

    @property
    def provider_name(self) -> str:
        return "none"

    @property
    def supports_form_login(self) -> bool:
        return False


# ---------- LDAP provider ----------


class LDAPAuthProvider(AuthProvider):
    """LDAP/AD authentication via ldap3.

    Supports:
    - Private-CA TLS: validate server cert against LDAP_CA_CERT / LDAP_CA_CERT_FILE
    - DC failover: comma-separated LDAP_SERVER list → ServerPool with FIRST strategy
    - Transitive group filter: LDAP_REQUIRED_GROUPS enforces membership via
      LDAP_MATCHING_RULE_IN_CHAIN (OID 1.2.840.113556.1.4.1941)
    """

    def __init__(
        self,
        server_url: str,
        base_dn: str,
        bind_dn: str = "",
        bind_password: str = "",
        user_search_filter: str = "(sAMAccountName={username})",
        start_tls: bool = False,
        ca_cert: str = "",
        required_groups: list[str] | None = None,
        connect_timeout: int = 5,
    ) -> None:
        self.server_url = server_url
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.user_search_filter = user_search_filter
        self.start_tls = start_tls
        self.ca_cert = ca_cert
        self.required_groups = required_groups or []
        self.connect_timeout = connect_timeout
        try:
            import ldap3  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "LDAP auth requires the 'ldap3' package. "
                "Install it with: pip install cert-watch[auth-ldap]"
            ) from None

    def _build_tls(self) -> tuple:
        """Build ldap3.Tls and server list from config.

        Returns (tls_obj, servers) where servers is a list of ldap3.Server.
        For ldaps:// with ca_cert configured, sets CERT_REQUIRED (fail-closed).
        For start_tls, TLS is negotiated after connect.
        For plain ldap://, returns (None, servers).
        """
        import ssl

        import ldap3

        server_urls = [s.strip() for s in self.server_url.split(",") if s.strip()]
        tls = None
        is_ldaps = any(s.lower().startswith("ldaps://") for s in server_urls)

        if is_ldaps or self.start_tls:
            tls_kwargs: dict = {}
            if self.ca_cert:
                tls_kwargs["validate"] = ssl.CERT_REQUIRED
                ca_path = self._resolve_ca_cert()
                if ca_path and ca_path.exists():
                    tls_kwargs["ca_certs_file"] = str(ca_path)
                else:
                    tls_kwargs["ca_certs_data"] = self.ca_cert
            else:
                tls_kwargs["validate"] = ssl.CERT_REQUIRED if is_ldaps else ssl.CERT_NONE

            if is_ldaps and not self.ca_cert:
                logger.warning(
                    "LDAPS without LDAP_CA_CERT — validating against system trust "
                    "store only; private-CA servers will fail. "
                    "Set LDAP_CA_CERT or LDAP_CA_CERT_FILE to pin your CA."
                )

            tls = ldap3.Tls(**tls_kwargs)

        servers = [
            ldap3.Server(url, get_info=ldap3.NONE, tls=tls, connect_timeout=self.connect_timeout)
            for url in server_urls
        ]
        return tls, servers

    def _resolve_ca_cert(self) -> Path | None:
        """If ca_cert looks like a file path that exists, return it; else None."""
        p = Path(self.ca_cert)
        if p.is_file():
            return p
        return None

    def authenticate(self, username: str, password: str) -> AuthResult:
        if not username or not password:
            return AuthResult(success=False, error="username and password required")
        try:
            import ldap3
        except ImportError:
            return AuthResult(success=False, error="ldap3 not installed")

        try:
            tls, servers = self._build_tls()

            pool_or_single: ldap3.ServerPool | ldap3.Server
            if len(servers) > 1:
                pool_or_single = ldap3.ServerPool(
                    servers, pool_strategy=ldap3.FIRST, active=True,
                )
            else:
                pool_or_single = servers[0]

            use_ssl = any(getattr(s, 'ssl', False) for s in servers)
            conn = ldap3.Connection(
                pool_or_single,
                user=self.bind_dn or None,
                password=self.bind_password or None,
                auto_bind=False,
                use_ssl=use_ssl,
            )
            if self.start_tls and tls:
                conn.start_tls()
            else:
                conn.bind()

            search_filter = self.user_search_filter.replace(
                "{username}", ldap3.utils.conv.escape_filter_chars(username)
            )

            if self.required_groups:
                group_filters = " ".join(
                    f"(memberOf:1.2.840.113556.1.4.1941:={ldap3.utils.conv.escape_filter_chars(g)})"
                    for g in self.required_groups
                )
                search_filter = f"(&{search_filter}(|{group_filters}))"

            conn.search(
                self.base_dn,
                search_filter,
                attributes=["distinguishedName", "cn", "mail", "memberOf"],
            )
            if not conn.entries:
                conn.unbind()
                if self.required_groups:
                    return AuthResult(
                        success=False,
                        error="user not found or not in required group(s)",
                    )
                return AuthResult(success=False, error="user not found")

            user_dn = str(conn.entries[0].distinguishedName)
            user_groups = (
                list(conn.entries[0].memberOf.values)
                if hasattr(conn.entries[0], "memberOf")
                else []
            )
            conn.unbind()

            user_conn = ldap3.Connection(
                pool_or_single, user=user_dn, password=password,
                auto_bind=True, use_ssl=use_ssl,
            )
            user_conn.unbind()

            return AuthResult(
                success=True,
                username=username,
                groups=user_groups,
            )
        except ldap3.core.exceptions.LDAPBindError:
            return AuthResult(success=False, error="invalid credentials")
        except Exception as exc:
            logger.warning("LDAP auth error: %s", exc)
            return AuthResult(success=False, error="authentication failed")

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="OAuth not available with LDAP provider")

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return AuthResult(success=False, error="OAuth not available with LDAP provider")

    @property
    def provider_name(self) -> str:
        return "ldap"

    @property
    def supports_form_login(self) -> bool:
        return True


# ---------- OAuth/OIDC provider (Entra, Google, etc.) ----------


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
    """OAuth 2.0 / OIDC authentication. Works with Entra ID, Google, etc."""

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
        uri, state = client.create_authorization_url(
            authorization_endpoint, redirect_uri=redirect_uri
        )
        return AuthResult(success=True, redirect_url=uri, oauth_state=_sign_state(state))

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        try:
            from authlib.integrations.requests_client import OAuth2Session
        except ImportError:
            return AuthResult(success=False, error="authlib not installed")
        # BC-009: verify state parameter before exchanging code
        if state:
            expected_state = _verify_state(state)
            if expected_state is None:
                return AuthResult(success=False, error="invalid OAuth state")
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
                    return AuthResult(
                        success=False,
                        error=f"ID token verification error: {exc}",
                    )
            if not username:
                userinfo_endpoint = endpoints.get("userinfo_endpoint", "")
                if userinfo_endpoint:
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
            return AuthResult(success=False, error=f"OAuth authentication failed: {exc}")

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


# ---------- Authorization gate ----------


def check_authz(
    result: AuthResult,
    allowed_groups: list[str],
    allowed_roles: list[str],
) -> AuthResult:
    """Enforce group/role authorization gate.

    If ``allowed_groups`` and ``allowed_roles`` are both empty, any
    authenticated user is accepted (backward compat).

    Otherwise the user must belong to ≥1 allowed group OR hold ≥1 allowed role.
    On denial, returns a failed AuthResult with a descriptive error.
    """
    if not allowed_groups and not allowed_roles:
        return result
    user_groups = result.groups or []
    user_roles = result.roles or []
    group_match = any(g in allowed_groups for g in user_groups)
    role_match = any(r in allowed_roles for r in user_roles)
    if group_match or role_match:
        return result
    return AuthResult(
        success=False,
        username=result.username,
        error="access denied: user not in an allowed group or role",
    )


# ---------- Local break-glass admin ----------


def _scrypt_hash(
    password: str, *, n: int = 2**14, r: int = 8, p: int = 1, salt: bytes | None = None,
) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_scrypt_hash(password: str, stored_hash: str) -> bool:
    if not stored_hash or not stored_hash.startswith("scrypt$"):
        return False
    parts = stored_hash.split("$")
    if len(parts) != 6:
        return False
    try:
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt = base64.b64decode(parts[4])
        expected_dk = base64.b64decode(parts[5])
    except (ValueError, Exception):
        return False
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return hmac.compare_digest(dk, expected_dk)


class LocalAdminProvider(AuthProvider):
    def __init__(self, username: str, password_hash: str) -> None:
        self.username = username
        self.password_hash = password_hash

    def authenticate(self, username: str, password: str) -> AuthResult:
        if not username or not password:
            return AuthResult(success=False, error="username and password required")
        if username != self.username:
            return AuthResult(success=False, error="invalid credentials")
        if not verify_scrypt_hash(password, self.password_hash):
            return AuthResult(success=False, error="invalid credentials")
        logger.warning("BREAK-GLASS LOGIN: local admin '%s' authenticated", username)
        return AuthResult(
            success=True,
            username=username,
            groups=["admins"],
            roles=["admin"],
        )

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="Use form login for local admin")

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return AuthResult(success=False, error="Use form login for local admin")

    @property
    def provider_name(self) -> str:
        return "local-admin"

    @property
    def supports_form_login(self) -> bool:
        return True


# ---------- Composite provider (local admin + primary) ----------


class _CompositeProvider(AuthProvider):
    def __init__(self, local: LocalAdminProvider, primary: AuthProvider) -> None:
        self._local = local
        self._primary = primary

    def authenticate(self, username: str, password: str) -> AuthResult:
        result = self._local.authenticate(username, password)
        if result.success:
            return result
        return self._primary.authenticate(username, password)

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return self._primary.start_oauth_flow(redirect_uri)

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return self._primary.complete_oauth_flow(code, redirect_uri, state)

    @property
    def provider_name(self) -> str:
        return self._primary.provider_name

    @property
    def supports_form_login(self) -> bool:
        return True


# ---------- Factory ----------


def build_auth_provider(
    provider: str = "",
    *,
    # LDAP options
    ldap_server: str = "",
    ldap_base_dn: str = "",
    ldap_bind_dn: str = "",
    ldap_bind_password: str = "",
    ldap_user_filter: str = "(sAMAccountName={username})",
    ldap_start_tls: bool = False,
    ldap_ca_cert: str = "",
    ldap_required_groups: list[str] | None = None,
    ldap_connect_timeout: int = 5,
    # OAuth options
    oauth_client_id: str = "",
    oauth_client_secret: str = "",
    oauth_issuer_url: str = "",
    oauth_scope: str = "openid profile email",
    oauth_authorization_endpoint: str = "",
    oauth_token_endpoint: str = "",
    oauth_userinfo_endpoint: str = "",
    # Authorization options
    allowed_groups: list[str] | None = None,
    allowed_roles: list[str] | None = None,
    # Local break-glass admin
    local_admin_user: str = "",
    local_admin_password_hash: str = "",
) -> AuthProvider:
    """Build an auth provider from config values. Returns NoAuthProvider if provider is empty."""
    provider = provider.lower().strip()

    local_admin: LocalAdminProvider | None = None
    if local_admin_user and local_admin_password_hash:
        local_admin = LocalAdminProvider(local_admin_user, local_admin_password_hash)

    primary: AuthProvider
    if not provider or provider == "none":
        if local_admin:
            return LocalAdminProvider(local_admin_user, local_admin_password_hash)
        return NoAuthProvider()
    if provider == "ldap":
        if not ldap_server or not ldap_base_dn:
            logger.warning("LDAP auth misconfigured: LDAP_SERVER and LDAP_BASE_DN required")
            if local_admin:
                return local_admin
            return NoAuthProvider()
        primary = LDAPAuthProvider(
            server_url=ldap_server,
            base_dn=ldap_base_dn,
            bind_dn=ldap_bind_dn,
            bind_password=ldap_bind_password,
            user_search_filter=ldap_user_filter,
            start_tls=ldap_start_tls,
            ca_cert=ldap_ca_cert,
            required_groups=ldap_required_groups,
            connect_timeout=ldap_connect_timeout,
        )
        if local_admin:
            return _CompositeProvider(local_admin, primary)
        return primary
    if provider in ("oauth", "entra", "azure", "oidc"):
        if not oauth_client_id or not oauth_issuer_url:
            logger.warning("OAuth misconfigured: OAUTH_CLIENT_ID and OAUTH_ISSUER_URL required")
            if local_admin:
                return local_admin
            return NoAuthProvider()
        primary = OAuthProvider(
            OAuthConfig(
                client_id=oauth_client_id,
                client_secret=oauth_client_secret,
                issuer_url=oauth_issuer_url,
                scope=oauth_scope,
                authorization_endpoint=oauth_authorization_endpoint,
                token_endpoint=oauth_token_endpoint,
                userinfo_endpoint=oauth_userinfo_endpoint,
            )
        )
        if local_admin:
            return _CompositeProvider(local_admin, primary)
        return primary
    logger.warning("Unknown AUTH_PROVIDER=%r, falling back to no auth", provider)
    if local_admin:
        return local_admin
    return NoAuthProvider()
