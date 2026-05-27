"""Authentication providers: LDAP/AD and OAuth/OIDC (Entra).

When AUTH_PROVIDER is unset, NoAuthProvider allows all requests (backward compat).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger("cert_watch.auth")

# Session cookie config
SESSION_COOKIE = "cw_auth"
SESSION_TTL = 8 * 3600  # 8 hours, matches CSRF token TTL
_signing_key = os.environ.get("CERT_WATCH_AUTH_SECRET") or secrets.token_hex(32)
if not os.environ.get("CERT_WATCH_AUTH_SECRET"):
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


class AuthProvider(ABC):
    @abstractmethod
    def authenticate(self, username: str, password: str) -> AuthResult:
        """Authenticate with username/password (LDAP form login)."""

    @abstractmethod
    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        """Begin OAuth flow; returns redirect URL in AuthResult."""

    @abstractmethod
    def complete_oauth_flow(self, code: str, redirect_uri: str) -> AuthResult:
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

    def complete_oauth_flow(self, code: str, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="OAuth not configured")

    @property
    def provider_name(self) -> str:
        return "none"

    @property
    def supports_form_login(self) -> bool:
        return False


# ---------- LDAP provider ----------


class LDAPAuthProvider(AuthProvider):
    """LDAP/AD authentication via ldap3."""

    def __init__(
        self,
        server_url: str,
        base_dn: str,
        bind_dn: str = "",
        bind_password: str = "",
        user_search_filter: str = "(sAMAccountName={username})",
        start_tls: bool = False,
    ) -> None:
        self.server_url = server_url
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.user_search_filter = user_search_filter
        self.start_tls = start_tls
        # Validate ldap3 is available at init time
        try:
            import ldap3  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "LDAP auth requires the 'ldap3' package. "
                "Install it with: pip install cert-watch[auth-ldap]"
            ) from None

    def authenticate(self, username: str, password: str) -> AuthResult:
        if not username or not password:
            return AuthResult(success=False, error="username and password required")
        try:
            import ldap3
        except ImportError:
            return AuthResult(success=False, error="ldap3 not installed")

        try:
            server = ldap3.Server(self.server_url, get_info=ldap3.NONE)
            # Step 1: bind with service account to search for user DN
            conn = ldap3.Connection(
                server,
                user=self.bind_dn or None,
                password=self.bind_password or None,
                auto_bind=False,
            )
            if self.start_tls:
                conn.start_tls()
            else:
                conn.bind()
            search_filter = self.user_search_filter.replace(
                "{username}", ldap3.utils.conv.escape_filter_chars(username)
            )
            conn.search(
                self.base_dn,
                search_filter,
                attributes=["distinguishedName", "cn", "mail"],
            )
            if not conn.entries:
                conn.unbind()
                return AuthResult(success=False, error="user not found")
            user_dn = str(conn.entries[0].distinguishedName)
            conn.unbind()

            # Step 2: rebind as the user to verify password
            user_conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
            return AuthResult(success=True, username=username)
        except ldap3.core.exceptions.LDAPBindError:
            return AuthResult(success=False, error="invalid credentials")
        except Exception as exc:
            logger.warning("LDAP auth error: %s", exc)
            return AuthResult(success=False, error="authentication failed")

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="OAuth not available with LDAP provider")

    def complete_oauth_flow(self, code: str, redirect_uri: str) -> AuthResult:
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


class OAuthProvider(AuthProvider):
    """OAuth 2.0 / OIDC authentication. Works with Entra ID, Google, etc."""

    def __init__(self, config: OAuthConfig) -> None:
        self.config = config
        self._discovered: dict[str, str] = {}
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
            }
        except Exception as exc:
            logger.warning("OIDC discovery failed: %s", exc)
            # Fall back to explicit config
            self._discovered = {
                "authorization_endpoint": self.config.authorization_endpoint,
                "token_endpoint": self.config.token_endpoint,
                "userinfo_endpoint": self.config.userinfo_endpoint,
            }
        return self._discovered

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
        return AuthResult(success=True, redirect_url=uri, error=_sign_state(state))

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
            # Try to get username from ID token claims or userinfo
            username = ""
            id_token = token.get("id_token")
            if id_token:
                try:
                    # Decode without verification for claims (authlib handles verification)
                    import base64

                    parts = id_token.split(".")
                    if len(parts) >= 2:
                        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                        # BC-015/014: verify iss and aud claims
                        expected_iss = self.config.issuer_url.rstrip("/")
                        actual_iss = claims.get("iss", "").rstrip("/")
                        if actual_iss and expected_iss and actual_iss != expected_iss:
                            return AuthResult(success=False, error="ID token issuer mismatch")
                        aud = claims.get("aud", "")
                        if isinstance(aud, list):
                            aud = aud[0] if aud else ""
                        if aud and aud != self.config.client_id:
                            return AuthResult(success=False, error="ID token audience mismatch")
                        username = (
                            claims.get("preferred_username")
                            or claims.get("email")
                            or claims.get("sub", "")
                        )
                except Exception:
                    pass
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
    # OAuth options
    oauth_client_id: str = "",
    oauth_client_secret: str = "",
    oauth_issuer_url: str = "",
    oauth_scope: str = "openid profile email",
    oauth_authorization_endpoint: str = "",
    oauth_token_endpoint: str = "",
    oauth_userinfo_endpoint: str = "",
) -> AuthProvider:
    """Build an auth provider from config values. Returns NoAuthProvider if provider is empty."""
    provider = provider.lower().strip()
    if not provider or provider == "none":
        return NoAuthProvider()
    if provider == "ldap":
        if not ldap_server or not ldap_base_dn:
            logger.warning("LDAP auth misconfigured: LDAP_SERVER and LDAP_BASE_DN required")
            return NoAuthProvider()
        return LDAPAuthProvider(
            server_url=ldap_server,
            base_dn=ldap_base_dn,
            bind_dn=ldap_bind_dn,
            bind_password=ldap_bind_password,
            user_search_filter=ldap_user_filter,
            start_tls=ldap_start_tls,
        )
    if provider in ("oauth", "entra", "azure", "oidc"):
        if not oauth_client_id or not oauth_issuer_url:
            logger.warning("OAuth misconfigured: OAUTH_CLIENT_ID and OAUTH_ISSUER_URL required")
            return NoAuthProvider()
        return OAuthProvider(
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
    logger.warning("Unknown AUTH_PROVIDER=%r, falling back to no auth", provider)
    return NoAuthProvider()
