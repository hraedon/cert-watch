"""Auth provider factory and the authorization gate."""

from __future__ import annotations

import logging

from .ldap_provider import LDAPAuthProvider
from .local_admin import LocalAdminProvider, _CompositeProvider
from .oauth_provider import OAuthConfig, OAuthProvider
from .protocol import AuthProvider, AuthResult, NoAuthProvider

logger = logging.getLogger("cert_watch.auth")


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
    ldap_group_filter: str = "",
    # OAuth options
    oauth_client_id: str = "",
    oauth_client_secret: str = "",
    oauth_issuer_url: str = "",
    oauth_scope: str = "openid profile email",
    oauth_authorization_endpoint: str = "",
    oauth_token_endpoint: str = "",
    oauth_userinfo_endpoint: str = "",
    # SSRF policy for OAuth IdP fetches
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
    jwks_cache_ttl: int = 86400,
    # Authorization options
    allowed_groups: list[str] | None = None,
    allowed_roles: list[str] | None = None,
    # Local break-glass admin
    local_admin_user: str = "",
    local_admin_password_hash: str = "",
    db_path: str | None = None,
) -> AuthProvider:
    """Build an auth provider from config values. Returns NoAuthProvider if provider is empty."""
    provider = provider.lower().strip()

    if local_admin_user and ":" in local_admin_user:
        raise ValueError(
            "Local admin username must not contain colons — colons are used as "
            "field delimiters in session tokens and would cause parsing ambiguity."
        )

    local_admin: LocalAdminProvider | None = None
    if local_admin_user and local_admin_password_hash:
        local_admin = LocalAdminProvider(
            local_admin_user, local_admin_password_hash, db_path=db_path
        )

    primary: AuthProvider
    if not provider or provider == "none":
        if local_admin:
            return local_admin
        return NoAuthProvider()
    if provider == "ldap":
        if not ldap_server or not ldap_base_dn:
            raise ValueError(
                "LDAP auth misconfigured: LDAP_SERVER and LDAP_BASE_DN are required "
                "when AUTH_PROVIDER=ldap. Either configure LDAP or set AUTH_PROVIDER=none."
            )
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
            group_filter=ldap_group_filter,
        )
        if local_admin:
            return _CompositeProvider(local_admin, primary)
        return primary
    if provider in ("oauth", "entra", "azure", "oidc"):
        if not oauth_client_id or not oauth_issuer_url:
            raise ValueError(
                "OAuth misconfigured: OAUTH_CLIENT_ID and OAUTH_ISSUER_URL are required "
                "when AUTH_PROVIDER=oauth. Either configure OAuth or set AUTH_PROVIDER=none."
            )
        primary = OAuthProvider(
            OAuthConfig(
                client_id=oauth_client_id,
                client_secret=oauth_client_secret,
                issuer_url=oauth_issuer_url,
                scope=oauth_scope,
                authorization_endpoint=oauth_authorization_endpoint,
                token_endpoint=oauth_token_endpoint,
                userinfo_endpoint=oauth_userinfo_endpoint,
                allow_private=allow_private,
                allowed_subnets=allowed_subnets,
                jwks_cache_ttl=jwks_cache_ttl,
            )
        )
        if local_admin:
            return _CompositeProvider(local_admin, primary)
        return primary
    logger.warning("Unknown AUTH_PROVIDER=%r, refusing to start without authentication", provider)
    raise ValueError(
        f"Unknown AUTH_PROVIDER={provider!r}. Valid values: none, ldap, oauth/entra/azure/oidc."
    )
