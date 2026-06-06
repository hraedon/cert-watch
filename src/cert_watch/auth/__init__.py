"""Authentication providers: LDAP/AD, OAuth/OIDC (Entra), and local break-glass.

When AUTH_PROVIDER is unset, NoAuthProvider allows all requests (backward compat).
Local break-glass admin is activated by setting CERT_WATCH_LOCAL_ADMIN_USER and
CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH — it evaluates before the primary provider
and works regardless of external provider availability.

This package was decomposed from the former 877-line ``auth.py`` monolith
(Plan 021). The public API is re-exported here so that every existing
``from cert_watch.auth import ...`` keeps working unchanged.
"""

from __future__ import annotations

import logging

from .factory import build_auth_provider, check_authz
from .ldap_provider import LDAPAuthProvider
from .local_admin import (
    LocalAdminProvider,
    _CompositeProvider,
    _scrypt_hash,
    verify_scrypt_hash,
)
from .oauth_provider import (
    OAuthConfig,
    OAuthProvider,
    _validate_claims_manual,
)
from .protocol import AuthProvider, AuthResult, NoAuthProvider
from .session import (
    SESSION_COOKIE,
    SESSION_TTL,
    _sign_state,
    _verify_state,
    create_session,
    decode_session,
    set_signing_key,
    validate_session,
)

logger = logging.getLogger("cert_watch.auth")

__all__ = [
    "SESSION_COOKIE",
    "SESSION_TTL",
    "AuthProvider",
    "AuthResult",
    "NoAuthProvider",
    "LDAPAuthProvider",
    "OAuthProvider",
    "OAuthConfig",
    "LocalAdminProvider",
    "_CompositeProvider",
    "build_auth_provider",
    "check_authz",
    "create_session",
    "decode_session",
    "validate_session",
    "set_signing_key",
    "verify_scrypt_hash",
    "_scrypt_hash",
    "_sign_state",
    "_verify_state",
    "_validate_claims_manual",
]
