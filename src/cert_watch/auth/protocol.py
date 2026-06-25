"""Auth provider protocol, the AuthResult dataclass, and the no-auth passthrough."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AuthResult:
    success: bool
    username: str = ""
    error: str = ""
    redirect_url: str = ""  # For OAuth: URL to redirect user to
    oauth_state: str = ""  # Signed OAuth state for callback verification (BC-045)
    groups: list[str] | None = None
    roles: list[str] | None = None
    email: str = ""  # User email (Plan 040: for local users + AD/Entra contact)


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
    def provider_label(self) -> str:
        return self.provider_name

    @property
    @abstractmethod
    def supports_form_login(self) -> bool:
        """Whether this provider supports username/password form login."""

    @property
    def is_break_glass_enabled(self) -> bool:
        """Whether a local break-glass admin is configured."""
        return False


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
