"""Application credential metadata; credential values never belong here."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class ApplicationSecret:
    id: str
    application_name: str
    application_id: str
    credential_id: str
    credential_name: str
    tenant_id: str
    expires_at: datetime | None
    owner_email: str
    created_at: datetime | None
    retired_at: datetime | None = None
    # Stored timestamps this build cannot read (a hand edit or a restore). The
    # record stays listed so an operator can see and replace it.
    unreadable: tuple[str, ...] = ()

    @property
    def retired(self) -> bool:
        # Any stored retirement retires the record, as the SQL does, even if
        # its time is unreadable.
        return self.retired_at is not None or "retired_at" in self.unreadable

    def state(self, now: datetime) -> str:
        if self.retired:
            return "Retired"
        if self.expires_at is None:
            return "Expiry unreadable"
        remaining = (self.expires_at - now).total_seconds()
        if remaining <= 0:
            return "Expired"
        if remaining <= 7 * 86400:
            return "Expires within 7 days"
        if remaining <= 30 * 86400:
            return "Expires within 30 days"
        return "Current"


@dataclass(frozen=True)
class SecretMetadata:
    application_name: str
    application_id: str
    credential_id: str
    credential_name: str
    tenant_id: str
    expires_at: datetime
    owner_email: str


def parse_metadata(data: Mapping[str, object]) -> SecretMetadata:
    """Reject unknown keys and never echo submitted values in diagnostics."""
    allowed = {
        "application_name", "application_id", "credential_id", "credential_name",
        "tenant_id", "expires_at", "owner_email",
    }
    if set(data) - allowed:
        raise ValueError(
            "Only credential metadata fields are accepted; never submit secret values."
        )
    fields: dict[str, str] = {}
    for name in allowed:
        value = data.get(name, "")
        if not isinstance(value, str) or len(value) > 256:
            raise ValueError("Metadata fields must be text of at most 256 characters.")
        value = value.strip()
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("Metadata fields cannot contain control characters.")
        fields[name] = value
    if not all(fields[name] for name in ("application_name", "application_id", "credential_id")):
        raise ValueError("Application name, application ID and credential ID are required.")
    try:
        expires = datetime.fromisoformat(fields["expires_at"].replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Expiry must be an ISO 8601 timestamp with a timezone.") from None
    if expires.tzinfo is None:
        raise ValueError("Expiry must include a timezone, for example 2027-01-01T00:00:00Z.")
    try:
        expires = expires.astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError("Expiry must be representable as a UTC timestamp.") from None
    email = fields["owner_email"]
    if email and (
        email.count("@") != 1 or not all(email.split("@"))
        or any(c.isspace() or c in ',;<>"()[]:' for c in email)
    ):
        raise ValueError("Owner email must be a single email address.")
    return SecretMetadata(
        application_name=fields["application_name"],
        application_id=fields["application_id"],
        credential_id=fields["credential_id"],
        credential_name=fields["credential_name"],
        tenant_id=fields["tenant_id"],
        expires_at=expires,
        owner_email=email,
    )
