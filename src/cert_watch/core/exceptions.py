"""Custom exceptions for cert-watch."""


class CertWatchError(Exception):
    """Base exception for cert-watch."""

    pass


class CertificateError(CertWatchError):
    """Certificate-related errors."""

    pass


class CertificateParseError(CertificateError):
    """Failed to parse certificate file."""

    pass


class TLSError(CertWatchError):
    """TLS handshake errors."""

    pass


class TLSConnectionError(TLSError):
    """Failed to establish TLS connection."""

    pass


class TLSHandshakeError(TLSError):
    """TLS handshake failed."""

    pass


class AlertError(CertWatchError):
    """Email alert errors."""

    pass


class SMTPConfigurationError(AlertError):
    """SMTP not configured properly."""

    pass


class AlertSendError(AlertError):
    """Failed to send alert email."""

    pass


class RepositoryError(CertWatchError):
    """Database repository errors."""

    pass


class NotFoundError(RepositoryError):
    """Record not found in database."""

    pass
