"""Certificate formatting utilities.

This module provides CANONICAL functions for formatting certificate fields.
ALL certificate formatting MUST go through these functions to ensure consistency
between scanned and uploaded certificates.
"""

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ..core.exceptions import CertificateParseError


def format_subject(cert: x509.Certificate) -> str:
    """Format certificate subject as a canonical string.

    Extracts the Common Name (CN) from the subject. Falls back to
    organizational fields if CN is not present.

    Args:
        cert: The X.509 certificate

    Returns:
        Canonical subject string
    """
    subject = cert.subject
    cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn:
        return str(cn[0].value)

    # Fallback chain
    for oid in [
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
        x509.NameOID.ORGANIZATION_NAME,
    ]:
        attrs = subject.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)

    return str(subject)


def format_issuer(cert: x509.Certificate) -> str:
    """Format certificate issuer as a canonical string.

    Args:
        cert: The X.509 certificate

    Returns:
        Canonical issuer string
    """
    issuer = cert.issuer
    cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn:
        return str(cn[0].value)

    o = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if o:
        return str(o[0].value)

    return str(issuer)


def compute_thumbprint(cert: x509.Certificate) -> str:
    """Compute SHA-256 fingerprint of certificate.

    Args:
        cert: The X.509 certificate

    Returns:
        Hex-encoded SHA-256 fingerprint (lowercase, no colons)
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(cert.tbs_certificate_bytes)
    return digest.finalize().hex()


def format_datetime(dt: datetime) -> str:
    """Format datetime for display in canonical format.

    Args:
        dt: The datetime (naive UTC)

    Returns:
        ISO 8601 format string (YYYY-MM-DD HH:MM:SS UTC)
    """
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def compute_days_remaining(not_after: datetime) -> int:
    """Compute days remaining until expiry.

    Args:
        not_after: Certificate expiry datetime (naive UTC)

    Returns:
        Days remaining (negative if expired)
    """
    now = datetime.utcnow()
    delta = not_after - now
    return delta.days


def get_status_color(days_remaining: int) -> str:
    """Get color code based on days remaining.

    Per spec FR-01:
    - Red: < 7 days
    - Yellow: < 30 days
    - Green: > 30 days

    Args:
        days_remaining: Days until expiry

    Returns:
        Color code: "red", "yellow", or "green"
    """
    if days_remaining < 7:
        return "red"
    elif days_remaining <= 30:
        return "yellow"
    else:
        return "green"


def parse_certificate_file(data: bytes) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Parse certificate file and extract chain.

    Handles PEM and DER encoded files.

    Args:
        data: Raw certificate file bytes

    Returns:
        Tuple of (leaf certificate, list of chain certificates)

    Raises:
        CertificateParseError: If parsing fails
    """
    if not data or len(data) == 0:
        raise CertificateParseError("Empty certificate data")

    # Try PEM format first (most common)
    if b"-----BEGIN CERTIFICATE-----" in data:
        return _parse_pem_data(data)

    # Try DER format (binary)
    try:
        cert = x509.load_der_x509_certificate(data)
        return (cert, [])
    except Exception:
        pass  # Not DER, will raise error below

    raise CertificateParseError("Unable to parse certificate file. Must be PEM or DER format.")


def _parse_pem_data(data: bytes) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Parse PEM-encoded certificate data.

    Args:
        data: PEM-encoded certificate bytes

    Returns:
        Tuple of (leaf certificate, list of chain certificates)

    Raises:
        CertificateParseError: If parsing fails
    """
    certificates = []

    # Split on certificate boundaries and parse each
    import re

    # Find all PEM blocks
    pem_pattern = rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----"
    matches = re.findall(pem_pattern, data, re.DOTALL)

    if not matches:
        raise CertificateParseError("No valid PEM certificates found")

    for match in matches:
        try:
            # Clean up the base64 data (remove newlines/spaces)
            cert_data = re.sub(rb"\s+", b"", match)
            cert_bytes = (
                b"-----BEGIN CERTIFICATE-----\n" + cert_data + b"\n-----END CERTIFICATE-----\n"
            )
            cert = x509.load_pem_x509_certificate(cert_bytes)
            certificates.append(cert)
        except Exception:
            # Skip invalid certificates but continue processing
            continue

    if not certificates:
        raise CertificateParseError("No valid certificates could be parsed from PEM data")

    # First certificate is the leaf, rest are chain
    leaf = certificates[0]
    chain = certificates[1:] if len(certificates) > 1 else []

    return (leaf, chain)


async def extract_certificate_from_tls(
    hostname: str, port: int
) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Extract certificate via TLS handshake.

    Args:
        hostname: Target hostname
        port: Target port

    Returns:
        Tuple of (leaf certificate, list of chain certificates)

    Raises:
        TLSConnectionError: If connection fails
        TLSHandshakeError: If handshake fails
    """
    import socket
    import ssl

    from ..core.exceptions import TLSConnectionError, TLSHandshakeError

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get peer certificate in DER format
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    raise TLSHandshakeError("No certificate received from server")

                # Parse leaf certificate
                leaf_cert = x509.load_der_x509_certificate(cert_der)

                # Get certificate chain if available
                chain_certs = []

                # Try to get the full chain using getpeercertchain (Python 3.10+)
                try:
                    chain_der = ssock.getpeercertchain()
                    if chain_der:
                        for i, cert_bytes in enumerate(chain_der):
                            if i == 0:
                                # First cert is the leaf, skip it
                                continue
                            try:
                                chain_cert = x509.load_der_x509_certificate(cert_bytes)
                                chain_certs.append(chain_cert)
                            except Exception:
                                # Skip certs we can't parse
                                pass
                except AttributeError:
                    # getpeercertchain not available in this Python version
                    pass

                return (leaf_cert, chain_certs)

    except TimeoutError:
        raise TLSConnectionError(f"Connection to {hostname}:{port} timed out")
    except socket.gaierror:
        raise TLSConnectionError(f"Could not resolve hostname: {hostname}")
    except ssl.SSLError as e:
        raise TLSHandshakeError(f"SSL handshake failed: {str(e)}")
    except OSError as e:
        raise TLSConnectionError(f"Connection failed: {str(e)}")


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serialize certificate to PEM format.

    Args:
        cert: The X.509 certificate

    Returns:
        PEM-encoded certificate bytes
    """
    return cert.public_bytes(serialization.Encoding.PEM)
