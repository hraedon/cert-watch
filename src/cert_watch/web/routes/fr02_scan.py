"""FR-02: TLS Scanning routes.

Provides endpoints for:
- Adding hosts for TLS scanning
- Manual rescan of existing certificates
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse

from ..deps import get_repo
from ...core.exceptions import TLSConnectionError, TLSHandshakeError
from ...core.formatters import (
    compute_thumbprint,
    extract_certificate_from_tls,
    format_issuer,
    format_subject,
    serialize_certificate,
)
from ...models.certificate import Certificate, CertificateSource, CertificateType
from ...repositories.base import CertificateRepository

router = APIRouter()


def _validate_hostname(hostname: Optional[str]) -> str:
    """Validate hostname format."""
    if not hostname or not hostname.strip():
        raise HTTPException(status_code=422, detail="Hostname is required")
    hostname = hostname.strip()
    if len(hostname) > 253:
        raise HTTPException(status_code=422, detail="Hostname too long")
    return hostname


def _validate_port(port: Optional[str]) -> int:
    """Validate and parse port number."""
    if port is None or port == "":
        return 443
    try:
        port_num = int(port)
    except ValueError:
        raise HTTPException(status_code=422, detail="Port must be a number")
    if port_num < 1 or port_num > 65535:
        raise HTTPException(status_code=422, detail="Port must be between 1 and 65535")
    return port_num


@router.post("/scan/add-host")
async def add_host(
    request: Request,
    hostname: Optional[str] = Form(None),
    port: Optional[str] = Form(None),
    repo: CertificateRepository = Depends(get_repo),
):
    """Add a host for TLS scanning.

    Accepts form data with hostname and port, performs TLS handshake,
    extracts the certificate and chain, and stores them.
    """
    # Validate inputs
    try:
        hostname = _validate_hostname(hostname)
        port_num = _validate_port(port)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid input: {str(e)}")

    try:
        # Extract certificate via TLS handshake
        leaf_cert, chain_certs = await extract_certificate_from_tls(hostname, port_num)

        now = datetime.utcnow()
        leaf_fingerprint = compute_thumbprint(leaf_cert)

        # Check if leaf certificate already exists
        existing = await repo.get_by_fingerprint(leaf_fingerprint)
        if existing:
            # Update existing certificate
            existing.updated_at = now
            existing.last_scanned_at = now
            existing.pem_data = serialize_certificate(leaf_cert)
            await repo.update(existing)
            leaf_cert_model = existing
        else:
            # Create new leaf certificate entry
            leaf_cert_model = Certificate(
                certificate_type=CertificateType.LEAF,
                source=CertificateSource.SCANNED,
                hostname=hostname,
                port=port_num,
                subject=format_subject(leaf_cert),
                issuer=format_issuer(leaf_cert),
                not_before=leaf_cert.not_valid_before,
                not_after=leaf_cert.not_valid_after,
                fingerprint=leaf_fingerprint,
                serial_number=str(leaf_cert.serial_number),
                chain_position=0,
                pem_data=serialize_certificate(leaf_cert),
                created_at=now,
                updated_at=now,
                last_scanned_at=now,
                source_hostname=hostname,
                source_port=port_num,
            )
            leaf_cert_model = await repo.create(leaf_cert_model)

        # Store chain certificates
        for i, chain_cert in enumerate(chain_certs, start=1):
            chain_fingerprint = compute_thumbprint(chain_cert)

            # Check if chain cert already exists
            existing_chain = await repo.get_by_fingerprint(chain_fingerprint)
            if existing_chain:
                # Update existing chain cert
                existing_chain.updated_at = now
                existing_chain.pem_data = serialize_certificate(chain_cert)
                await repo.update(existing_chain)
            else:
                # Create new chain certificate entry
                # Determine chain type
                if i == len(chain_certs):
                    # Last cert in chain is typically the root
                    cert_type = CertificateType.ROOT
                else:
                    cert_type = CertificateType.INTERMEDIATE

                chain_model = Certificate(
                    certificate_type=cert_type,
                    source=CertificateSource.SCANNED,
                    subject=format_subject(chain_cert),
                    issuer=format_issuer(chain_cert),
                    not_before=chain_cert.not_valid_before,
                    not_after=chain_cert.not_valid_after,
                    fingerprint=chain_fingerprint,
                    serial_number=str(chain_cert.serial_number),
                    chain_fingerprint=leaf_fingerprint,
                    chain_position=i,
                    pem_data=serialize_certificate(chain_cert),
                    created_at=now,
                    updated_at=now,
                    source_hostname=hostname,
                    source_port=port_num,
                )
                await repo.create(chain_model)

        # Return success response
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            # Redirect to dashboard on success
            return RedirectResponse(url="/", status_code=303)
        else:
            return {
                "success": True,
                "message": f"Certificate for {hostname}:{port_num} scanned successfully",
                "certificate_id": leaf_cert_model.id,
                "subject": leaf_cert_model.subject,
                "issuer": leaf_cert_model.issuer,
                "not_after": leaf_cert_model.not_after.isoformat(),
            }

    except TLSConnectionError as e:
        # Connection error
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <body>
                    <h1>Scan Failed</h1>
                    <p>Error: Could not connect to {hostname}:{port_num}</p>
                    <p>Details: {str(e)}</p>
                    <a href="/">Back to Dashboard</a>
                </body>
                </html>
                """,
                status_code=200,
            )
        raise HTTPException(status_code=400, detail=f"Connection failed: {str(e)}")

    except TLSHandshakeError as e:
        # TLS handshake error
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <body>
                    <h1>Scan Failed</h1>
                    <p>Error: TLS handshake failed for {hostname}:{port_num}</p>
                    <p>Details: {str(e)}</p>
                    <a href="/">Back to Dashboard</a>
                </body>
                </html>
                """,
                status_code=200,
            )
        raise HTTPException(status_code=400, detail=f"TLS handshake failed: {str(e)}")

    except Exception as e:
        # General error
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <body>
                    <h1>Scan Failed</h1>
                    <p>Error: Failed to scan {hostname}:{port_num}</p>
                    <p>Details: {str(e)}</p>
                    <a href="/">Back to Dashboard</a>
                </body>
                </html>
                """,
                status_code=500,
            )
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/{cert_id}/rescan")
async def rescan_certificate(
    cert_id: int,
    request: Request,
    repo: CertificateRepository = Depends(get_repo),
):
    """Manually rescan an existing certificate entry.

    Re-performs TLS handshake for the certificate's hostname and port,
    updating the stored certificate data.
    """
    # Get the existing certificate
    existing_cert = await repo.get_by_id(cert_id)
    if not existing_cert:
        raise HTTPException(status_code=404, detail=f"Certificate {cert_id} not found")

    # Check if this is a scanned certificate with hostname/port
    if existing_cert.source != CertificateSource.SCANNED:
        raise HTTPException(
            status_code=400, detail="Can only rescan certificates that were originally scanned"
        )

    if not existing_cert.hostname or not existing_cert.port:
        raise HTTPException(
            status_code=400, detail="Certificate missing hostname or port information"
        )

    try:
        # Extract certificate via TLS handshake
        leaf_cert, chain_certs = await extract_certificate_from_tls(
            existing_cert.hostname, existing_cert.port
        )

        now = datetime.utcnow()

        # Update the existing certificate
        # Note: We don't update fingerprint as it's a unique identifier
        existing_cert.subject = format_subject(leaf_cert)
        existing_cert.issuer = format_issuer(leaf_cert)
        existing_cert.not_before = leaf_cert.not_valid_before
        existing_cert.not_after = leaf_cert.not_valid_after
        existing_cert.serial_number = str(leaf_cert.serial_number)
        existing_cert.pem_data = serialize_certificate(leaf_cert)
        existing_cert.updated_at = now
        existing_cert.last_scanned_at = now

        await repo.update(existing_cert)

        # Return success response
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return RedirectResponse(url="/", status_code=303)
        else:
            return {
                "success": True,
                "message": f"Certificate {cert_id} rescanned successfully",
                "certificate_id": existing_cert.id,
                "subject": existing_cert.subject,
                "not_after": existing_cert.not_after.isoformat(),
            }

    except (TLSConnectionError, TLSHandshakeError) as e:
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <body>
                    <h1>Rescan Failed</h1>
                    <p>Error: Failed to rescan {existing_cert.hostname}:{existing_cert.port}</p>
                    <p>Details: {str(e)}</p>
                    <a href="/">Back to Dashboard</a>
                </body>
                </html>
                """,
                status_code=200,
            )
        raise HTTPException(status_code=400, detail=f"Rescan failed: {str(e)}")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rescan failed: {str(e)}")
