"""FR-03: Certificate Upload Route.

This module provides the certificate upload functionality.
- File upload accepts .cer, .pem, .crt formats
- Parses expiry date from certificate
- Extracts chain certificates if present
- Validates file format and content
"""

from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from ..deps import get_repo
from ...core.formatters import (
    format_issuer,
    format_subject,
    compute_thumbprint,
    parse_certificate_file,
    serialize_certificate,
)
from ...core.exceptions import CertificateParseError
from ...models.certificate import Certificate, CertificateSource, CertificateType
from ...repositories.base import CertificateRepository

router = APIRouter()


# Supported file extensions
ALLOWED_EXTENSIONS = {".cer", ".pem", ".crt"}


@router.post("/upload")
async def upload_certificate(
    request: Request,
    certificate: UploadFile = File(...),
    label: str = Form(""),
    repo: CertificateRepository = Depends(get_repo()),
):
    """Handle certificate file upload.

    Accepts .cer, .pem, and .crt files. Parses the certificate(s),
    extracts metadata, and creates database entries.

    Args:
        request: FastAPI request object
        certificate: Uploaded certificate file
        label: Optional user-provided label
        repo: Certificate repository for database operations

    Returns:
        Redirect to result page or error response
    """
    # Validate file extension
    file_ext = Path(certificate.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file extension: {file_ext}. Allowed: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    # Read file content
    try:
        file_content = await certificate.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")

    if not file_content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # Parse certificate file
    try:
        leaf_cert, chain_certs = parse_certificate_file(file_content)
    except CertificateParseError as e:
        raise HTTPException(status_code=422, detail=f"Invalid certificate file: {str(e)}")

    # Extract display label
    display_label = label if label else format_subject(leaf_cert)

    # Create leaf certificate entry
    leaf_fingerprint = compute_thumbprint(leaf_cert)
    leaf_model = Certificate(
        certificate_type=CertificateType.LEAF,
        source=CertificateSource.UPLOADED,
        label=display_label,
        subject=format_subject(leaf_cert),
        issuer=format_issuer(leaf_cert),
        not_before=leaf_cert.not_valid_before,
        not_after=leaf_cert.not_valid_after,
        fingerprint=leaf_fingerprint,
        serial_number=str(leaf_cert.serial_number),
        pem_data=serialize_certificate(leaf_cert),
        chain_position=0,
    )

    # Store leaf certificate
    try:
        await repo.create(leaf_model)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store certificate: {str(e)}")

    # Store chain certificates
    chain_fingerprints = []
    for i, chain_cert in enumerate(chain_certs, start=1):
        chain_fingerprint = compute_thumbprint(chain_cert)
        chain_fingerprints.append(chain_fingerprint)

        chain_model = Certificate(
            certificate_type=CertificateType.INTERMEDIATE,
            source=CertificateSource.UPLOADED,
            label=f"{display_label} (Chain {i})",
            subject=format_subject(chain_cert),
            issuer=format_issuer(chain_cert),
            not_before=chain_cert.not_valid_before,
            not_after=chain_cert.not_valid_after,
            fingerprint=chain_fingerprint,
            serial_number=str(chain_cert.serial_number),
            pem_data=serialize_certificate(chain_cert),
            chain_fingerprint=leaf_fingerprint,
            chain_position=i,
        )

        try:
            await repo.create(chain_model)
        except Exception:
            # Continue storing other chain certs even if one fails
            pass

    # Redirect to result page
    return RedirectResponse(
        url="/",
        status_code=303,  # See Other - recommended for POST-redirect-GET
    )
