"""FR-01 Dashboard Routes.

Dashboard display for monitored certificates with color-coded status.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ...core.formatters import format_datetime
from ...repositories.base import CertificateRepository
from ..deps import get_repo

# Setup templates
BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Create router - NO prefix! Auto-discovery adds prefix from filename
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    repo: CertificateRepository = Depends(get_repo()),
):
    """Main dashboard displaying all certificates.

    Shows certificates with:
    - Hostname/label
    - Issuer
    - Expiry date
    - Days remaining
    - Color-coded status (red <7 days, yellow <30 days, green >30 days)

    Sorted by urgency (days remaining ascending).
    """
    # Get all certificates sorted by urgency
    certificates = await repo.get_all()

    # Prepare certificate data with computed fields
    cert_data = []
    for cert in certificates:
        days_remaining = cert.days_remaining
        status_color = cert.status_color

        cert_data.append(
            {
                "id": cert.id,
                "display_name": cert.display_name,
                "hostname": cert.hostname,
                "label": cert.label,
                "subject": cert.subject,
                "issuer": cert.issuer,
                "not_after": cert.not_after,
                "not_after_formatted": format_datetime(cert.not_after),
                "days_remaining": days_remaining,
                "status_color": status_color,
                "fingerprint": cert.fingerprint[:16] + "..."
                if len(cert.fingerprint) > 16
                else cert.fingerprint,
                "certificate_type": cert.certificate_type.name.lower(),
                "source": cert.source.name.lower(),
            }
        )

    # Count certificates by status
    red_count = sum(1 for c in cert_data if c["status_color"] == "red")
    yellow_count = sum(1 for c in cert_data if c["status_color"] == "yellow")
    green_count = sum(1 for c in cert_data if c["status_color"] == "green")

    context = {
        "request": request,
        "certificates": cert_data,
        "total_count": len(cert_data),
        "red_count": red_count,
        "yellow_count": yellow_count,
        "green_count": green_count,
        "has_certificates": len(cert_data) > 0,
    }

    return templates.TemplateResponse(request, "dashboard.html", context)
