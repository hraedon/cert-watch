"""FR-04: Email Alerts routes.

Provides endpoints for:
- Viewing alert history
- Manual alert triggering
- Alert configuration
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ...models.alert import AlertStatus
from ...repositories.base import AlertRepository, CertificateRepository
from ...services.base import AlertService
from ..deps import get_alert_repo, get_alert_service, get_repo

router = APIRouter()


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    cert_repo: CertificateRepository = Depends(get_repo),
    alert_repo: AlertRepository = Depends(get_alert_repo),
):
    """Display alert history page.

    Shows all alerts with their status, linked to certificates.
    """
    # Get all certificates first
    certificates = await cert_repo.get_all(limit=1000)

    # Get alerts for all certificates
    all_alerts = []
    for cert in certificates:
        cert_alerts = await alert_repo.get_for_certificate(cert.id, limit=10)
        for alert in cert_alerts:
            all_alerts.append((alert, cert))

    # Sort by created_at descending (most recent first)
    all_alerts.sort(key=lambda x: x[0].created_at, reverse=True)

    # Limit to 50 most recent
    alerts_with_certs = all_alerts[:50]

    # Simple HTML response
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Certificate Alerts - cert-watch</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .status-pending {{ color: orange; }}
        .status-sent {{ color: green; }}
        .status-failed {{ color: red; }}
        .nav {{ margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">← Dashboard</a> |
        <a href="/alerts">Alerts</a> |
        <a href="/alerts/config">Configuration</a>
    </div>
    <h1>Certificate Alerts</h1>
    <h2>Alert History ({len(alerts_with_certs)} recent)</h2>
    <table>
        <tr>
            <th>Certificate</th>
            <th>Type</th>
            <th>Days</th>
            <th>Status</th>
            <th>Recipient</th>
            <th>Created</th>
        </tr>
"""

    for alert, cert in alerts_with_certs:
        cert_name = cert.display_name if cert else f"Cert #{alert.certificate_id}"

        status_class = f"status-{alert.status.name.lower()}"

        html_content += f"""        <tr>
            <td>{cert_name}</td>
            <td>{alert.alert_type.name}</td>
            <td>{alert.days_remaining}</td>
            <td class="{status_class}">{alert.status.name}</td>
            <td>{alert.recipient}</td>
            <td>{alert.created_at.strftime("%Y-%m-%d %H:%M")}</td>
        </tr>
"""

    html_content += """    </table>
    <h2>Actions</h2>
    <form method="post" action="/alerts/send">
        <button type="submit">Send Pending Alerts Now</button>
    </form>
</body>
</html>
"""

    return HTMLResponse(content=html_content)


@router.post("/alerts/send")
async def send_alerts(
    request: Request,
):
    """Manually trigger sending of pending alerts.

    This endpoint evaluates alerts and sends any pending ones immediately.
    """
    try:
        service = get_alert_service()

        # First evaluate to create any new pending alerts
        await service.evaluate_alerts()

        # Then send pending alerts
        sent, failed = await service.send_pending_alerts()

        # Return success response
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return RedirectResponse(url="/alerts", status_code=303)
        else:
            return {
                "success": True,
                "sent": sent,
                "failed": failed,
            }

    except NotImplementedError:
        # Service not yet fully implemented
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return HTMLResponse(
                content="""<!DOCTYPE html>
<html>
<body>
    <h1>Service Not Ready</h1>
    <p>The alert service is not yet fully implemented.</p>
    <a href="/alerts">Back to Alerts</a>
</body>
</html>
""",
                status_code=503,
            )
        raise HTTPException(status_code=503, detail="Alert service not yet implemented")

    except Exception as e:
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            return HTMLResponse(
                content=f"""<!DOCTYPE html>
<html>
<body>
    <h1>Error</h1>
    <p>Failed to send alerts: {str(e)}</p>
    <a href="/alerts">Back to Alerts</a>
</body>
</html>
""",
                status_code=500,
            )
        raise HTTPException(status_code=500, detail=f"Failed to send alerts: {str(e)}")


@router.get("/alerts/config", response_class=HTMLResponse)
async def alerts_config(
    request: Request,
):
    """Display alert configuration page.

    Shows current SMTP and threshold settings.
    """
    from ...core.config import Settings

    settings = Settings.get()

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Alert Configuration - cert-watch</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        .config-section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .config-item {{ margin: 10px 0; }}
        .label {{ font-weight: bold; display: inline-block; width: 200px; }}
        .value {{ font-family: monospace; }}
        .nav {{ margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">← Dashboard</a> |
        <a href="/alerts">Alerts</a> |
        <a href="/alerts/config">Configuration</a>
    </div>
    <h1>Alert Configuration</h1>

    <div class="config-section">
        <h2>SMTP Settings</h2>
        <div class="config-item">
            <span class="label">SMTP Host:</span>
            <span class="value">{settings.smtp_host or "Not configured"}</span>
        </div>
        <div class="config-item">
            <span class="label">SMTP Port:</span>
            <span class="value">{settings.smtp_port}</span>
        </div>
        <div class="config-item">
            <span class="label">SMTP User:</span>
            <span class="value">{settings.smtp_user or "Not configured"}</span>
        </div>
        <div class="config-item">
            <span class="label">SMTP Use TLS:</span>
            <span class="value">{settings.smtp_use_tls}</span>
        </div>
        <div class="config-item">
            <span class="label">From Address:</span>
            <span class="value">{settings.smtp_from_addr or "Not configured"}</span>
        </div>
    </div>

    <div class="config-section">
        <h2>Alert Recipients</h2>
"""

    if settings.alert_recipients:
        for recipient in settings.alert_recipients:
            html_content += f'        <div class="config-item">• {recipient}</div>\n'
    else:
        html_content += '        <div class="config-item">No recipients configured</div>\n'

    html_content += """    </div>

    <div class="config-section">
        <h2>Alert Thresholds</h2>
        <div class="config-item">
            <span class="label">Leaf Certificates:</span>
            <span class="value">14, 7, 3, 1 days</span>
        </div>
        <div class="config-item">
            <span class="label">Chain Certificates:</span>
            <span class="value">30, 14, 7 days</span>
        </div>
    </div>

    <p><em>Note: Configure these settings via environment variables.</em></p>
</body>
</html>
"""

    return HTMLResponse(content=html_content)
