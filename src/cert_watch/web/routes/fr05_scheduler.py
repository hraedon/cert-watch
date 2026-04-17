"""FR-05: Scheduler routes for daily scan and status.

Provides web endpoints for:
- Manual scan triggering
- Scheduler status
- Scan history viewing
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch.repositories.base import ScanHistoryRepository
from cert_watch.services.base import ScanSchedulerService
from cert_watch.web.deps import get_scan_repo

router = APIRouter()


def get_scheduler_service() -> ScanSchedulerService:
    """Get the scheduler service instance.

    Returns:
        ScanSchedulerService implementation

    Raises:
        HTTPException: If scheduler service is not available
    """
    try:
        from cert_watch.services.scheduler_impl import ScanSchedulerImpl

        return ScanSchedulerImpl()
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Scheduler service not available: {e}",
        )


@router.post("/scheduler/scan")
async def trigger_manual_scan(
    scheduler: ScanSchedulerService = Depends(get_scheduler_service),
):
    """Manually trigger a scan cycle.

    This endpoint runs the same scan cycle that the scheduler runs daily.
    It refreshes all scanned certificates and triggers alert evaluation.

    Returns:
        Redirect to scheduler status page
    """
    try:
        await scheduler.run_daily_scan()
        return RedirectResponse(url="/scheduler", status_code=302)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/scheduler", response_class=HTMLResponse)
async def scheduler_status_page(
    request: Request,
    scan_repo: ScanHistoryRepository = Depends(get_scan_repo),
):
    """Display scheduler status and configuration.

    Shows:
    - Current scheduler configuration (scan time, timezone)
    - Recent scan history
    - Next scheduled scan time

    Args:
        request: FastAPI request object
        scan_repo: Scan history repository

    Returns:
        HTML page with scheduler status
    """
    from cert_watch.core.config import Settings

    settings = Settings.get()

    # Get recent scan history
    recent_scans = await scan_repo.get_recent(limit=10)

    # Format scans for display
    formatted_scans = []
    for scan in recent_scans:
        formatted_scans.append(
            {
                "id": scan.id,
                "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.started_at
                else "Unknown",
                "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.completed_at
                else "In Progress",
                "status": scan.status.name if scan.status else "UNKNOWN",
                "total_hosts": scan.total_hosts,
                "successful_hosts": scan.successful_hosts,
                "failed_hosts": scan.failed_hosts,
                "updated_certificates": scan.updated_certificates,
                "error_message": scan.error_message,
            }
        )

    # Simple HTML response (for HTMX compatibility)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scheduler Status - Cert Watch</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #555; margin-top: 30px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .status-SUCCESS {{ color: green; font-weight: bold; }}
            .status-PARTIAL {{ color: orange; font-weight: bold; }}
            .status-FAILURE {{ color: red; font-weight: bold; }}
            .config-box {{ background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            .btn {{
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                margin: 10px 5px;
            }}
            .btn:hover {{ background-color: #45a049; }}
        </style>
    </head>
    <body>
        <h1>Scheduler Status</h1>

        <div class="config-box">
            <h2>Configuration</h2>
            <p><strong>Daily Scan Time:</strong> {settings.scan_time}</p>
            <p><strong>Timezone:</strong> {settings.scan_timezone}</p>
            <p><strong>Leaf Alert Thresholds:</strong> {", ".join(map(str, settings.leaf_alert_thresholds))} days</p>
            <p><strong>Chain Alert Thresholds:</strong> {", ".join(map(str, settings.chain_alert_thresholds))} days</p>
        </div>

        <h2>Actions</h2>
        <form action="/scheduler/scan" method="post" style="display: inline;">
            <button type="submit" class="btn">Run Manual Scan</button>
        </form>
        <a href="/scheduler/history" class="btn">View Full History</a>
        <a href="/" class="btn">Back to Dashboard</a>

        <h2>Recent Scan History</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Started At</th>
                    <th>Completed At</th>
                    <th>Status</th>
                    <th>Total Hosts</th>
                    <th>Successful</th>
                    <th>Failed</th>
                    <th>Updated Certs</th>
                </tr>
            </thead>
            <tbody>
    """

    for scan in formatted_scans:
        status_class = f"status-{scan['status']}"
        html_content += f"""
                <tr>
                    <td>{scan["id"]}</td>
                    <td>{scan["started_at"]}</td>
                    <td>{scan["completed_at"]}</td>
                    <td class="{status_class}">{scan["status"]}</td>
                    <td>{scan["total_hosts"]}</td>
                    <td>{scan["successful_hosts"]}</td>
                    <td>{scan["failed_hosts"]}</td>
                    <td>{scan["updated_certificates"]}</td>
                </tr>
        """

    if not formatted_scans:
        html_content += """
                <tr>
                    <td colspan="8" style="text-align: center; color: #666;">
                        No scan history available
                    </td>
                </tr>
        """

    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


@router.get("/scheduler/history", response_class=HTMLResponse)
async def scan_history_page(
    request: Request,
    scan_repo: ScanHistoryRepository = Depends(get_scan_repo),
):
    """Display full scan history.

    Shows a detailed view of all scan history entries.

    Args:
        request: FastAPI request object
        scan_repo: Scan history repository

    Returns:
        HTML page with full scan history
    """
    # Get all scan history
    all_scans = await scan_repo.get_recent(limit=100)

    # Format scans for display
    formatted_scans = []
    for scan in all_scans:
        formatted_scans.append(
            {
                "id": scan.id,
                "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.started_at
                else "Unknown",
                "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.completed_at
                else "In Progress",
                "status": scan.status.name if scan.status else "UNKNOWN",
                "total_hosts": scan.total_hosts,
                "successful_hosts": scan.successful_hosts,
                "failed_hosts": scan.failed_hosts,
                "updated_certificates": scan.updated_certificates,
                "error_message": scan.error_message,
            }
        )

    # Simple HTML response
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan History - Cert Watch</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .status-SUCCESS { color: green; font-weight: bold; }
            .status-PARTIAL { color: orange; font-weight: bold; }
            .status-FAILURE { color: red; font-weight: bold; }
            .btn {
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                margin: 10px 5px;
            }
            .btn:hover { background-color: #45a049; }
            .error-msg { color: red; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <h1>Scan History</h1>
        <a href="/scheduler" class="btn">Back to Scheduler</a>
        <a href="/" class="btn">Back to Dashboard</a>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Started At</th>
                    <th>Completed At</th>
                    <th>Status</th>
                    <th>Total Hosts</th>
                    <th>Successful</th>
                    <th>Failed</th>
                    <th>Updated Certs</th>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
    """

    for scan in formatted_scans:
        status_class = f"status-{scan['status']}"
        error_display = (
            scan["error_message"][:50] + "..."
            if scan["error_message"] and len(scan["error_message"]) > 50
            else (scan["error_message"] or "")
        )
        html_content += f"""
                <tr>
                    <td>{scan["id"]}</td>
                    <td>{scan["started_at"]}</td>
                    <td>{scan["completed_at"]}</td>
                    <td class="{status_class}">{scan["status"]}</td>
                    <td>{scan["total_hosts"]}</td>
                    <td>{scan["successful_hosts"]}</td>
                    <td>{scan["failed_hosts"]}</td>
                    <td>{scan["updated_certificates"]}</td>
                    <td class="error-msg">{error_display}</td>
                </tr>
        """

    if not formatted_scans:
        html_content += """
                <tr>
                    <td colspan="9" style="text-align: center; color: #666;">
                        No scan history available
                    </td>
                </tr>
        """

    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


@router.get("/scheduler/status")
async def scheduler_api_status(
    scan_repo: ScanHistoryRepository = Depends(get_scan_repo),
):
    """Get scheduler status as JSON API.

    Returns:
        JSON with scheduler configuration and recent scan history
    """
    from cert_watch.core.config import Settings

    settings = Settings.get()
    recent_scans = await scan_repo.get_recent(limit=5)

    return {
        "scan_time": settings.scan_time,
        "scan_timezone": settings.scan_timezone,
        "leaf_alert_thresholds": settings.leaf_alert_thresholds,
        "chain_alert_thresholds": settings.chain_alert_thresholds,
        "recent_scans": [
            {
                "id": scan.id,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "status": scan.status.name if scan.status else None,
                "total_hosts": scan.total_hosts,
                "successful_hosts": scan.successful_hosts,
                "failed_hosts": scan.failed_hosts,
                "updated_certificates": scan.updated_certificates,
            }
            for scan in recent_scans
        ],
    }
