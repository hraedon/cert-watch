"""Activity domain entry point.

/activity is the nav URL for the Activity domain (alerts + scan history +
audit log); it lands on the first tab. The tab routes keep their old URLs
(/alerts, /scan-history, /audit) and render templates/activity.html.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/activity")
def activity_root() -> RedirectResponse:
    return RedirectResponse(url="/alerts", status_code=303)
