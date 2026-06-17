"""Alert configuration routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from cert_watch.routes.settings.config import _ALERT_KEYS
from cert_watch.routes.settings.core import _save_config_section

router = APIRouter()


@router.post("/settings/alerts")
async def save_alert_config(request: Request) -> RedirectResponse:
    # encrypt=True so webhook_headers (a SENSITIVE_SETTING_KEY) is stored
    # encrypted at rest via kv_set_secret. Other alert keys are non-sensitive
    # and pass through kv_set unchanged regardless of this flag.
    return await _save_config_section(request, _ALERT_KEYS, "alerts", encrypt=True, rebuild=True)
