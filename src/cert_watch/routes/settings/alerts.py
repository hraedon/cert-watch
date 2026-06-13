"""Alert configuration routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from cert_watch.routes.settings.config import _ALERT_KEYS
from cert_watch.routes.settings.core import _save_config_section

router = APIRouter()


@router.post("/settings/alerts")
async def save_alert_config(request: Request) -> RedirectResponse:
    return await _save_config_section(request, _ALERT_KEYS, "alerts", encrypt=False, rebuild=True)
