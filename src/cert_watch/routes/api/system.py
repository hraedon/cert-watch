"""Operational JSON API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.auth.guards import require_auth
from cert_watch.routes.health import build_api_health_response

router = APIRouter()


@router.get("/api/health", dependencies=[Depends(require_auth)])
def api_health(request: Request) -> JSONResponse:
    return build_api_health_response(request)
