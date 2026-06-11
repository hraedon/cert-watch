"""Renewal analytics API endpoints."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.middleware import require_auth
from cert_watch.renewal_analytics import compute_fleet_analytics, compute_host_analytics
from cert_watch.routes._deps import _db_path

router = APIRouter()


@router.get("/api/renewal-analytics")
def api_renewal_analytics(
    request: Request, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)
    analytics = compute_fleet_analytics(db)
    return JSONResponse(content=[asdict(a) for a in analytics])


@router.get("/api/renewal-analytics/{hostname}")
def api_renewal_analytics_host(
    hostname: str, request: Request, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)
    analytics = compute_host_analytics(db, hostname)
    return JSONResponse(content=asdict(analytics))
