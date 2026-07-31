"""Route modules for cert-watch."""

from fastapi import APIRouter

from cert_watch.routes.alerts_view import router as alerts_view_router
from cert_watch.routes.api import router as api_router
from cert_watch.routes.audit import router as audit_router
from cert_watch.routes.auth import router as auth_router
from cert_watch.routes.certificates import router as certificates_router
from cert_watch.routes.dashboard import router as dashboard_router
from cert_watch.routes.health import router as health_router
from cert_watch.routes.hosts import router as hosts_router
from cert_watch.routes.insights import router as insights_router
from cert_watch.routes.metrics import router as metrics_router
from cert_watch.routes.scan_history import router as scan_history_router
from cert_watch.routes.settings import router as settings_router
from cert_watch.routes.setup import router as setup_router
from cert_watch.routes.team import router as team_router

# Collect all routers for easy mounting
api: list[APIRouter] = [
    auth_router,
    health_router,
    dashboard_router,
    alerts_view_router,
    scan_history_router,
    insights_router,
    team_router,
    metrics_router,
    audit_router,
    hosts_router,
    certificates_router,
    api_router,
    setup_router,
    settings_router,
]
