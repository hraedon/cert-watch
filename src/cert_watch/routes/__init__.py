"""Route modules for cert-watch."""

from fastapi import APIRouter

from cert_watch.routes.api import router as api_router
from cert_watch.routes.audit import router as audit_router
from cert_watch.routes.auth import router as auth_router
from cert_watch.routes.certificates import router as certificates_router
from cert_watch.routes.hosts import router as hosts_router
from cert_watch.routes.setup import router as setup_router
from cert_watch.routes.views import router as views_router

# Collect all routers for easy mounting
api: list[APIRouter] = [
    auth_router,
    views_router,
    audit_router,
    hosts_router,
    certificates_router,
    api_router,
    setup_router,
]
