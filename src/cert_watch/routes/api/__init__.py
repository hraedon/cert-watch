"""REST API (JSON) endpoints.

The former monolithic ``routes/api.py`` (1,141 lines) has been decomposed into
a ``routes/api/`` package with concern-specific modules:

- ``certificates`` — cert CRUD, PEM download, tags, notes, history, revocation
- ``hosts`` — host list, owner updates, host tags
- ``alerts`` — alerts list, alert groups CRUD, cert routing
- ``reports`` — CSV/JSON exports, inventory, expiring, compliance reports
- ``insights`` — pivot entries, trends, calendar, webhook test
- ``policy`` — policy set CRUD, policy violations export

All modules are aggregated here into a single router so the rest of the app
continues to mount ``routes.api.router`` unchanged.
"""

from __future__ import annotations

from fastapi import APIRouter

from cert_watch.routes.api.alerts import router as alerts_router
from cert_watch.routes.api.certificates import router as certificates_router
from cert_watch.routes.api.events import router as events_router
from cert_watch.routes.api.hosts import router as hosts_router
from cert_watch.routes.api.insights import router as insights_router
from cert_watch.routes.api.keys import router as keys_router
from cert_watch.routes.api.policy import router as policy_router
from cert_watch.routes.api.renewal_analytics import router as renewal_analytics_router
from cert_watch.routes.api.reports import router as reports_router

router = APIRouter()

# Include all sub-routers.  Prefixes are empty because each sub-router already
# declares its full path (e.g.  @router.get("/api/certificates"))
router.include_router(certificates_router)
router.include_router(hosts_router)
router.include_router(alerts_router)
router.include_router(reports_router)
router.include_router(insights_router)
router.include_router(keys_router)
router.include_router(events_router)
router.include_router(policy_router)
router.include_router(renewal_analytics_router)
