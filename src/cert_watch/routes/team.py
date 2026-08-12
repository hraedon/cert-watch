"""Legacy /team route — retired by the 2026-08 UI redesign (plan 055).

The email-keyed team dashboard (roles.email ↔ hosts.owner_email) only ever
worked for local users and duplicated the certificate inventory with fewer
controls. Team visibility is now the tag-scope model: a scoped user's
dashboard IS their team view (the topbar shows a scope indicator), and an
unscoped user can filter by any tag. The URL redirects so bookmarks land
somewhere useful.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from cert_watch.middleware import require_auth

router = APIRouter()


@router.get("/team", dependencies=[Depends(require_auth)])
def team_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(url="/", status_code=301)
