"""Shared helpers for API route modules."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from cert_watch.tags import format_tags, parse_tags

logger = logging.getLogger("cert_watch.routes.api")


def _tags_from_body(body: object) -> str | None:
    """Extract tags from a request body as a normalized csv string.

    Accepts ``{"tags": ["a", "b"]}`` or ``{"tags": "a,b"}``. Returns None when
    the shape is invalid (caller turns that into a 400).
    """
    if not isinstance(body, dict) or "tags" not in body:
        return None
    raw = body["tags"]
    if isinstance(raw, str):
        return format_tags(parse_tags(raw))
    if isinstance(raw, list) and all(isinstance(t, str) for t in raw):
        return format_tags(raw)
    return None


def _pagination_links(request: Request, path: str, page: int, limit: int, total: int) -> dict:
    """Build HATEOAS pagination links for a JSON API response."""
    pages = (total + limit - 1) // limit if limit else 0
    base = str(request.base_url).rstrip("/") + path
    links: dict[str, str | None] = {"self": f"{base}?page={page}&limit={limit}"}
    links["next"] = f"{base}?page={page + 1}&limit={limit}" if page < pages else None
    links["prev"] = f"{base}?page={page - 1}&limit={limit}" if page > 1 else None
    return links


def _runbook_url_error(url: str) -> str | None:
    """Return an error message if *url* is unsafe to store as a runbook link.

    runbook_url is rendered as an ``<a href>`` on the cert detail page. Jinja
    autoescaping neutralizes HTML metacharacters but NOT a ``javascript:`` /
    ``data:`` scheme, so a write-user could otherwise plant a click-to-execute
    stored-XSS payload. Allow empty (clears the field) and http(s) only.
    """
    if not url.strip():
        return None
    from urllib.parse import urlparse

    if urlparse(url.strip()).scheme.lower() not in ("http", "https"):
        return "runbook_url must be an http(s) URL"
    return None


def _validate_webhook_url(url: str) -> JSONResponse | None:
    from cert_watch.http_client import validate_webhook_url as _validate

    error = _validate(url)
    if error:
        return JSONResponse(
            content={"error": f"webhook_url rejected: {error}"},
            status_code=400,
        )
    return None


def _alert_group_json(g: Any) -> dict:
    return {
        "id": g.id,
        "name": g.name,
        "recipients": g.recipients,
        "match_tags": g.match_tags,
        "webhook_url": g.webhook_url,
        "created_at": g.created_at.isoformat(),
    }


def compliance_signing_key(request: Request) -> str:
    """Return the report signing key, or raise 503 if the app isn't fully booted.

    Signing with an empty key produces a report whose HMAC is trivially
    forgeable — worse than no signature, because it *looks* verifiable. Fail
    closed rather than hand an auditor an unverifiable "signed" report.
    """
    security = getattr(request.app.state, "security", None)
    if security is None or not getattr(security, "signing_key", ""):
        raise HTTPException(status_code=503, detail="signing key unavailable")
    return security.signing_key
