"""Shared helpers for API route modules."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, cast

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from cert_watch.tags import format_tags, parse_tags

logger = logging.getLogger("cert_watch.routes.api")


def _normalize_pagination(page: int, limit: int, total: int) -> tuple[int, int, int, int]:
    """Return validated (page, limit, pages, offset).

    Ensures *limit* is in [1, 200] and *page* is at least 1.
    """
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    pages = (total + limit - 1) // limit if limit else 0
    offset = (page - 1) * limit
    return page, limit, pages, offset


class JsonBodyError(ValueError):
    """The request body is not the JSON the route needs; ``str(exc)`` is the
    400 message."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonBodyError("invalid JSON")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise JsonBodyError("invalid JSON")


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _invalid_decoded(value: Any, max_depth: int) -> bool:
    """Whether decoded JSON nests deeper than ``max_depth`` or holds a lone
    surrogate. Iterative, so hostile nesting cannot recurse here; only
    containers are queued, strings are checked where they are found."""
    if isinstance(value, str):
        return _LONE_SURROGATE.search(value) is not None
    if not isinstance(value, dict | list):
        return False
    search = _LONE_SURROGATE.search
    pending: list[tuple[dict[str, Any] | list[Any], int]] = [(value, 1)]
    while pending:
        container, depth = pending.pop()
        if depth > max_depth:
            return True
        if isinstance(container, dict):
            for key in container:
                if search(key) is not None:
                    return True
            children: Any = container.values()
        else:
            children = container
        for child in children:
            if isinstance(child, str):
                if search(child) is not None:
                    return True
            elif isinstance(child, dict | list):
                pending.append((child, depth + 1))
    return False


# No API body is more than a few levels deep. The bound is explicit because
# relying on RecursionError is interpreter-dependent: CPython 3.14.7 parses a
# 100k-deep body without raising it, leaving the value to whatever recurses over
# it next. The bound is checked on the decoded value (json.loads also accepts
# UTF-16/32 bytes, which a byte-level scan would misread).
MAX_JSON_DEPTH = 64
# JSON API bodies are small (tags, owner fields, policy, keys). The global
# request limit is sized for CSV uploads; capping JSON separately bounds the
# parse-and-walk cost of a hostile body to a fraction of a second.
MAX_JSON_BODY_BYTES = 1024 * 1024


def json_body(raw: bytes, *, require_object: bool = True) -> Any:
    """Parse a request body as ``Request.json()`` would, raising
    :class:`JsonBodyError` with the message the API has always returned.

    Used as the deferred input of a scope-enforcing service, so the body is
    judged only after the caller's scope on the target has been checked.
    """
    if len(raw) > MAX_JSON_BODY_BYTES:
        raise JsonBodyError("JSON body too large")
    try:
        body = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, RecursionError):
        raise JsonBodyError("invalid JSON") from None
    if _invalid_decoded(body, MAX_JSON_DEPTH):
        raise JsonBodyError("invalid JSON")
    if require_object and not isinstance(body, dict):
        raise JsonBodyError("JSON body must be an object")
    return body


def _tags_from_body(body: dict[str, Any] | None) -> str | None:
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


def tags_from_json_body(raw: bytes) -> str:
    """The deferred tags input of the tag-setting API routes: parse the body,
    extract its tags, or raise :class:`JsonBodyError` with the API's message."""
    tags = _tags_from_body(json_body(raw, require_object=False))
    if tags is None:
        raise JsonBodyError("tags must be a string or list of strings")
    return tags


def _pagination_links(
    request: Request, path: str, page: int, limit: int, total: int,
) -> dict[str, str | None]:
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
    from cert_watch.services.host_ownership import runbook_url_error

    return runbook_url_error(url)


def _validate_webhook_url(url: str) -> JSONResponse | None:
    from cert_watch.http_client import validate_webhook_url as _validate

    error = _validate(url)
    if error:
        return JSONResponse(
            content={"error": f"webhook_url rejected: {error}"},
            status_code=400,
        )
    return None


def _alert_group_json(g: Any) -> dict[str, Any]:
    return {
        "id": g.id,
        "name": g.name,
        "recipients": g.recipients,
        "match_tags": g.match_tags,
        "webhook_url": g.webhook_url,
        "created_at": g.created_at.isoformat(),
        "threshold_days": g.threshold_days,
        "digest_cadence_days": g.digest_cadence_days,
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
    return cast(str, security.signing_key)
