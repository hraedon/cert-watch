"""Renewal-report ingestion and endpoint history (#118 S2)."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime
from typing import Annotated, Literal, Self

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import renewal_report_guard, renewal_report_read_guard
from cert_watch.host_validation import canonical_hostname
from cert_watch.routes._deps import _db_path, _get_settings, acting_auth
from cert_watch.routes.api._shared import JsonBodyError, json_body
from cert_watch.security.ratelimit import check_rate_limit
from cert_watch.services.renewal_reports import (
    RenewalReportConflictError,
    RenewalReportInput,
    RenewalReportNotFoundError,
    create_report,
    list_reports,
    resolve_history_target,
    resolve_target,
)

router = APIRouter()
MAX_RENEWAL_REPORT_BYTES = 16 * 1024
_TOOL_RE = re.compile(r"^[A-Za-z0-9._+\-]{1,64}$")
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


class RenewalReportBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Literal["started", "succeeded", "failed"]
    hostname: StrictStr | None = None
    port: StrictInt | None = None
    cert_fingerprint: StrictStr | None = None
    message: StrictStr | None = None
    new_fingerprint: StrictStr | None = None
    tool: StrictStr | None = None
    correlation_id: StrictStr | None = None
    occurred_at: StrictStr | None = None

    @field_validator("hostname")
    @classmethod
    def canonicalize_hostname(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return canonical_hostname(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from None

    @field_validator("port")
    @classmethod
    def valid_port(cls, value: int | None) -> int | None:
        if value is not None and not 1 <= value <= 65535:
            raise ValueError("must be between 1 and 65535")
        return value

    @field_validator("cert_fingerprint", "new_fingerprint")
    @classmethod
    def valid_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", value):
            raise ValueError("must be a SHA-256 hexadecimal fingerprint")
        return value.lower()

    @field_validator("message")
    @classmethod
    def valid_message(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = unicodedata.normalize("NFC", value)
        if len(value) > 2000:
            raise ValueError("must contain at most 2000 code points")
        for character in value:
            code = ord(character)
            if code in _BIDI or (code < 32 and character not in "\t\n") or 0x7F <= code <= 0x9F:
                raise ValueError("contains a disallowed control character")
        return value

    @field_validator("tool")
    @classmethod
    def valid_tool(cls, value: str | None) -> str | None:
        if value is not None and not _TOOL_RE.fullmatch(value):
            raise ValueError("must match ^[A-Za-z0-9._+-]{1,64}$")
        return value

    @field_validator("correlation_id")
    @classmethod
    def valid_correlation(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 128:
            raise ValueError("must contain at most 128 code points")
        return value

    @field_validator("occurred_at")
    @classmethod
    def valid_occurred_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("must be an ISO 8601 timestamp") from None
        if instant.tzinfo is None:
            raise ValueError("must include a UTC offset")
        return instant.isoformat()

    @model_validator(mode="after")
    def exactly_one_target(self) -> Self:
        endpoint = self.hostname is not None or self.port is not None
        if endpoint and (self.hostname is None or self.port is None):
            raise ValueError("hostname and port must be supplied together")
        if endpoint == (self.cert_fingerprint is not None):
            raise ValueError("send either hostname and port or cert_fingerprint")
        return self


def _validation_error(exc: ValidationError | JsonBodyError) -> JSONResponse:
    if isinstance(exc, JsonBodyError):
        message = str(exc)
    else:
        first = exc.errors(include_url=False, include_context=False)[0]
        field = ".".join(str(part) for part in first["loc"])
        message = f"{field}: {first['msg']}" if field else str(first["msg"])
    return JSONResponse(status_code=422, content={"error": message})


async def _capped_body(request: Request) -> bytes | None:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_RENEWAL_REPORT_BYTES:
            return None
    return bytes(body)


def _idempotency_key(raw: str | None) -> str | None:
    if raw is None:
        return None
    if not 1 <= len(raw) <= 128 or any(not 0x20 <= ord(c) <= 0x7E for c in raw):
        raise ValueError("Idempotency-Key must be 1-128 printable ASCII characters")
    return raw


def _canonical_hash(body: RenewalReportBody) -> str:
    raw = json.dumps(
        body.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


@router.post("/api/renewal-reports")
async def api_create_renewal_report(
    request: Request,
    _auth: str = Depends(renewal_report_guard),
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JSONResponse:
    auth = acting_auth(request)
    principal = str(auth.principal_id)
    if not check_rate_limit(f"renewal_report:{principal}", 30, 60):
        return JSONResponse(status_code=429, content={"error": "rate limited"})
    raw = await _capped_body(request)
    if raw is None:
        return JSONResponse(status_code=413, content={"error": "request body too large"})
    try:
        body = RenewalReportBody.model_validate(json_body(raw))
        idem = _idempotency_key(idempotency_key)
    except (JsonBodyError, ValidationError) as exc:
        return _validation_error(exc)
    except ValueError as exc:
        return JSONResponse(status_code=422, content={"error": str(exc)})
    try:
        target = resolve_target(
            _db_path(request),
            auth,
            hostname=body.hostname,
            port=body.port,
            cert_fingerprint=body.cert_fingerprint,
        )
    except RenewalReportNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})
    except RenewalReportConflictError as exc:
        return JSONResponse(status_code=409, content={"error": str(exc)})
    if not check_rate_limit(f"renewal_report_endpoint:{principal}:{target.host_id}", 5, 60):
        return JSONResponse(status_code=429, content={"error": "rate limited"})
    if body.outcome == "succeeded":
        return JSONResponse(
            status_code=503,
            content={"error": "renewal verification is not available yet"},
        )
    report = RenewalReportInput(
        outcome=body.outcome,
        message=body.message,
        tool=body.tool,
        correlation_id=body.correlation_id,
        new_fingerprint=body.new_fingerprint,
        occurred_at=body.occurred_at,
    )
    try:
        result, _replayed = create_report(
            _db_path(request),
            _get_settings(request),
            target,
            report,
            auth=auth,
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
            idempotency_key=idem,
            body_sha256=_canonical_hash(body),
        )
    except RenewalReportNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})
    except RenewalReportConflictError as exc:
        return JSONResponse(status_code=409, content={"error": str(exc)})
    return JSONResponse(status_code=202, content=result.__dict__)


@router.get("/api/renewal-reports")
def api_renewal_report_history(
    request: Request,
    hostname: str,
    port: Annotated[int, Query(ge=1, le=65535)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    _auth: str = Depends(renewal_report_read_guard),
) -> JSONResponse:
    try:
        hostname = canonical_hostname(hostname)
        target = resolve_history_target(_db_path(request), acting_auth(request), hostname, port)
    except (ValueError, RenewalReportNotFoundError):
        return JSONResponse(status_code=404, content={"error": "endpoint not found"})
    return JSONResponse(
        content=list_reports(
            _db_path(request), target, auth=acting_auth(request), page=page, limit=limit
        )
    )
