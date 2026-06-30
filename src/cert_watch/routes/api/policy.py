"""Policy API endpoints — read/modify the active policy set, export violations."""

from __future__ import annotations

import csv
import io
import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from cert_watch.database import SqliteAlertRepository
from cert_watch.middleware import require_admin_write, require_auth
from cert_watch.policy import (
    PolicyRule,
    PolicySet,
    acquire_policy_lock,
    load_policy_set,
    save_policy_set_locked,
)
from cert_watch.routes._deps import _csv_safe, _db_path

logger = logging.getLogger("cert_watch.routes.api.policy")

router = APIRouter()


def _rule_json(r: PolicyRule) -> dict[str, Any]:
    return {
        "rule_id": r.rule_id,
        "category": r.category,
        "severity": r.severity,
        "enabled": r.enabled,
        "parameters": r.parameters,
    }


@router.get("/api/policy")
def api_get_policy(
    request: Request, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)
    ruleset = load_policy_set(str(db))
    return JSONResponse(content={
        "default_severity": ruleset.default_severity,
        "rules": [_rule_json(r) for r in ruleset.rules],
    })


@router.put("/api/policy")
async def api_put_policy(
    request: Request, _auth: str = Depends(require_admin_write)
) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)

    db = _db_path(request)
    default_sev = body.get("default_severity", "warning")
    if default_sev not in ("critical", "warning", "info"):
        return JSONResponse(
            content={"error": "default_severity must be critical, warning, or info"},
            status_code=400,
        )
    rules_data = body.get("rules", [])
    if not isinstance(rules_data, list):
        return JSONResponse(content={"error": "rules must be a list"}, status_code=400)

    rules: list[PolicyRule] = []
    for r in rules_data:
        if not isinstance(r, dict):
            continue
        rule_id = r.get("rule_id", "unknown")
        category = r.get("category", "custom")
        severity = r.get("severity", default_sev)
        if severity not in ("critical", "warning", "info"):
            return JSONResponse(
                content={"error": f"invalid severity for rule {rule_id}: {severity}"},
                status_code=400,
            )
        enabled = bool(r.get("enabled", False))
        parameters = r.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {}
        min_rsa = parameters.get("min_rsa")
        if min_rsa is not None:
            try:
                min_rsa = int(min_rsa)
                if min_rsa <= 0:
                    raise ValueError
            except (ValueError, TypeError):
                return JSONResponse(
                    content={"error": f"min_rsa must be a positive integer for rule {rule_id}"},
                    status_code=400,
                )
        max_days = parameters.get("max_days")
        if max_days is not None:
            try:
                max_days = int(max_days)
                if max_days <= 0:
                    raise ValueError
            except (ValueError, TypeError):
                return JSONResponse(
                    content={"error": f"max_days must be a positive integer for rule {rule_id}"},
                    status_code=400,
                )
        allowed_issuers = parameters.get("allowed_issuers")
        if allowed_issuers is not None and (
            not isinstance(allowed_issuers, list)
            or not all(isinstance(i, str) for i in allowed_issuers)
        ):
            return JSONResponse(
                content={"error": f"allowed_issuers must be a list of strings for rule {rule_id}"},
                status_code=400,
            )
        rules.append(PolicyRule(
            rule_id=rule_id,
            category=category,
            severity=severity,
            enabled=enabled,
            parameters=parameters,
        ))

    ruleset = PolicySet(rules=rules, default_severity=default_sev)

    # Merge incoming rules into the current policy under the write lock (WI-017).
    # This prevents two concurrent PUTs from losing one writer's changes.
    with acquire_policy_lock():
        current = load_policy_set(str(db))
        current_by_id = {r.rule_id: r for r in current.rules}
        for r in ruleset.rules:
            current_by_id[r.rule_id] = r
        merged = PolicySet(
            rules=list(current_by_id.values()),
            default_severity=ruleset.default_severity,
        )
        save_policy_set_locked(str(db), merged)

    from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip

    record_audit(
        str(db),
        actor=resolve_actor(request),
        action="policy.update",
        target_type="policy_set",
        target_id="policy_set",
        detail={"rule_count": len(merged.rules), "default_severity": default_sev},
        source_ip=resolve_source_ip(request),
    )

    return JSONResponse(content={
        "default_severity": merged.default_severity,
        "rules": [_rule_json(r) for r in merged.rules],
    })


@router.get("/api/reports/policy-violations", response_model=None)
def api_policy_violations(
    request: Request,
    _auth: str = Depends(require_auth),
    format: str = "json",
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> JSONResponse | PlainTextResponse:
    db = _db_path(request)
    repo = SqliteAlertRepository(str(db))
    violations = repo.list_pending_filtered(
        alert_type="policy_violation",
        limit=limit,
        offset=offset,
    )

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["cert_id", "hostname", "severity", "message", "status", "created_at"])
        for a in violations:
            msg = a.message or ""
            sev = "warning"
            if "(critical)" in msg:
                sev = "critical"
            elif "(warning)" in msg:
                sev = "warning"
            detail = msg
            if ": " in msg:
                detail = msg.split(": ", 1)[1]
            writer.writerow([
                _csv_safe(a.cert_id),
                _csv_safe(a.hostname),
                _csv_safe(sev),
                _csv_safe(detail),
                _csv_safe(a.status),
                _csv_safe(a.created_at.isoformat() if a.created_at else ""),
            ])
        return PlainTextResponse(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=policy-violations.csv"},
        )

    items = []
    for a in violations:
        items.append({
            "cert_id": a.cert_id,
            "hostname": a.hostname,
            "message": a.message,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })
    return JSONResponse(content={"violations": items})