"""Policy settings routes."""

from __future__ import annotations

import contextlib
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.middleware import check_csrf, require_admin_form
from cert_watch.policy import PolicyRule, PolicySet, save_policy_set
from cert_watch.routes._deps import _db_path

router = APIRouter()


@router.post("/settings/policy")
async def save_policy_settings(request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=policy&error={csrf_err}", status_code=303)

    db = _db_path(request)
    form = await request.form()

    default_severity = str(form.get("default_severity") or "warning")
    rule_ids = form.getlist("rule_id")
    rules: list[PolicyRule] = []
    for rid in rule_ids:
        rid = str(rid)
        category = str(form.get(f"category_{rid}", "custom"))
        severity = str(form.get(f"severity_{rid}", default_severity))
        enabled = form.get(f"enabled_{rid}") == "1"
        parameters: dict[str, Any] = {}
        min_rsa_raw = form.get(f"min_rsa_{rid}")
        if min_rsa_raw is not None:
            with contextlib.suppress(ValueError):
                parameters["min_rsa"] = int(str(min_rsa_raw))
        max_days_raw = form.get(f"max_days_{rid}")
        if max_days_raw is not None:
            with contextlib.suppress(ValueError):
                parameters["max_days"] = int(str(max_days_raw))
        min_tls_raw = form.get(f"min_tls_{rid}")
        if min_tls_raw is not None:
            parameters["min_tls"] = str(min_tls_raw)
        allowed_issuers_raw = form.get(f"allowed_issuers_{rid}")
        if allowed_issuers_raw is not None:
            val = str(allowed_issuers_raw).strip()
            parameters["allowed_issuers"] = (
                [i.strip() for i in val.split(",") if i.strip()]
                if val else []
            )
        allowed_curves_raw = form.get(f"allowed_curves_{rid}")
        if allowed_curves_raw is not None:
            val = str(allowed_curves_raw).strip()
            parameters["allowed_curves"] = (
                [c.strip() for c in val.split(",") if c.strip()]
                if val else []
            )
        rules.append(PolicyRule(
            rule_id=rid,
            category=category,
            severity=severity,
            enabled=enabled,
            parameters=parameters,
        ))

    ruleset = PolicySet(rules=rules, default_severity=default_severity)
    save_policy_set(str(db), ruleset)

    record_audit(
        str(db),
        actor=resolve_actor(request),
        action="policy.update",
        target_type="policy_set",
        target_id="policy_set",
        detail={"rule_count": len(rules), "default_severity": default_severity},
        source_ip=resolve_source_ip(request),
    )

    return RedirectResponse(url="/settings?tab=policy&saved=1", status_code=303)
