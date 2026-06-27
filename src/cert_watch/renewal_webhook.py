"""Renewal webhook — structured, action-oriented payload for external renewal tools.

When cert-watch detects a renewal-overdue certificate, this module builds a
machine-readable webhook payload that external tools (certbot, acme.sh,
Certify the Web, custom scripts, Ansible) can consume to trigger renewal.

This is separate from the alert webhook (human-readable) and the event-stream
webhook (monitoring/logging). The renewal webhook is designed for *integration*:
the payload carries enough context (hostname, SANs, issuer, expiry, automation
hint) for the receiving tool to act without querying cert-watch back.

Env vars:
  CERT_WATCH_RENEWAL_WEBHOOK_URL — destination URL (enables the feature)
  CERT_WATCH_RENEWAL_WEBHOOK_HEADERS — JSON dict of extra headers (optional)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cert_watch.http_client import ssrf_safe_urlopen
from cert_watch.renewal_analytics import RenewalOverdueSignal

logger = logging.getLogger("cert_watch.renewal_webhook")

_WEBHOOK_TIMEOUT = 15


@dataclass(frozen=True)
class RenewalWebhookConfig:
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    allow_private: bool = True
    allowed_subnets: tuple[str, ...] = ()


def _resolve_cert_details(
    db_path: str | Path, hostname: str, fingerprint: str
) -> dict[str, Any]:
    from cert_watch.database.connection import _connect

    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT id, subject AS subject_cn, san_dns_names AS san_names,
                      issuer AS issuer_cn, not_after
               FROM certificates
               WHERE hostname = ? AND is_leaf = 1 AND fingerprint_sha256 = ?
               ORDER BY created_at DESC
               LIMIT 1""",
            (hostname, fingerprint),
        ).fetchone()
    if row is None:
        return {}
    return dict(row)


def _resolve_automation_hint(
    db_path: str | Path, hostname: str
) -> str:
    from cert_watch.renewal_analytics import compute_host_analytics

    try:
        analytics = compute_host_analytics(db_path, hostname)
        return analytics.automation_classification
    except Exception:
        return "unknown"


def build_renewal_payload(
    signal: RenewalOverdueSignal,
    db_path: str | Path,
    *,
    port: int = 443,
    base_url: str = "",
) -> dict[str, Any]:
    cert = _resolve_cert_details(db_path, signal.hostname, signal.cert_fingerprint)
    automation = _resolve_automation_hint(db_path, signal.hostname)

    san_raw = cert.get("san_names", "")
    try:
        san_list = json.loads(san_raw) if san_raw else []
    except (json.JSONDecodeError, TypeError):
        san_list = []

    payload: dict[str, Any] = {
        "event": "renewal_needed",
        "hostname": signal.hostname,
        "port": port,
        "cert_fingerprint": signal.cert_fingerprint,
        "subject_cn": cert.get("subject_cn", ""),
        "san_names": san_list,
        "issuer": cert.get("issuer_cn", ""),
        "expiry": cert.get("not_after", ""),
        "days_remaining": signal.days_remaining,
        "expected_renewal_at_days": signal.expected_renewal_at_days,
        "days_overdue": signal.days_overdue,
        "confidence": signal.confidence,
        "automation_hint": automation,
    }
    if base_url and cert.get("id"):
        payload["cert_watch_url"] = f"{base_url.rstrip('/')}/certificates/{cert['id']}"
    return payload


def send_renewal_webhook(
    payload: dict[str, Any],
    config: RenewalWebhookConfig,
) -> bool:
    body = json.dumps(payload, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", **config.headers}
    try:
        resp = ssrf_safe_urlopen(
            config.url,
            data=body,
            headers=headers,
            timeout=_WEBHOOK_TIMEOUT,
            allow_private=config.allow_private,
            allowed_subnets=config.allowed_subnets,
        )
        try:
            resp.read(1)
            status = resp.status
        finally:
            resp.close()
        if not (200 <= status < 300):
            logger.warning(
                "renewal webhook for %s returned HTTP %d",
                payload.get("hostname", "?"),
                status,
            )
            return False
        logger.info(
            "renewal webhook delivered for %s",
            payload.get("hostname", "?"),
        )
        return True
    except Exception as exc:
        logger.warning(
            "renewal webhook delivery failed for %s: %s",
            payload.get("hostname", "?"),
            exc,
        )
        return False


def load_renewal_webhook_config(
    *,
    env_url: str = "",
    env_headers: str = "",
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> RenewalWebhookConfig | None:
    url = env_url.strip()
    if not url:
        return None
    headers: dict[str, str] = {}
    raw_headers = env_headers.strip()
    if raw_headers:
        try:
            parsed = json.loads(raw_headers)
            if isinstance(parsed, dict):
                headers = {str(k): str(v) for k, v in parsed.items()}
        except (json.JSONDecodeError, TypeError):
            logger.warning("CERT_WATCH_RENEWAL_WEBHOOK_HEADERS is not valid JSON; ignoring")
    return RenewalWebhookConfig(
        url=url,
        headers=headers,
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
    )
