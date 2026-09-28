"""Renewal digest target selection and rendering (Plan 048)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cert_watch.alerting.digest.engine import DigestTarget
from cert_watch.alerting.model import AlertConfig, OutboundMessage
from cert_watch.alerting.transports.smtp import _validate_email
from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.database.schema import init_schema

logger = logging.getLogger("cert_watch.alerting.digest")


@dataclass
class RenewalDigest:
    days: int
    renewed_count: int
    renewed_hosts: list[str]
    overdue_count: int
    overdue_hosts: list[str]
    shortened_count: int
    shortened_hosts: list[str]
    owner_email: str = ""
    host_expiry: dict[str, str | None] = field(default_factory=dict)
    failed_count: int = 0
    failed_entries: list[str] = field(default_factory=list)
    not_deployed_count: int = 0
    not_deployed_entries: list[str] = field(default_factory=list)


def _parse_event_payload(payload_raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(payload_raw)
        return payload if isinstance(payload, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


_Endpoint = tuple[str, int | None]


def _event_endpoint(payload: dict[str, Any]) -> _Endpoint | None:
    hostname = payload.get("hostname")
    if not isinstance(hostname, str) or not hostname.strip():
        return None
    port = payload.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        port = None
    return hostname, port


def _endpoint_label(endpoint: _Endpoint) -> str:
    hostname, port = endpoint
    if port is None:
        return f"{hostname} (port unknown)"
    if port == 443:
        return hostname
    return f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"


def build_renewal_digest(
    db_path: str | Path,
    days: int = 7,
    *,
    cadence_days: int | None = None,
    now: datetime | None = None,
) -> list[RenewalDigest]:
    """Build per-owner renewal activity for the requested cadence window."""
    effective_days = cadence_days if cadence_days is not None else days
    init_schema(db_path)
    current = now or datetime.now(UTC)
    cutoff = (current - timedelta(days=effective_days)).isoformat()

    with _connect(db_path) as conn:
        renewed_rows = conn.execute(
            """SELECT payload FROM event_log
               WHERE event_type = 'cert_renewed'
               AND timestamp >= ?""",
            (cutoff,),
        ).fetchall()
        overdue_rows = conn.execute(
            """SELECT payload FROM event_log
               WHERE event_type = 'renewal_overdue'
               AND timestamp >= ?""",
            (cutoff,),
        ).fetchall()
        problem_rows = conn.execute(
            """SELECT a.attempt_id,a.state,a.failure_reported_at,a.raised_at,
                      h.hostname,h.port,h.owner_email
               FROM renewal_attempts a
               JOIN hosts h ON h.id=a.host_id
               WHERE a.is_current=1 AND (
                  (a.failure_reported_at>=? AND a.failure_reported_at<=?
                      AND a.state NOT IN ('verified','cancelled'))
                  OR (a.raised_at>=? AND a.raised_at<=? AND a.state='not_deployed'))
               ORDER BY COALESCE(a.failure_reported_at,a.raised_at),a.opened_seq""",
            (cutoff, current.isoformat(), cutoff, current.isoformat()),
        ).fetchall()

    renewed_by_endpoint: dict[_Endpoint, int] = {}
    for row in renewed_rows:
        endpoint = _event_endpoint(_parse_event_payload(row["payload"]))
        if endpoint is not None:
            renewed_by_endpoint[endpoint] = renewed_by_endpoint.get(endpoint, 0) + 1

    overdue_by_endpoint: dict[_Endpoint, int] = {}
    for row in overdue_rows:
        endpoint = _event_endpoint(_parse_event_payload(row["payload"]))
        if endpoint is not None:
            overdue_by_endpoint[endpoint] = overdue_by_endpoint.get(endpoint, 0) + 1

    problem_endpoints = {
        (str(row["hostname"]), int(row["port"])) for row in problem_rows
    }
    activity_endpoints = renewed_by_endpoint.keys() | overdue_by_endpoint.keys()
    endpoints = activity_endpoints | problem_endpoints
    if not endpoints:
        return []

    host_owners: dict[_Endpoint, str] = {}
    current_expiry: dict[_Endpoint, str | None] = {}
    with _connect(db_path) as conn:
        for row in conn.execute(
            "SELECT hostname, port, owner_email FROM hosts"
        ).fetchall():
            host_owners[(row["hostname"], row["port"])] = row["owner_email"] or ""
        for endpoint in endpoints:
            hostname, port = endpoint
            if port is None:
                current_expiry[endpoint] = None
                continue
            row = conn.execute(
                """SELECT not_after FROM certificates
                   WHERE hostname = ? AND port = ? AND is_leaf = 1 AND source = 'scanned'
                   ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (hostname, port),
            ).fetchone()
            current_expiry[endpoint] = row["not_after"] if row is not None else None

    from cert_watch.renewal_analytics import compute_host_analytics

    shortened_endpoints = {
        endpoint
        for endpoint in activity_endpoints
        if endpoint[1] is not None
        and compute_host_analytics(
            db_path,
            endpoint[0],
            port=endpoint[1],
        ).lifetime_trend
        == "decreasing"
    }

    by_owner: dict[str, RenewalDigest] = {}

    def _ensure_owner(email: str) -> RenewalDigest:
        if email not in by_owner:
            by_owner[email] = RenewalDigest(
                days=effective_days,
                renewed_count=0,
                renewed_hosts=[],
                overdue_count=0,
                overdue_hosts=[],
                shortened_count=0,
                shortened_hosts=[],
                owner_email=email,
            )
        return by_owner[email]

    for endpoint, count in renewed_by_endpoint.items():
        owner = host_owners.get(endpoint, "") if endpoint[1] is not None else ""
        digest = _ensure_owner(owner)
        digest.renewed_count += count
        digest.renewed_hosts.append(_endpoint_label(endpoint))

    for endpoint, count in overdue_by_endpoint.items():
        owner = host_owners.get(endpoint, "") if endpoint[1] is not None else ""
        digest = _ensure_owner(owner)
        digest.overdue_count += count
        digest.overdue_hosts.append(_endpoint_label(endpoint))

    for endpoint in sorted(
        shortened_endpoints, key=lambda value: (value[0], value[1] or 0)
    ):
        digest = _ensure_owner(host_owners.get(endpoint, ""))
        digest.shortened_count += 1
        digest.shortened_hosts.append(_endpoint_label(endpoint))

    for row in problem_rows:
        endpoint = (str(row["hostname"]), int(row["port"]))
        digest = _ensure_owner(str(row["owner_email"] or ""))
        if row["failure_reported_at"] and row["state"] not in {"verified", "cancelled"}:
            digest.failed_count += 1
            digest.failed_entries.append(
                f"{_endpoint_label(endpoint)} at {_fmt_transition(row['failure_reported_at'])}"
            )
        if row["raised_at"] and row["state"] == "not_deployed":
            digest.not_deployed_count += 1
            digest.not_deployed_entries.append(
                f"{_endpoint_label(endpoint)} at {_fmt_transition(row['raised_at'])}"
            )

    expiry_by_label = {
        _endpoint_label(endpoint): value for endpoint, value in current_expiry.items()
    }
    for digest in by_owner.values():
        digest.host_expiry = {
            host: expiry_by_label.get(host)
            for host in (
                *digest.renewed_hosts,
                *digest.overdue_hosts,
                *digest.shortened_hosts,
            )
        }
    return list(by_owner.values())


def _fmt_expiry(not_after: str | None) -> str:
    """Render a cert's not_after as ' (expires YYYY-MM-DD)' or '' if unknown."""
    if not not_after:
        return ""
    try:
        return f" (expires {_parse_iso(not_after).strftime('%Y-%m-%d')})"
    except (ValueError, TypeError):
        return ""


def _fmt_transition(value: str) -> str:
    """Render a durable attempt transition in an unambiguous UTC form."""
    try:
        return _parse_iso(value).astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return "time unavailable"


def _merge_owner_address_variants(
    digests: list[RenewalDigest],
) -> list[RenewalDigest]:
    """Combine digests whose owner addresses differ only by case."""
    merged: dict[str, RenewalDigest] = {}
    for digest in digests:
        key = digest.owner_email.casefold()
        existing = merged.get(key)
        if existing is None:
            merged[key] = digest
            continue
        existing.renewed_count += digest.renewed_count
        existing.overdue_count += digest.overdue_count
        existing.shortened_count += digest.shortened_count
        existing.failed_count += digest.failed_count
        existing.not_deployed_count += digest.not_deployed_count
        for destination, additions in (
            (existing.renewed_hosts, digest.renewed_hosts),
            (existing.overdue_hosts, digest.overdue_hosts),
            (existing.shortened_hosts, digest.shortened_hosts),
            (existing.failed_entries, digest.failed_entries),
            (existing.not_deployed_entries, digest.not_deployed_entries),
        ):
            destination.extend(host for host in additions if host not in destination)
        existing.host_expiry.update(digest.host_expiry)
    return list(merged.values())


def _build_digest_message(digest: RenewalDigest) -> str:
    expiry = digest.host_expiry
    lines = [
        f"[cert-watch] Renewal Digest — last {digest.days} days",
        "",
        f"Renewed on schedule: {digest.renewed_count}",
    ]
    for host in digest.renewed_hosts:
        lines.append(f"  - {host}{_fmt_expiry(expiry.get(host))}")
    lines.extend(("", f"Overdue: {digest.overdue_count}"))
    for host in digest.overdue_hosts:
        lines.append(f"  - {host}{_fmt_expiry(expiry.get(host))}")
    if digest.shortened_hosts:
        lines.extend(("", f"Lifetimes shortened: {digest.shortened_count}"))
        for host in digest.shortened_hosts:
            lines.append(f"  - {host}{_fmt_expiry(expiry.get(host))}")
    if digest.failed_count:
        lines.extend(("", f"Renewal failed: {digest.failed_count}"))
        lines.extend(f"  - {entry}" for entry in digest.failed_entries)
    if digest.not_deployed_count:
        lines.extend(("", f"Reported but not deployed: {digest.not_deployed_count}"))
        lines.extend(f"  - {entry}" for entry in digest.not_deployed_entries)
    return "\n".join(lines)


def _aggregate(digests: list[RenewalDigest], cadence_days: int) -> RenewalDigest:
    return RenewalDigest(
        days=cadence_days,
        renewed_count=sum(digest.renewed_count for digest in digests),
        renewed_hosts=sorted({host for d in digests for host in d.renewed_hosts}),
        overdue_count=sum(digest.overdue_count for digest in digests),
        overdue_hosts=sorted({host for d in digests for host in d.overdue_hosts}),
        shortened_count=sum(digest.shortened_count for digest in digests),
        shortened_hosts=sorted({host for d in digests for host in d.shortened_hosts}),
        host_expiry={host: expiry for d in digests for host, expiry in d.host_expiry.items()},
        failed_count=sum(digest.failed_count for digest in digests),
        failed_entries=sorted(entry for d in digests for entry in d.failed_entries),
        not_deployed_count=sum(digest.not_deployed_count for digest in digests),
        not_deployed_entries=sorted(
            entry for d in digests for entry in d.not_deployed_entries
        ),
    )


@dataclass(frozen=True)
class RenewalDigestKind:
    """Per-owner renewal activity with a global SMTP summary."""

    alert_config: AlertConfig | None
    name: str = "renewal"
    webhook_fanout: Literal["per_target"] = "per_target"

    def targets(
        self,
        db_path: str | Path,
        now: datetime,
        cadence_days: int,
    ) -> list[DigestTarget]:
        digests = _merge_owner_address_variants(
            build_renewal_digest(
                db_path,
                cadence_days=cadence_days,
                now=now,
            )
        )
        if not digests:
            return []

        global_recipients = _valid_recipients(
            self.alert_config.recipients if self.alert_config is not None else []
        )
        global_keys = {recipient.casefold() for recipient in global_recipients}
        targets = [
            DigestTarget(
                key="global",
                payload=_aggregate(digests, cadence_days),
                smtp_recipients=tuple(global_recipients),
                is_global=True,
                webhook_eligible=False,
            )
        ]
        for digest in digests:
            owner = digest.owner_email
            key = owner.casefold() or "_unowned"
            recipients: tuple[str, ...] = ()
            if owner:
                if not _validate_email(owner):
                    logger.warning("skipping invalid owner_email digest: %r", owner)
                elif key not in global_keys:
                    recipients = (owner,)
            targets.append(
                DigestTarget(
                    key=key,
                    payload=digest,
                    smtp_recipients=recipients,
                    webhook_subject=f"Renewal Digest ({cadence_days}d)",
                )
            )
        return targets

    def render(self, target: DigestTarget) -> OutboundMessage:
        digest = target.payload
        if not isinstance(digest, RenewalDigest):
            raise TypeError("renewal target has the wrong payload")
        return OutboundMessage.from_digest(
            subject=(
                f"[cert-watch] Renewal Digest: {digest.renewed_count} renewed, "
                f"{digest.overdue_count} overdue, {digest.failed_count} failed, "
                f"{digest.not_deployed_count} not deployed"
            ),
            body=_build_digest_message(digest),
            severity="renewal_digest",
            idempotency_key="",
            recipients=target.smtp_recipients,
        )


def _valid_recipients(recipients: list[str]) -> list[str]:
    seen: set[str] = set()
    valid: list[str] = []
    for recipient in recipients:
        key = recipient.casefold()
        if not _validate_email(recipient):
            logger.warning("skipping invalid digest recipient: %r", recipient)
        elif key not in seen:
            seen.add(key)
            valid.append(recipient)
    return valid
