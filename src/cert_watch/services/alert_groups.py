"""Application service for alert-group CRUD shared by HTML and JSON adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.audit import record_audit
from cert_watch.database import SqliteAlertGroupRepository, get_write_lock
from cert_watch.database.repo import AlertGroup


class AlertGroupNotFoundError(LookupError):
    """The requested alert group does not exist."""


class AlertGroupConflictError(ValueError):
    """An alert-group name is already in use."""


def _ensure_admin(auth: Any) -> None:
    if auth is not None and not getattr(auth, "is_admin", False):
        raise PermissionError("admin required")


def create_alert_group(
    db_path: str | Path,
    *,
    name: str,
    recipients: list[str],
    match_tags: list[str],
    webhook_url: str,
    threshold_days: int | None,
    digest_cadence_days: int,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> AlertGroup:
    _ensure_admin(auth)
    repo = SqliteAlertGroupRepository(db_path)
    with get_write_lock():
        if repo.get_by_name(name):
            raise AlertGroupConflictError(f"alert group '{name}' already exists")
        group_id = repo.create(
            name,
            recipients,
            match_tags,
            webhook_url,
            threshold_days=threshold_days,
            digest_cadence_days=digest_cadence_days,
        )
    record_audit(
        db_path,
        actor=actor,
        action="alert_group.create",
        target_type="alert_group",
        target_id=group_id,
        detail={
            "name": name,
            "recipients": recipients,
            "match_tags": match_tags,
            "threshold_days": threshold_days,
            "digest_cadence_days": digest_cadence_days,
        },
        source_ip=source_ip,
    )
    group = repo.get(group_id)
    assert group is not None
    return group


def update_alert_group(
    db_path: str | Path,
    group_id: str,
    *,
    name: str | None,
    recipients: list[str] | None,
    match_tags: list[str] | None,
    webhook_url: str | None,
    threshold_days: int | object | None,
    digest_cadence_days: int | None,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> AlertGroup:
    _ensure_admin(auth)
    repo = SqliteAlertGroupRepository(db_path)
    with get_write_lock():
        if repo.get(group_id) is None:
            raise AlertGroupNotFoundError("alert group not found")
        if name is not None:
            existing = repo.get_by_name(name)
            if existing is not None and existing.id != group_id:
                raise AlertGroupConflictError(f"alert group '{name}' already exists")
        repo.update(
            group_id,
            name=name,
            recipients=recipients,
            match_tags=match_tags,
            webhook_url=webhook_url,
            threshold_days=threshold_days,
            digest_cadence_days=digest_cadence_days,
        )
    detail: dict[str, object] = {}
    for key, value in {
        "name": name,
        "recipients": recipients,
        "match_tags": match_tags,
        "webhook_url": webhook_url,
        "digest_cadence_days": digest_cadence_days,
    }.items():
        if value is not None:
            detail[key] = value
    if threshold_days is not SqliteAlertGroupRepository._UNSET:
        detail["threshold_days"] = threshold_days
    record_audit(
        db_path,
        actor=actor,
        action="alert_group.update",
        target_type="alert_group",
        target_id=group_id,
        detail=detail,
        source_ip=source_ip,
    )
    group = repo.get(group_id)
    assert group is not None
    return group


def delete_alert_group(
    db_path: str | Path,
    group_id: str,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> AlertGroup:
    _ensure_admin(auth)
    repo = SqliteAlertGroupRepository(db_path)
    with get_write_lock():
        group = repo.get(group_id)
        if group is None:
            raise AlertGroupNotFoundError("alert group not found")
        repo.delete(group_id)
    record_audit(
        db_path,
        actor=actor,
        action="alert_group.delete",
        target_type="alert_group",
        target_id=group_id,
        detail={"name": group.name},
        source_ip=source_ip,
    )
    return group
