"""Who an alert reaches: alert groups, host owners and role members.

Shared by the expiry rules, orphan detection, delivery evidence and the offline
routing report, so every surface resolves recipients the same way.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path
from typing import Any

logger = logging.getLogger("cert_watch.alerts")


def _load_host_owner_maps(
    db_path: str | Path,
    *,
    conn: sqlite3.Connection | None = None,
    endpoints: tuple[tuple[str, int], ...] | None = None,
) -> tuple[dict[tuple[str, int], int | None], dict[tuple[str, int], dict[str, Any]]]:
    """Load per-host threshold and owner/contact maps in a single query.

    Shared by ``evaluate_all_certs`` and ``evaluate_renewal_window`` so the
    ``hosts`` table is read once per evaluation path with consistent shaping.
    """
    host_thresholds: dict[tuple[str, int], int | None] = {}
    host_owners: dict[tuple[str, int], dict[str, Any]] = {}
    connection: AbstractContextManager[sqlite3.Connection]
    if conn is None:
        from cert_watch.database import _connect
        connection = _connect(db_path)
    else:
        connection = nullcontext(conn)
    with connection as active_conn:
        sql = "SELECT * FROM hosts"
        params: list[Any] = []
        if endpoints is not None:
            if not endpoints:
                return {}, {}
            sql += " WHERE " + " OR ".join(
                "(hostname = ? AND port = ?)" for _ in endpoints
            )
            params = [value for endpoint in endpoints for value in endpoint]
        for row in active_conn.execute(sql, params).fetchall():
            key = (row["hostname"], row["port"])
            d = dict(row)
            host_thresholds[key] = d.get("threshold_days")
            host_owners[key] = {
                "owner_name": d.get("owner_name", ""),
                "owner_email": d.get("owner_email", ""),
                "owner_slack": d.get("owner_slack", ""),
                "renewal_status": d.get("renewal_status", "pending"),
            }
    return host_thresholds, host_owners


def _load_role_user_emails(
    db_path: str | Path, *, conn: sqlite3.Connection | None = None,
) -> dict[str, list[str]]:
    """Map a role's team email (casefolded) → emails of users in that role.

    Used to fan alert routing out to the human members of a team whose address
    matches a host's ``owner_email``. Returns an empty map if the users/roles
    tables are unavailable (local-auth disabled), so routing degrades quietly.
    """
    role_user_emails: dict[str, list[str]] = {}
    try:
        connection: AbstractContextManager[sqlite3.Connection]
        if conn is None:
            from cert_watch.database import _connect
            connection = _connect(db_path)
        else:
            connection = nullcontext(conn)
        with connection as active_conn:
            roles = active_conn.execute("SELECT id, email FROM roles").fetchall()
            users = active_conn.execute(
                "SELECT email, role_id FROM users WHERE email != ''"
            ).fetchall()
        for role in roles:
            if not role["email"]:
                continue
            members = [
                user["email"] for user in users if user["role_id"] == role["id"]
            ]
            if members:
                role_user_emails[role["email"].casefold()] = members
    except (ImportError, sqlite3.Error):
        logger.warning("Role-based alert routing unavailable", exc_info=True)
        return {}
    return role_user_emails


def resolve_cert_recipients(
    group_recipients: list[str],
    owner_info: dict[str, Any] | None,
    role_user_emails: dict[str, list[str]],
) -> list[str]:
    """Merge a cert's alert-group recipients, host owner, and role members into a
    single order-preserving, deduplicated recipient list.

    This is the **one source of truth** for *who* an expiry alert for a cert
    reaches (beyond the global ``AlertConfig.recipients`` applied at send time).
    ``evaluate_all_certs`` uses it to populate ``extra_recipients``; orphan
    detection uses it to decide whether a cert routes to anyone specific. Keep
    dedup exact-string to match the downstream dedup in ``send_alert``.
    """
    merged: list[str] = list(group_recipients)
    owner_email = owner_info.get("owner_email") if owner_info else None
    if owner_email:
        if owner_email not in merged:
            merged.append(owner_email)
        for member in role_user_emails.get(owner_email.casefold(), []):
            if member not in merged:
                merged.append(member)
    return merged


def find_orphan_certs(db_path: str | Path) -> list[dict[str, Any]]:
    """Return leaf certs that resolve to **zero** specific recipients.

    An orphan matches no alert group and has no host ``owner_email`` (so no role
    members either). Such a cert is not dropped — at send time it still falls
    back to the global ``AlertConfig.recipients`` — but nothing routes it to a
    *named* owner or team, so it is the cert most likely to be silently
    forgotten. Surfaced in the admin renewal digest (Plan 050, decision pinned
    2026-06-20).

    Returns a list of ``{"cert_id", "hostname", "port", "subject"}`` dicts,
    ordered by hostname then subject, using the same routing resolver as the
    delivery path so the report can't drift from reality.
    """
    from cert_watch.database import _connect

    all_group_recipients, _ = _resolve_group_config(db_path)
    role_user_emails = _load_role_user_emails(db_path)
    _host_thresholds, host_owners = _load_host_owner_maps(db_path)

    with _connect(db_path) as conn:
        leaves = conn.execute(
            "SELECT id, subject, hostname, port FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    orphans: list[dict[str, Any]] = []
    for row in leaves:
        owner_info = host_owners.get((row["hostname"], row["port"]))
        recipients = resolve_cert_recipients(
            all_group_recipients.get(row["id"], []), owner_info, role_user_emails
        )
        if not recipients:
            orphans.append({
                "cert_id": row["id"],
                "hostname": row["hostname"] or "",
                "port": row["port"],
                "subject": row["subject"] or "",
            })
    orphans.sort(key=lambda o: (o["hostname"], o["subject"]))
    return orphans


def _resolve_group_config(
    db_path: str | Path,
    *,
    matched_groups: dict[str, list[str]] | None = None,
    cert_ids: tuple[str, ...] | None = None,
    conn: sqlite3.Connection | None = None,
) -> tuple[dict[str, list[str]], dict[str, int | None]]:
    """Single-pass resolution of alert-group recipients and threshold overrides.

    Returns (recipients_map, thresholds_map) where:
    - recipients_map: {cert_id: [deduplicated recipients]} for all matching certs
    - thresholds_map: {cert_id: min threshold_days} for certs matching groups
      that have threshold_days set (absent when no group with threshold_days matches)

    Performs the 3 SQL queries (groups, cert tags, manual assignments) once
    instead of duplicating them across resolve_all_group_recipients and
    resolve_group_thresholds.

    Role→alert-group link (WI-061): roles with a non-empty ``scope_tag`` and
    a linked ``alert_group_id`` also route alerts for certs whose effective
    tags intersect the role's scope tags.  The linked alert_group's
    recipients and threshold are included as if the group had matched.

    When supplied, matched_groups records the groups selected by these same
    branches, including empty-recipient groups. This lets the offline routing
    report explain matches without implementing another matching algorithm.
    """
    from cert_watch.tags import merge_tags, parse_tags, tags_match

    if cert_ids == ():
        return {}, {}
    placeholders = ",".join("?" for _ in cert_ids) if cert_ids is not None else ""
    cert_filter = f" AND c.id IN ({placeholders})" if cert_ids is not None else ""
    assignment_filter = f" WHERE cert_id IN ({placeholders})" if cert_ids is not None else ""
    params = cert_ids or ()
    connection: AbstractContextManager[sqlite3.Connection]
    if conn is None:
        from cert_watch.database.connection import _connect
        connection = _connect(db_path)
    else:
        connection = nullcontext(conn)
    with connection as active_conn:
        groups = [
            {
                "id": row["id"],
                "recipients": [r.strip() for r in row["recipients"].split(",") if r.strip()],
                "match_tags": parse_tags(row["match_tags"]),
                "threshold_days": row["threshold_days"],
            }
            for row in active_conn.execute(
                "SELECT id, recipients, match_tags, threshold_days FROM alert_groups"
            ).fetchall()
        ]
        if not groups:
            return {}, {}

        cert_tags_rows = active_conn.execute(
            """SELECT c.id, c.tags, h.tags AS host_tags
               FROM certificates c
               LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port
               WHERE c.is_leaf = 1""" + cert_filter, params,
        ).fetchall()
        cert_tags = {
            row["id"]: merge_tags(row["tags"], row["host_tags"])
            for row in cert_tags_rows
        }

        manual_rows = active_conn.execute(
            "SELECT cert_id, group_id FROM alert_group_certs" + assignment_filter, params,
        ).fetchall()
        manual_map: dict[str, set[str]] = {}
        for row in manual_rows:
            manual_map.setdefault(row["cert_id"], set()).add(row["group_id"])

    # Role→alert-group links (WI-061): load roles that have both a
    # scope_tag and a linked alert_group_id, so their linked group's
    # recipients are included for matching certs.
    role_links: list[dict[str, Any]] = []
    try:
        role_connection: AbstractContextManager[sqlite3.Connection]
        if conn is None:
            from cert_watch.database.connection import _connect
            role_connection = _connect(db_path)
        else:
            role_connection = nullcontext(conn)
        with role_connection as active_conn:
            role_rows = active_conn.execute(
                "SELECT alert_group_id, scope_tag FROM roles"
            ).fetchall()
        for role in role_rows:
            if role["alert_group_id"] and role["scope_tag"]:
                role_links.append({
                    "alert_group_id": role["alert_group_id"],
                    "scope_tags": parse_tags(role["scope_tag"]),
                })
    except (sqlite3.OperationalError, sqlite3.DatabaseError, ImportError):
        logger.warning("Role→alert-group link routing unavailable", exc_info=True)
        role_links = []

    group_by_id = {g["id"]: g for g in groups}

    recipients_map: dict[str, list[str]] = {}
    thresholds_map: dict[str, int | None] = {}
    for cert_id, effective in cert_tags.items():
        seen: set[str] = set()
        out: list[str] = []
        manual_ids = manual_map.get(cert_id, set())
        for g in groups:
            if g["id"] in manual_ids or tags_match(effective, g["match_tags"]):
                if matched_groups is not None:
                    matched_groups.setdefault(cert_id, []).append(g["id"])
                for r in g["recipients"]:
                    rc = r.casefold()
                    if rc not in seen:
                        seen.add(rc)
                        out.append(r)
                td = g["threshold_days"]
                if td is not None:
                    existing = thresholds_map.get(cert_id)
                    if existing is None or td < existing:
                        thresholds_map[cert_id] = td

        # Role-linked alert groups (WI-061): match certs against role
        # scope_tags and include the linked alert_group's recipients.
        for rl in role_links:
            if tags_match(effective, rl["scope_tags"]):
                lg = group_by_id.get(rl["alert_group_id"])
                if lg is None:
                    continue
                if matched_groups is not None:
                    selected = matched_groups.setdefault(cert_id, [])
                    if lg["id"] not in selected:
                        selected.append(lg["id"])
                for r in lg["recipients"]:
                    rc = r.casefold()
                    if rc not in seen:
                        seen.add(rc)
                        out.append(r)
                td = lg["threshold_days"]
                if td is not None:
                    existing = thresholds_map.get(cert_id)
                    if existing is None or td < existing:
                        thresholds_map[cert_id] = td

        if out:
            recipients_map[cert_id] = out
    return recipients_map, thresholds_map


def resolve_routing(
    db_path: str | Path,
    cert_ids: tuple[str, ...],
    *,
    conn: sqlite3.Connection | None = None,
) -> dict[str, dict[str, Any]]:
    """Resolve immutable, versioned routing snapshots for certificate IDs."""
    if not cert_ids:
        return {}
    # Keep every ``IN`` list below SQLite's conservative parameter ceiling.
    # This also gives status/filter callers one supported batch API for large
    # estates instead of reimplementing recipient matching (#126 S1).
    if len(cert_ids) > 350:
        resolved: dict[str, dict[str, Any]] = {}
        for start in range(0, len(cert_ids), 350):
            resolved.update(
                resolve_routing(db_path, cert_ids[start : start + 350], conn=conn)
            )
        return resolved
    placeholders = ",".join("?" for _ in cert_ids)
    connection: AbstractContextManager[sqlite3.Connection]
    if conn is None:
        from cert_watch.database.connection import _connect
        connection = _connect(db_path)
    else:
        connection = nullcontext(conn)
    with connection as active_conn:
        cert_rows = active_conn.execute(
            f"SELECT id, hostname, port FROM certificates WHERE id IN ({placeholders})",
            cert_ids,
        ).fetchall()
        group_rows = active_conn.execute(
            "SELECT id, name FROM alert_groups"
        ).fetchall()
    endpoints = {
        row["id"]: (row["hostname"], row["port"]) for row in cert_rows
    }
    endpoint_keys = tuple(
        dict.fromkeys(
            (str(hostname), int(port))
            for hostname, port in endpoints.values()
            if hostname is not None and port is not None
        )
    )
    matched_groups: dict[str, list[str]] = {}
    group_recipients, group_thresholds = _resolve_group_config(
        db_path, matched_groups=matched_groups, cert_ids=cert_ids, conn=conn,
    )
    _, owners = _load_host_owner_maps(db_path, conn=conn, endpoints=endpoint_keys)
    role_members = _load_role_user_emails(db_path, conn=conn)
    group_names = {row["id"]: row["name"] for row in group_rows}
    snapshots: dict[str, dict[str, Any]] = {}
    for cert_id in cert_ids:
        endpoint = endpoints.get(cert_id)
        owner = owners.get(endpoint) if endpoint else None
        recipients = resolve_cert_recipients(
            group_recipients.get(cert_id, []), owner, role_members,
        )
        snapshots[cert_id] = {
            "version": 1,
            "recipients": recipients,
            "groups": [
                {"id": group_id, "name": group_names.get(group_id, "(deleted group)")}
                for group_id in matched_groups.get(cert_id, [])
            ],
            "threshold_days": group_thresholds.get(cert_id),
        }
    return snapshots


def resolve_all_group_recipients(
    db_path: str | Path,
) -> dict[str, list[str]]:
    """Return {cert_id: [recipients]} for all leaf certs in one pass.

    Uses three targeted SQL queries instead of per-cert N+1 resolution.
    Results are identical to calling resolve_group_recipients() per cert.
    """
    recipients_map, _ = _resolve_group_config(db_path)
    return recipients_map


def resolve_group_thresholds(
    db_path: str | Path,
) -> dict[str, int | None]:
    """Return {cert_id: threshold_days} for certs matching groups with threshold_days set.

    When a cert matches multiple groups with threshold_days, the most urgent
    (smallest) threshold wins. Certs matching only groups without threshold_days
    are absent from the result (caller falls back to per-host or global defaults).
    """
    _, thresholds_map = _resolve_group_config(db_path)
    return thresholds_map


def resolve_group_recipients(
    db_path: str | Path,
    cert_id: str,
) -> list[str]:
    """Resolve alert-group recipients for a single cert (delegates to the batch path).

    Kept as a thin wrapper so callers that need one cert's recipients get the
    exact same result as the batch resolver — the two paths cannot diverge.
    """
    return resolve_all_group_recipients(db_path).get(cert_id, [])
