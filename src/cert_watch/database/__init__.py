"""Database layer package.

Previously a single 1200-line module (`database.py`).  Split into:
- `schema`     – DDL strings, `init_schema()`, migration logic
- `connection` – `_connect`, `_iso`, `_parse_iso`, `_row_to_cert`
- `repo`       – Repository classes (`CertificateRepository`, `AlertRepository`,
                `SqliteHostRepository`, `SqliteTrustAnchorRepository`)
- `queries`    – Dashboard helpers (`list_dashboard_rows`, `list_unified_entries`,
                `count_dashboard_leaves`), `replace_scanned`, `delete_certificate_cascade`,
                `list_alerts_with_subject`, `list_scan_history`, `store_scan_posture`,
                `get_posture_for_cert`

All public names from the monolith are re-exported so external imports
(`from cert_watch.database import X`) continue to work.
"""

# __future__ must stay at the top of the physical file
from __future__ import annotations

from cert_watch.database.connection import _connect, _iso, _parse_iso, _row_to_cert

# Dashboard & utility queries
from cert_watch.database.queries import (
    DriftEvent,
    _total_alerts,
    _total_scan_history,
    count_dashboard_leaves,
    create_drift_alert,
    delete_certificate_cascade,
    detect_drift,
    distinct_tags,
    get_pivot_group_entries,
    get_posture_for_cert,
    get_posture_grades_for_certs,
    get_renewal_history,
    group_entries_by_fingerprint,
    kv_all,
    kv_get,
    kv_set,
    list_alerts_with_subject,
    list_calendar,
    list_cert_history,
    list_dashboard_rows,
    list_fleet_pivot,
    list_grade_trends,
    list_scan_history,
    list_tls_version_trends,
    list_unified_entries,
    list_unified_entries_page,
    purge_old_history,
    record_cert_history,
    replace_scanned,
    store_scan_posture,
)

# Repositories & dataclasses
from cert_watch.database.repo import (
    Alert,
    AlertGroup,
    AlertRepository,
    CertificateRepository,
    HostEntry,
    SqliteAlertGroupRepository,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteTrustAnchorRepository,
    TrustAnchorEntry,
)

# Schema / connection
from cert_watch.database.schema import _BASE_INDEXES, _BASE_TABLES, ensure_base, init_schema

__all__ = [
    # schema
    "init_schema",
    "ensure_base",
    "_BASE_TABLES",
    "_BASE_INDEXES",
    # connection
    "_connect",
    "_iso",
    "_parse_iso",
    "_row_to_cert",
    # repo
    "Alert",
    "AlertGroup",
    "AlertRepository",
    "CertificateRepository",
    "HostEntry",
    "SqliteAlertGroupRepository",
    "SqliteAlertRepository",
    "SqliteCertificateRepository",
    "SqliteHostRepository",
    "SqliteTrustAnchorRepository",
    "TrustAnchorEntry",
    # queries
    "_total_alerts",
    "_total_scan_history",
    "count_dashboard_leaves",
    "create_drift_alert",
    "delete_certificate_cascade",
    "detect_drift",
    "distinct_tags",
    "DriftEvent",
    "get_posture_for_cert",
    "get_posture_grades_for_certs",
    "get_pivot_group_entries",
    "get_renewal_history",
    "group_entries_by_fingerprint",
    "kv_all",
    "kv_get",
    "kv_set",
    "list_alerts_with_subject",
    "list_calendar",
    "list_cert_history",
    "list_dashboard_rows",
    "list_fleet_pivot",
    "list_grade_trends",
    "list_scan_history",
    "list_tls_version_trends",
    "list_unified_entries",
    "list_unified_entries_page",
    "purge_old_history",
    "record_cert_history",
    "replace_scanned",
    "store_scan_posture",
]
