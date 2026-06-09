"""Database layer package.

Previously a single 1200-line module (`database.py`).  Split into:
- `schema`     – DDL strings, `init_schema()`, migration logic
- `connection` – `_connect`, `_iso`, `_parse_iso`, `_row_to_cert`
- `repo`       – Repository classes (`CertificateRepository`, `AlertRepository`,
                 `SqliteHostRepository`, `SqliteTrustAnchorRepository`)
- `queries`    – Re-export layer (BC-094 decomposition into submodules)

All public names are re-exported so external imports
(`from cert_watch.database import X`) continue to work.
"""

# __future__ must stay at the top of the physical file
from __future__ import annotations

# API keys (Plan 039)
from cert_watch.database.api_keys import (
    ApiKeyAuth,
    ApiKeyEntry,
    SqliteApiKeyRepository,
)

# Calendar
from cert_watch.database.calendar import list_calendar

# Certificate operations
from cert_watch.database.cert_ops import (
    _compute_renewal_diff,
    delete_certificate_cascade,
    distinct_tags,
    get_renewal_history,
    replace_scanned,
)
from cert_watch.database.connection import _connect, _iso, _parse_iso, _row_to_cert

# Dashboard
from cert_watch.database.dashboard import (
    _build_dashboard_rows,
    _build_host_filter,
    _build_pending_entries,
    _build_unified_for_leaf_ids,
    _build_unified_from_dash,
    _clamp_page,
    _escape_like,
    _filter_unified,
    _load_unified_filtered,
    _matches_q,
    _reorder_by_candidates,
    _sort_unified,
    count_dashboard_leaves,
    get_cert_detail,
    list_dashboard_grouped_page,
    list_dashboard_page,
    list_dashboard_rows,
    list_unified_entries,
    list_unified_entries_page,
)

# Drift + cert_history
from cert_watch.database.drift import (
    DriftEvent,
    _compute_drift_events,
    _drift_summary,
    _extract_key_algo,
    _extract_sig_algo,
    _grade_value,
    _is_sha1_algo,
    _parse_key_algo,
    _tls_value,
    create_drift_alert,
    detect_drift,
    list_cert_history,
    list_grade_trends,
    list_tls_version_trends,
    purge_old_history,
    record_cert_history,
)

# Encryption
from cert_watch.database.encryption import (
    _ENCRYPTED_PREFIX,
    check_encrypted_values,
    derive_encryption_key,
    fernet_decrypt,
    fernet_encrypt,
    re_encrypt_kv_store,
)

# Fleet
from cert_watch.database.fleet import (
    get_pivot_group_entries,
    group_entries_by_fingerprint,
    list_fleet_pivot,
)

# kv_store
from cert_watch.database.kv_store import (
    kv_all,
    kv_get,
    kv_set,
    kv_set_secret,
)

# Pagination
from cert_watch.database.pagination import (
    _count_alerts_by_filter,
    _total_alerts,
    _total_scan_history,
    list_alerts_with_subject,
    list_scan_batches,
    list_scan_history,
    purge_old_alerts,
)

# Posture
from cert_watch.database.posture import (
    get_posture_for_cert,
    get_posture_for_certs,
    get_posture_grades_for_certs,
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

# Session versions
from cert_watch.database.session_versions import (
    bump_session_version,
    get_session_version,
)

# Users & Roles (Plan 040)
from cert_watch.database.users_roles import (
    Role,
    SqliteRoleRepository,
    SqliteUserRepository,
    User,
)

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
    # api keys
    "ApiKeyAuth",
    "ApiKeyEntry",
    "SqliteApiKeyRepository",
    # encryption
    "_ENCRYPTED_PREFIX",
    "derive_encryption_key",
    "fernet_decrypt",
    "fernet_encrypt",
    "check_encrypted_values",
    "re_encrypt_kv_store",
    # cert_ops
    "distinct_tags",
    "replace_scanned",
    "delete_certificate_cascade",
    "get_renewal_history",
    "_compute_renewal_diff",
    # drift
    "DriftEvent",
    "_compute_drift_events",
    "_drift_summary",
    "_extract_key_algo",
    "_extract_sig_algo",
    "_grade_value",
    "_is_sha1_algo",
    "_parse_key_algo",
    "_tls_value",
    "detect_drift",
    "create_drift_alert",
    "record_cert_history",
    "purge_old_history",
    "list_cert_history",
    "list_tls_version_trends",
    "list_grade_trends",
    # dashboard
    "_build_dashboard_rows",
    "_build_host_filter",
    "_build_pending_entries",
    "_build_unified_for_leaf_ids",
    "_build_unified_from_dash",
    "_clamp_page",
    "_escape_like",
    "_filter_unified",
    "_load_unified_filtered",
    "_matches_q",
    "_reorder_by_candidates",
    "_sort_unified",
    "count_dashboard_leaves",
    "get_cert_detail",
    "list_dashboard_grouped_page",
    "list_dashboard_page",
    "list_dashboard_rows",
    "list_unified_entries",
    "list_unified_entries_page",
    # posture
    "store_scan_posture",
    "get_posture_for_cert",
    "get_posture_grades_for_certs",
    "get_posture_for_certs",
    # kv_store
    "kv_all",
    "kv_get",
    "kv_set",
    "kv_set_secret",
    # session_versions
    "get_session_version",
    "bump_session_version",
    # users & roles
    "Role",
    "User",
    "SqliteRoleRepository",
    "SqliteUserRepository",
    # pagination
    "_count_alerts_by_filter",
    "_total_alerts",
    "_total_scan_history",
    "list_alerts_with_subject",
    "list_scan_batches",
    "list_scan_history",
    "purge_old_alerts",
    # fleet
    "list_fleet_pivot",
    "get_pivot_group_entries",
    "group_entries_by_fingerprint",
    # calendar
    "list_calendar",
]
