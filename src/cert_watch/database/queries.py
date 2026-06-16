"""Dashboard and utility queries.

BC-094: This module is now a thin re-export layer. All functions have been
moved to concern-specific submodules:

- ``encryption``     – at-rest encryption (derive_encryption_key, fernet_encrypt, …)
- ``cert_ops``       – certificate store operations (replace_scanned, delete_certificate_cascade, …)
- ``drift``          – drift detection + cert_history
- ``dashboard``      – dashboard + unified entry queries
- ``posture``        – posture evaluation storage/retrieval
- ``kv_store``       – kv_store helpers
- ``session_versions`` – session token revocation versions
- ``pagination``     – alert / scan history pagination
- ``fleet``          – fleet pivot + grouping
- ``calendar``       – calendar view queries

New code should import from the specific submodule; the re-exports here are
for backward compatibility with existing imports.
"""
from __future__ import annotations

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

# Connection helpers (backward compat for test imports)
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
    pivot_urgency_stats,
)

# Drift detection + cert_history
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

# Session versions
from cert_watch.database.session_versions import (
    bump_session_version,
    get_session_version,
)

__all__ = [
    # connection (backward compat)
    "_connect",
    "_iso",
    "_parse_iso",
    "_row_to_cert",
    # encryption
    "_ENCRYPTED_PREFIX",
    "check_encrypted_values",
    "derive_encryption_key",
    "fernet_decrypt",
    "fernet_encrypt",
    "re_encrypt_kv_store",
    # cert_ops
    "_compute_renewal_diff",
    "delete_certificate_cascade",
    "distinct_tags",
    "get_renewal_history",
    "replace_scanned",
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
    "create_drift_alert",
    "detect_drift",
    "list_cert_history",
    "list_grade_trends",
    "list_tls_version_trends",
    "purge_old_history",
    "record_cert_history",
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
    "pivot_urgency_stats",
    # posture
    "get_posture_for_cert",
    "get_posture_for_certs",
    "get_posture_grades_for_certs",
    "store_scan_posture",
    # kv_store
    "kv_all",
    "kv_get",
    "kv_set",
    "kv_set_secret",
    # session_versions
    "bump_session_version",
    "get_session_version",
    # pagination
    "_count_alerts_by_filter",
    "_total_alerts",
    "_total_scan_history",
    "list_alerts_with_subject",
    "list_scan_batches",
    "list_scan_history",
    "purge_old_alerts",
    # fleet
    "get_pivot_group_entries",
    "group_entries_by_fingerprint",
    "list_fleet_pivot",
    # calendar
    "list_calendar",
]
