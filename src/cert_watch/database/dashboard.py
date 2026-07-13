"""Dashboard and unified entry queries — re-export shim.

The implementation has been decomposed into focused submodules:

- :mod:`cert_watch.database.dashboard_helpers`  — shared constants + helpers
- :mod:`cert_watch.database.dashboard_rows`      — dashboard row building
- :mod:`cert_watch.database.dashboard_stats`     — urgency-bucket statistics
- :mod:`cert_watch.database.dashboard_unified`   — unified-entry builders + loaders
- :mod:`cert_watch.database.dashboard_page`      — SQL-paginated ungrouped path
- :mod:`cert_watch.database.dashboard_grouped`   — SQL-grouped fingerprint path
- :mod:`cert_watch.database.dashboard_detail`    — single-certificate detail

This module re-exports the full public surface so that existing imports
``from cert_watch.database.dashboard import X`` continue to work unchanged.
"""
from __future__ import annotations

# --- detail ----------------------------------------------------------------
from cert_watch.database.dashboard_detail import get_cert_detail as get_cert_detail

# --- grouped ---------------------------------------------------------------
from cert_watch.database.dashboard_grouped import (
    list_dashboard_grouped_page as list_dashboard_grouped_page,
)

# --- helpers ---------------------------------------------------------------
from cert_watch.database.dashboard_helpers import (
    _SORT_COLUMNS_ALIAS as _SORT_COLUMNS_ALIAS,
)
from cert_watch.database.dashboard_helpers import (
    _SORT_COLUMNS_BARE as _SORT_COLUMNS_BARE,
)
from cert_watch.database.dashboard_helpers import (
    _SORT_COLUMNS_GROUPED as _SORT_COLUMNS_GROUPED,
)
from cert_watch.database.dashboard_helpers import (
    _SQL_DIRS as _SQL_DIRS,
)
from cert_watch.database.dashboard_helpers import (
    _UNIFIED_SORT_KEYS as _UNIFIED_SORT_KEYS,
)
from cert_watch.database.dashboard_helpers import (
    _URGENCY_ORDER as _URGENCY_ORDER,
)
from cert_watch.database.dashboard_helpers import (
    _add_effective_tag_filter as _add_effective_tag_filter,
)
from cert_watch.database.dashboard_helpers import (
    _add_grouped_effective_tag_filter as _add_grouped_effective_tag_filter,
)
from cert_watch.database.dashboard_helpers import (
    _clamp_page as _clamp_page,
)
from cert_watch.database.dashboard_helpers import (
    _entry_matches_scope_tag as _entry_matches_scope_tag,
)
from cert_watch.database.dashboard_helpers import (
    _escape_like as _escape_like,
)
from cert_watch.database.dashboard_helpers import (
    _filter_unified as _filter_unified,
)
from cert_watch.database.dashboard_helpers import (
    _matches_q as _matches_q,
)
from cert_watch.database.dashboard_helpers import (
    _reorder_by_candidates as _reorder_by_candidates,
)
from cert_watch.database.dashboard_helpers import (
    _safe_col as _safe_col,
)
from cert_watch.database.dashboard_helpers import (
    _safe_dir as _safe_dir,
)
from cert_watch.database.dashboard_helpers import (
    _sort_unified as _sort_unified,
)
from cert_watch.database.dashboard_helpers import (
    build_scope_tag_clause as build_scope_tag_clause,
)

# --- page ------------------------------------------------------------------
from cert_watch.database.dashboard_page import (
    list_dashboard_page as list_dashboard_page,
)
from cert_watch.database.dashboard_page import (
    list_unified_entries_page as list_unified_entries_page,
)

# --- rows ------------------------------------------------------------------
from cert_watch.database.dashboard_rows import (
    _build_dashboard_rows as _build_dashboard_rows,
)
from cert_watch.database.dashboard_rows import (
    count_dashboard_leaves as count_dashboard_leaves,
)
from cert_watch.database.dashboard_rows import (
    list_dashboard_rows as list_dashboard_rows,
)

# --- stats -----------------------------------------------------------------
from cert_watch.database.dashboard_stats import (
    dashboard_urgency_stats as dashboard_urgency_stats,
)
from cert_watch.database.dashboard_stats import (
    pivot_urgency_stats as pivot_urgency_stats,
)

# --- unified ---------------------------------------------------------------
from cert_watch.database.dashboard_unified import (
    _build_host_filter as _build_host_filter,
)
from cert_watch.database.dashboard_unified import (
    _build_pending_entries as _build_pending_entries,
)
from cert_watch.database.dashboard_unified import (
    _build_unified_for_leaf_ids as _build_unified_for_leaf_ids,
)
from cert_watch.database.dashboard_unified import (
    _build_unified_from_dash as _build_unified_from_dash,
)
from cert_watch.database.dashboard_unified import (
    _load_unified_filtered as _load_unified_filtered,
)
from cert_watch.database.dashboard_unified import (
    list_unified_entries as list_unified_entries,
)

__all__ = [
    # helpers
    "_URGENCY_ORDER",
    "_SORT_COLUMNS_BARE",
    "_SORT_COLUMNS_ALIAS",
    "_SORT_COLUMNS_GROUPED",
    "_SQL_DIRS",
    "_UNIFIED_SORT_KEYS",
    "_add_effective_tag_filter",
    "build_scope_tag_clause",
    "_add_grouped_effective_tag_filter",
    "_safe_col",
    "_safe_dir",
    "_escape_like",
    "_clamp_page",
    "_reorder_by_candidates",
    "_matches_q",
    "_filter_unified",
    "_sort_unified",
    "_entry_matches_scope_tag",
    # rows
    "_build_dashboard_rows",
    "list_dashboard_rows",
    "count_dashboard_leaves",
    # stats
    "pivot_urgency_stats",
    "dashboard_urgency_stats",
    # unified
    "list_unified_entries",
    "list_unified_entries_page",
    "_build_unified_for_leaf_ids",
    "_build_unified_from_dash",
    "_build_pending_entries",
    "_build_host_filter",
    "_load_unified_filtered",
    # page
    "list_dashboard_page",
    # grouped
    "list_dashboard_grouped_page",
    # detail
    "get_cert_detail",
]
