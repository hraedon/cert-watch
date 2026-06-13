"""cert-watch configuration — re-exported from the decomposed package.

Decomposed from the monolithic config.py (BC-144a / config decomposition).
All imports remain backward-compatible: ``from cert_watch.config import Settings``
works exactly as before.
"""

from cert_watch.config.helpers import (
    SENSITIVE_SETTING_KEYS,
    _default_data_dir,
    _default_data_dir_str,
    _parse_float,
    _parse_int,
    _parse_role_map,
    _validate_range,
    read_secret,
    resolve_or_persist_secret,
    split_group_dns,
)
from cert_watch.config.settings import Settings

__all__ = [
    "Settings",
    "read_secret",
    "resolve_or_persist_secret",
    "SENSITIVE_SETTING_KEYS",
    "split_group_dns",
    "_default_data_dir",
    "_default_data_dir_str",
    "_parse_float",
    "_parse_int",
    "_parse_role_map",
    "_validate_range",
]
