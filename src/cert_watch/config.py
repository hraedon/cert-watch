"""Backward-compat shim for the decomposed config package.

All real code lives in ``cert_watch.config.*`` (settings, helpers, kv_loader).
This file re-exports the public API so existing imports continue to work.

BC-144a / config decomposition.
"""

from cert_watch.config import (  # noqa: F401
    SENSITIVE_SETTING_KEYS,
    read_secret,
    resolve_or_persist_secret,
    split_group_dns,
)
from cert_watch.config.helpers import (  # noqa: F401
    _default_data_dir,
    _default_data_dir_str,
    _parse_float,
    _parse_int,
    _parse_role_map,
)
from cert_watch.config.settings import Settings  # noqa: F401
