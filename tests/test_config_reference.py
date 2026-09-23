"""The settings reference in docs/configuration.md is generated from the code.

A setting without a description, or a reference that no longer matches the
code, fails here rather than drifting silently.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from cert_watch.config.field_docs import FIELD_DOCS, GROUPS, INTERNAL
from cert_watch.config.field_specs import FIELD_SPECS

_ROOT = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_config_reference", _ROOT / "scripts" / "gen_config_reference.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_setting_is_described_or_declared_internal() -> None:
    documented = set(FIELD_DOCS) | set(INTERNAL)
    missing = set(FIELD_SPECS) - documented
    assert missing == set(), "describe new settings in config/field_docs.py"
    stale = documented - set(FIELD_SPECS)
    assert stale == set(), "field_docs.py names a setting that no longer exists"
    assert set(FIELD_DOCS) & set(INTERNAL) == set()


def test_every_described_setting_has_an_operator_source() -> None:
    for name in FIELD_DOCS:
        assert FIELD_SPECS[name].env_names, f"{name} is documented but has no environment variable"


def test_every_group_is_known() -> None:
    assert {group for group, _text in FIELD_DOCS.values()} <= set(GROUPS)


def test_published_reference_is_current() -> None:
    generator = _generator()
    document = (_ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")
    assert generator.splice(document) == document, (
        "docs/configuration.md is stale: run python scripts/gen_config_reference.py"
    )
