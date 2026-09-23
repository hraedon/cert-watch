"""Regenerate the settings reference in docs/configuration.md.

The reference is built from ``cert_watch.config.field_specs.FIELD_SPECS`` (the
sources, defaults and bounds cert-watch actually uses) and
``cert_watch.config.field_docs`` (what each setting is for). Run it after adding
or changing a setting:

    python scripts/gen_config_reference.py

``tests/test_config_reference.py`` fails when the committed file is stale.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cert_watch.config.field_docs import FIELD_DOCS, GROUPS
from cert_watch.config.field_specs import FIELD_SPECS, FieldSpec

DOC = Path(__file__).resolve().parents[1] / "docs" / "configuration.md"
BEGIN = "<!-- BEGIN GENERATED REFERENCE: scripts/gen_config_reference.py -->"
END = "<!-- END GENERATED REFERENCE -->"

_CALLABLE_DEFAULTS = {
    "data_dir": "`/var/lib/cert-watch`; `%PROGRAMDATA%\\cert-watch` on Windows",
    "instance_id": "host name",
}


def _default(name: str, spec: FieldSpec) -> str:
    if name in _CALLABLE_DEFAULTS:
        return _CALLABLE_DEFAULTS[name]
    value = spec.default
    if callable(value):
        value = value()
    if spec.sensitive or value in (None, "", (), {}):
        return "—"
    if isinstance(value, bool):
        return "`1`" if value else "`0`"
    if isinstance(value, tuple):
        return "`" + ",".join(value) + "`"
    return f"`{value}`"


def _range(spec: FieldSpec) -> str:
    if spec.minimum is None and spec.maximum is None:
        return ""
    low = "" if spec.minimum is None else str(spec.minimum)
    high = "" if spec.maximum is None else str(spec.maximum)
    if low and high:
        return f" Range {low}–{high}."
    return f" Minimum {low}." if low else f" Maximum {high}."


def render() -> str:
    lines: list[str] = [BEGIN, ""]
    for group in GROUPS:
        rows = [
            (name, FIELD_SPECS[name], text)
            for name, (g, text) in FIELD_DOCS.items()
            if g == group
        ]
        if not rows:
            continue
        lines += [f"### {group}", "", "| Variable | Default | In Settings | Description |",
                  "|---|---|:---:|---|"]
        for name, spec, text in rows:
            env = " / ".join(f"`{e}`" for e in spec.env_names)
            if spec.sensitive:
                env += " (also `_FILE`)"
            gui = "yes" if spec.kv_key else ""
            lines.append(f"| {env} | {_default(name, spec)} | {gui} | {text}{_range(spec)} |")
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def splice(document: str) -> str:
    head, _, rest = document.partition(BEGIN)
    _, _, tail = rest.partition(END)
    return head + render() + tail


def main() -> int:
    current = DOC.read_text(encoding="utf-8")
    updated = splice(current)
    if "--check" in sys.argv:
        return 0 if updated == current else 1
    DOC.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
