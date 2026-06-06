"""Shared helpers for route modules."""

from __future__ import annotations

from fastapi import Request

from cert_watch.config import Settings

_CSV_DANGEROUS_PREFIXES = frozenset({"=", "+", "-", "@", "\t", "\r", "\n"})


def _get_settings(request: Request) -> Settings:
    """Return the resolved Settings from app state."""
    return request.app.state.settings  # type: ignore[no-any-return]


def _db_path(request: Request) -> str:
    return str(_get_settings(request).db_path)


def _csv_safe(value: object) -> str:
    """Escape a value so it can't inject Excel formulas in CSV exports."""
    s = str(value) if value is not None else ""
    if s and s[0] in _CSV_DANGEROUS_PREFIXES:
        return "'" + s
    return s
