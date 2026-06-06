"""Shared helpers for route modules."""

from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from cert_watch.config import Settings
from cert_watch.filters import register_filters

_CSV_DANGEROUS_PREFIXES = frozenset({"=", "+", "-", "@", "\t", "\r", "\n"})

# Single shared templates instance avoids repeated setup across route modules.
_BASE_DIR = Path(__file__).parent.parent
_templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))
register_filters(_templates)


def get_templates() -> Jinja2Templates:
    """Return the shared Jinja2Templates instance."""
    return _templates


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
