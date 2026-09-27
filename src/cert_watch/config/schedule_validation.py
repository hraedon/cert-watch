"""Validation shared by the HTML and JSON scan-schedule adapters."""

from __future__ import annotations

from typing import Any


class ScheduleValidationError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def validate_schedule(hour: Any, minute: Any) -> tuple[int, int]:
    """Return a valid UTC schedule or raise a field-specific error."""

    def bounded_int(field: str, value: Any, low: int, high: int) -> int:
        if isinstance(value, bool):
            raise ScheduleValidationError(
                field, f"{field} must be a whole number between {low} and {high}"
            )
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise ScheduleValidationError(
                field, f"{field} must be a whole number between {low} and {high}"
            ) from None
        if isinstance(value, float) and not value.is_integer():
            raise ScheduleValidationError(
                field, f"{field} must be a whole number between {low} and {high}"
            )
        if isinstance(value, str) and value.strip() != str(parsed):
            raise ScheduleValidationError(
                field, f"{field} must be a whole number between {low} and {high}"
            )
        if not low <= parsed <= high:
            raise ScheduleValidationError(field, f"{field} must be between {low} and {high}")
        return parsed

    return (
        bounded_int("sched_hour", hour, 0, 23),
        bounded_int("sched_min", minute, 0, 59),
    )
