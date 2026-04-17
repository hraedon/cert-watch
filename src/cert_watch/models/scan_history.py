"""Scan history data models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional


class ScanStatus(Enum):
    """Status of a scan operation."""

    SUCCESS = auto()
    PARTIAL = auto()  # Some hosts failed
    FAILURE = auto()


@dataclass
class ScanHistory:
    """Scan history model representing a scan cycle."""

    id: Optional[int] = None

    # Scan details
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: ScanStatus = ScanStatus.SUCCESS

    # Results summary
    total_hosts: int = 0
    successful_hosts: int = 0
    failed_hosts: int = 0
    updated_certificates: int = 0

    # Error tracking
    error_message: Optional[str] = None
