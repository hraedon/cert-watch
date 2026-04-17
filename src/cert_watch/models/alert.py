"""Alert data models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto


class AlertType(Enum):
    """Type of alert."""

    EXPIRY_WARNING = auto()
    EXPIRED = auto()
    SCAN_FAILURE = auto()


class AlertStatus(Enum):
    """Status of alert."""

    PENDING = auto()
    SENT = auto()
    FAILED = auto()


@dataclass
class Alert:
    """Alert model representing a sent or pending alert."""

    id: int | None = None

    # Reference
    certificate_id: int = 0

    # Alert details
    alert_type: AlertType = AlertType.EXPIRY_WARNING
    days_remaining: int = 0
    status: AlertStatus = AlertStatus.PENDING

    # Email tracking
    recipient: str = ""
    subject: str = ""
    body: str = ""
    error_message: str | None = None

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    sent_at: datetime | None = None
