"""Alert service implementation for FR-04.

Provides business logic for email alerts at configured thresholds.
"""

import smtplib
from email.mime.text import MIMEText

from ..core.config import Settings
from ..core.exceptions import AlertSendError, SMTPConfigurationError
from ..core.formatters import format_datetime
from ..models.alert import Alert, AlertStatus, AlertType
from ..models.certificate import CertificateType
from ..repositories.base import AlertRepository, CertificateRepository
from ..repositories.sqlite import SQLiteConnectionPool
from .base import AlertService


class AlertServiceImpl(AlertService):
    """Service for alert business logic."""

    def __init__(
        self,
        cert_repo: CertificateRepository | None = None,
        alert_repo: AlertRepository | None = None,
        settings: Settings | None = None,
    ):
        """Initialize the alert service.

        Args:
            cert_repo: Certificate repository. If None, creates from settings.
            alert_repo: Alert repository. If None, creates from settings.
            settings: Application settings. If None, uses Settings.get().
        """
        self._settings = settings or Settings.get()
        self._cert_repo = cert_repo
        self._alert_repo = alert_repo

    def _get_cert_repo(self) -> CertificateRepository:
        """Get certificate repository, creating if needed."""
        if self._cert_repo is None:
            from ..repositories.sqlite import SQLiteCertificateRepository

            pool = SQLiteConnectionPool(self._settings.database_path)
            self._cert_repo = SQLiteCertificateRepository(pool)
        return self._cert_repo

    def _get_alert_repo(self) -> AlertRepository:
        """Get alert repository, creating if needed."""
        if self._alert_repo is None:
            from ..repositories.sqlite import SQLiteAlertRepository

            pool = SQLiteConnectionPool(self._settings.database_path)
            self._alert_repo = SQLiteAlertRepository(pool)
        return self._alert_repo

    async def evaluate_alerts(self) -> list[int]:
        """Evaluate all certificates and create pending alerts.

        Checks certificates against configured thresholds and creates
        pending alerts for those that have reached alert thresholds.

        Returns:
            List of created alert IDs
        """
        cert_repo = self._get_cert_repo()
        alert_repo = self._get_alert_repo()

        # Get all certificates
        certificates = await cert_repo.get_all()

        created_alert_ids: list[int] = []

        for cert in certificates:
            # Determine thresholds based on certificate type
            if cert.certificate_type == CertificateType.LEAF:
                thresholds = self._settings.leaf_alert_thresholds
            else:
                thresholds = self._settings.chain_alert_thresholds

            days_remaining = cert.days_remaining

            # Check if certificate has expired
            if days_remaining < 0:
                # Check if we already have an EXPIRED alert
                existing_alerts = await alert_repo.get_for_certificate(cert.id)
                expired_alert_exists = any(
                    a.alert_type == AlertType.EXPIRED and a.status == AlertStatus.SENT
                    for a in existing_alerts
                )

                if not expired_alert_exists:
                    # Create expired alert
                    alert = Alert(
                        certificate_id=cert.id,
                        alert_type=AlertType.EXPIRED,
                        days_remaining=days_remaining,
                        status=AlertStatus.PENDING,
                        recipient=self._get_primary_recipient(),
                        subject=f"CRITICAL: Certificate Has Expired - {cert.display_name}",
                        body=self._format_expired_email_body(cert),
                    )
                    created = await alert_repo.create(alert)
                    created_alert_ids.append(created.id)
                continue

            # Check each threshold (ascending order so smallest applicable threshold matches first)
            for threshold in sorted(thresholds):
                if days_remaining <= threshold:
                    # Check if alert already sent for this threshold
                    existing_alerts = await alert_repo.get_for_certificate(cert.id)
                    alert_exists = any(
                        a.days_remaining == threshold and a.status == AlertStatus.SENT
                        for a in existing_alerts
                    )

                    if not alert_exists:
                        # Create alert for this threshold
                        alert = Alert(
                            certificate_id=cert.id,
                            alert_type=AlertType.EXPIRY_WARNING,
                            days_remaining=threshold,
                            status=AlertStatus.PENDING,
                            recipient=self._get_primary_recipient(),
                            subject=self._format_alert_subject(cert, threshold),
                            body=self._format_alert_body(cert, threshold),
                        )
                        created = await alert_repo.create(alert)
                        created_alert_ids.append(created.id)

                    # Only create one alert per evaluation (the highest threshold hit)
                    break

        return created_alert_ids

    async def send_pending_alerts(self) -> tuple[int, int]:
        """Send all pending alerts.

        Returns:
            Tuple of (sent_count, failed_count)
        """
        alert_repo = self._get_alert_repo()

        # Get all pending alerts
        pending_alerts = await alert_repo.get_pending()

        if not pending_alerts:
            return (0, 0)

        # Check SMTP configuration
        if not self._validate_smtp_config():
            # Mark all as failed due to config error
            for alert in pending_alerts:
                await alert_repo.mark_failed(alert.id, "SMTP not configured")
            return (0, len(pending_alerts))

        sent_count = 0
        failed_count = 0

        for alert in pending_alerts:
            try:
                await self._send_alert_email(alert)
                await alert_repo.mark_sent(alert.id)
                sent_count += 1
            except Exception as e:
                await alert_repo.mark_failed(alert.id, str(e))
                failed_count += 1

        return (sent_count, failed_count)

    def _validate_smtp_config(self) -> bool:
        """Check if SMTP is properly configured."""
        return all(
            [
                self._settings.smtp_host,
                self._settings.smtp_from_addr,
                self._settings.alert_recipients,
            ]
        )

    def _get_primary_recipient(self) -> str:
        """Get the primary alert recipient."""
        if self._settings.alert_recipients:
            return self._settings.alert_recipients[0]
        return ""

    def _get_all_recipients(self) -> list[str]:
        """Get all alert recipients."""
        return self._settings.alert_recipients or []

    def _format_alert_subject(self, cert, threshold: int) -> str:
        """Format alert email subject line."""
        urgency = "URGENT" if threshold <= 3 else "WARNING"
        return f"{urgency}: Certificate Expires in {threshold} Days - {cert.display_name}"

    def _format_alert_body(self, cert, threshold: int) -> str:
        """Format alert email body."""
        return f"""Certificate Expiry Alert

Hostname: {cert.display_name}
Subject: {cert.subject}
Issuer: {cert.issuer}
Expiry: {format_datetime(cert.not_after)}
Days Remaining: {threshold}

This certificate will expire in {threshold} days.

Please renew this certificate soon to avoid service interruption.
"""

    def _format_expired_email_body(self, cert) -> str:
        """Format email body for expired certificates."""
        days_past = abs(cert.days_remaining)
        return f"""CRITICAL: Certificate Has Expired

Hostname: {cert.display_name}
Subject: {cert.subject}
Issuer: {cert.issuer}
Expiry: {format_datetime(cert.not_after)}
Days Past Expiry: {days_past}

This certificate has EXPIRED {days_past} days ago and needs immediate renewal!

Services using this certificate may be experiencing errors.
"""

    async def _send_alert_email(self, alert: Alert) -> None:
        """Send a single alert email via SMTP.

        Args:
            alert: The alert to send

        Raises:
            SMTPConfigurationError: If SMTP is not configured
            AlertSendError: If sending fails
        """
        if not self._validate_smtp_config():
            raise SMTPConfigurationError("SMTP not configured properly")

        recipients = self._get_all_recipients()
        if not recipients:
            raise SMTPConfigurationError("No alert recipients configured")

        try:
            msg = MIMEText(alert.body)
            msg["Subject"] = alert.subject
            msg["From"] = self._settings.smtp_from_addr
            msg["To"] = ", ".join(recipients)

            with smtplib.SMTP(self._settings.smtp_host, self._settings.smtp_port) as server:
                if self._settings.smtp_use_tls:
                    server.starttls()

                # Authenticate if credentials provided
                if self._settings.smtp_user and self._settings.smtp_password:
                    server.login(self._settings.smtp_user, self._settings.smtp_password)

                server.sendmail(
                    self._settings.smtp_from_addr,
                    recipients,
                    msg.as_string(),
                )

        except smtplib.SMTPException as e:
            raise AlertSendError(f"SMTP error: {str(e)}")
        except Exception as e:
            raise AlertSendError(f"Failed to send email: {str(e)}")
