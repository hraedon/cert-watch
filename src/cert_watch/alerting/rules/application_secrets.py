"""Application credential expiry reminders through the existing alert queue."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.alert_store import AlertStore
from cert_watch.database.application_secrets import list_application_secrets
from cert_watch.database.connection import _connect, get_write_lock
from cert_watch.database.repo import Alert

THRESHOLDS = (30, 14, 7, 3, 1)


def evaluate_application_secrets(
    db_path: str | Path, *, now: datetime | None = None,
) -> list[Alert]:
    current = now or datetime.now(UTC)
    raised: list[Alert] = []
    store = AlertStore(db_path, initialize=False)
    with get_write_lock(), _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        for secret in list_application_secrets(db_path):
            if secret.retired_at is not None:
                continue
            seconds = (secret.expires_at - current).total_seconds()
            crossed = [day for day in THRESHOLDS if seconds <= day * 86400]
            if not crossed:
                continue
            threshold = 0 if seconds <= 0 else min(crossed)
            resource = f"application-secret:{secret.id}"
            seen = conn.execute(
                "SELECT MIN(threshold_days) FROM alerts WHERE cert_id=?",
                (resource,),
            ).fetchone()[0]
            if seen is not None and seen <= threshold:
                continue
            # The most urgent stage supersedes unsent earlier reminders.
            stale_keys = {str(row[0]) for row in conn.execute(
                """SELECT dedupe_key FROM alerts WHERE cert_id=?
                   AND threshold_days>? AND closed_at IS NULL AND status='pending'""",
                (resource, threshold),
            )}
            store.close_keys(
                stale_keys, conn=conn, now=current, reason="expiry reminder superseded",
            )
            label = "expired" if threshold == 0 else f"expires within {threshold} days"
            message = (
                f"Application credential {label}: {secret.application_name}\n"
                f"Application ID: {secret.application_id}\n"
                f"Credential: {secret.credential_name or secret.credential_id}\n"
                f"Credential ID: {secret.credential_id}\n"
                f"Expiry (UTC): {secret.expires_at.isoformat()}\n"
                "Rotate the credential in its provider and deploy the replacement, "
                "then retire this metadata record. cert-watch does not rotate secrets."
            )
            recipients = [secret.owner_email] if secret.owner_email else []
            alert = Alert(
                cert_id=resource, alert_type="application_secret_expired" if threshold == 0
                else "application_secret_expiry", status="pending", message=message,
                subject=secret.application_name, threshold_days=threshold, created_at=current,
                dedupe_key=f"application-secret:{secret.id}:{threshold}",
                extra_recipients=recipients,
                routing={"version": 1, "recipients": recipients, "groups": []},
            )
            if store.enqueue(alert, conn=conn, lifetime=True):
                raised.append(alert)
        conn.commit()
    return raised
