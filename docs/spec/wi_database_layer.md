# Interface Specification: Database Layer

## Dependencies

- `interface_ref`: `certificate_model`

## AC-01: Certificate Repository ABC
A `CertificateRepository` abstract base class must define:
- `add(cert: Certificate) -> str` — insert a certificate, return its ID
- `get_by_id(cert_id: str) -> Certificate | None`
- `list_all() -> list[Certificate]`
- `list_expiring_within(days: int) -> list[Certificate]`
- `update_expiry(cert_id: str, not_after: datetime) -> None`
- `delete(cert_id: str) -> None`

## AC-02: SQLite Implementation
A `SqliteCertificateRepository(CertificateRepository)` must implement all methods using SQLite with a `certificates` table storing: id, subject, issuer, not_before, not_after, san_dns_names (JSON), fingerprint_sha256, raw_der (blob), source, hostname, port, created_at, updated_at.

The `add(cert)` method must persist `cert.fingerprint_sha256` from the `certificate_model` `Certificate` instance — the test must create a `Certificate` via `parse_certificate(der_bytes)` and verify that `repo.get_by_id(cert_id).fingerprint_sha256` matches `cert.fingerprint_sha256`. This ensures the implementation exercises a non-trivial dep field rather than storing only literal test data.

## AC-03: Alert Repository ABC
An `AlertRepository` abstract base class must define:
- `create(alert: Alert) -> str` — insert an alert, return its ID
- `list_pending() -> list[Alert]`
- `mark_sent(alert_id: str) -> None`
- `mark_failed(alert_id: str, error_message: str) -> None`

## AC-04: Alert Repository Implementation
A `SqliteAlertRepository(AlertRepository)` must implement all methods using SQLite with an `alerts` table storing: id, cert_id, alert_type, status, created_at, sent_at, error_message.

## AC-05: Alert Type
`Alert` must be a dataclass with:
- `cert_id: str`
- `alert_type: str` — one of `"expiry_warning"`, `"expired"`, `"scan_failure"`
- `status: str` — one of `"pending"`, `"sent"`, `"failed"`
- `message: str`

## AC-06: Init Schema
A function `init_schema(db_path: str | Path) -> None` must create all tables if they do not exist. Idempotent — safe to call on an already-initialized database.