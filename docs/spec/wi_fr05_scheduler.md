# Interface Specification: FR-05 Daily Scheduler

## Dependencies

- `interface_ref`: `fr02_tls_scan`
- `interface_ref`: `fr04_alerts`

## AC-01: Scheduler Setup
A function `start_scheduler(scan_fn: Callable, alert_fn: Callable, hour: int = 6, minute: int = 0) -> None` must configure and start a recurring daily scan at the specified time.

## AC-02: Scan Cycle
Each scan cycle must:
1. Select registered endpoints due for a scan, including endpoints without a certificate
2. Scan each selected host using the provided `scan_fn`
3. Update expiry dates for successful scans
4. Log scan results to `scan_history`

Host selection and the next scheduler wakeup must use the same cadence policy.
A positive `scan_interval_hours` is measured from the last successful scan;
hosts without a positive override use the configured daily UTC boundary.
Failed attempts are retried no sooner than one hour later. A host without any
attempt is eligible when a cycle runs and is discovered by the hourly recheck.
Manual endpoint scans bypass this cadence policy.

Saving monitoring or delivery settings must refresh the running scheduler and
wake it to recalculate its next run. Each job uses one complete settings and
transport snapshot; an update during a job takes effect on subsequent jobs.
Environment overrides continue to win over stored settings.

## AC-03: Alert Cycle
After the scan cycle completes, the scheduler must call the provided `alert_fn` to evaluate thresholds and send pending alerts.

## AC-04: Scan History
A `ScanHistory` dataclass must contain:
- `id: str`
- `hostname: str`
- `port: int`
- `status: str` — one of `"success"`, `"partial"`, `"failure"`
- `scanned_at: datetime`
- `error_message: str | None`

## AC-05: Graceful Degradation
If an individual host scan fails, the scheduler must log the failure and continue to the next host — not abort the entire cycle.

## AC-06: Run Now
A function `run_scan_now(scan_fn: Callable, alert_fn: Callable) -> dict[str, int]` must execute one full scan+alert cycle immediately and return counts: `{"scanned": N, "alerts_sent": M, "failures": K}`.
