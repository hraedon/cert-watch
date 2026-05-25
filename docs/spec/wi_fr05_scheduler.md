# Interface Specification: FR-05 Daily Scheduler

## Dependencies

- `interface_ref`: `fr02_tls_scan`
- `interface_ref`: `fr04_alerts`

## AC-01: Scheduler Setup
A function `start_scheduler(scan_fn: Callable, alert_fn: Callable, hour: int = 6, minute: int = 0) -> None` must configure and start a recurring daily scan at the specified time.

## AC-02: Scan Cycle
Each scan cycle must:
1. Retrieve all certificates with `source == "scanned"` from the repository
2. Re-scan each host using the provided `scan_fn`
3. Update expiry dates for successful scans
4. Log scan results to `scan_history`

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