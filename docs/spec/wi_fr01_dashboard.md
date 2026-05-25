# Interface Specification: FR-01 Dashboard

## Dependencies

- `interface_ref`: `database_layer`

## AC-01: Dashboard Route
A FastAPI route `GET /` must render a Jinja2 template showing all monitored certificates.

## AC-02: Color-Coded Status
Each certificate row must display a status color:
- Red (`< 7 days`): certificates expiring within 7 days
- Yellow (`< 30 days`): certificates expiring within 30 days
- Green (`>= 30 days`): all other certificates

## AC-03: Sort by Urgency
The dashboard list must be sorted by days remaining ascending (most urgent first).

## AC-04: Display Fields
Each certificate row must show: hostname/port, subject, issuer, expiry date, days remaining.

## AC-05: Error State
If no certificates exist, the dashboard must display an empty-state message (not a server error).