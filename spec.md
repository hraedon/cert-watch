# Specification: cert-watch

**Spec Level:** 1  
**Date:** 2026-04-17

## 1. Problem Statement

TLS certificates are scattered across infrastructure. Expiring certificates cause silent outages discovered only when something breaks.

## 2. MVP Definition

A web dashboard showing all monitored certificates with color-coded expiry status, supporting both automatic scanning and manual upload, with email alerts before expiry.

## 3. Glossary

| Term | Definition |
|---|---|
| **Leaf certificate** | The end-entity certificate presented by a server. |
| **Chain certificate** | An intermediate or root CA certificate in the trust chain. |
| **Scanned entry** | Certificate created by TLS handshake to a host. |
| **Uploaded entry** | Certificate created by uploading a certificate file. |

## 4. MVP Functional Requirements

### FR-01: Dashboard Display
The dashboard displays all monitored certificates showing hostname/label, issuer, expiry date, days remaining, and color-coded status (red <7 days, yellow <30 days, green >30 days). Sorted by urgency.

**Acceptance Criteria:**
- List view with all fields visible
- Color coding matches thresholds
- Sort by days remaining (ascending)

### FR-02: Add Host for TLS Scanning
User can add a host by providing hostname and port. System performs TLS handshake, extracts leaf certificate and chain, creates monitored entries.

**Acceptance Criteria:**
- Input form accepts hostname + port
- TLS connection succeeds and extracts cert
- Leaf and chain certs stored separately

### FR-03: Upload Certificate File
User can upload a certificate file (.cer/.pem/.crt). System parses file, extracts expiry and chain, creates monitored entry.

**Acceptance Criteria:**
- File upload accepts supported formats
- Parses expiry date correctly
- Extracts chain if present

### FR-04: Email Alerts
System sends email alerts at configured thresholds before expiry (14/7/3/1 days for leaf, 30/14/7 days for chain).

**Acceptance Criteria:**
- Configurable SMTP settings
- Alerts sent at thresholds
- Alert history logged

### FR-05: Daily Automatic Scan
Built-in scheduler runs daily scan cycle, refreshing all scanned certificates and sending alerts for newly detected issues.

**Acceptance Criteria:**
- Daily scan at configurable time
- Updates existing entries
- Logs scan results

## 5. Technical Stack

- **Language:** Python 3.12+
- **Web Framework:** FastAPI
- **Database:** SQLite (with repository pattern for future extensibility)
- **Scheduler:** APScheduler or similar
- **TLS:** Standard library ssl module
- **Email:** Standard library smtplib

## 6. Out of Scope (v1)

- Authentication (network-level access assumed)
- Teams/webhook notifications (stretch)
- MSSQL backend (SQLite for v1)
- Certificate renewal automation
- Windows CA API integration
