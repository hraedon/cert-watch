# API Reference

This document describes the REST API endpoints available in cert-watch.

## Base URL

```
http://localhost:8000
```

## Content Types

- **HTML Responses**: Default for browser requests (`Accept: text/html`)
- **JSON Responses**: Available for API requests (`Accept: application/json`)

## Authentication

v1 does not include authentication. Access control should be implemented at the network level (firewall, VPN, reverse proxy).

## Endpoints Overview

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard (FR-01) |
| `/scan/add-host` | POST | Add host for TLS scanning (FR-02) |
| `/scan/{id}/rescan` | POST | Rescan existing certificate (FR-02) |
| `/fr03-upload/upload` | POST | Upload certificate file (FR-03) |
| `/alerts` | GET | View alert history (FR-04) |
| `/alerts/send` | POST | Send pending alerts (FR-04) |
| `/alerts/config` | GET | View alert configuration (FR-04) |
| `/scheduler` | GET | Scheduler status page (FR-05) |
| `/scheduler/scan` | POST | Trigger manual scan (FR-05) |
| `/scheduler/history` | GET | Full scan history (FR-05) |
| `/scheduler/status` | GET | Scheduler status JSON (FR-05) |

---

## Dashboard (FR-01)

### GET /

Returns the main dashboard with all monitored certificates.

**Request:**
```http
GET / HTTP/1.1
Accept: text/html
```

**Response (HTML):**
```html
<!DOCTYPE html>
<html>
<head><title>Cert-Watch Dashboard</title></head>
<body>
  <h1>🔒 Cert-Watch Dashboard</h1>
  <!-- Certificate table with color-coded status -->
</body>
</html>
```

**Features:**
- Lists all certificates sorted by urgency (days remaining ascending)
- Color-coded status: red (<7 days), yellow (<30 days), green (>30 days)
- Shows hostname/label, issuer, expiry date, days remaining
- Summary statistics (critical/warning/healthy counts)

---

## TLS Scanning (FR-02)

### POST /scan/add-host

Add a new host for TLS certificate scanning.

**Request:**
```http
POST /scan/add-host HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Accept: application/json

hostname=example.com&port=443
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `hostname` | string | Yes | - | Target hostname |
| `port` | integer | No | 443 | Target port (1-65535) |

**Response (Success - JSON):**
```json
{
  "success": true,
  "message": "Certificate for example.com:443 scanned successfully",
  "certificate_id": 123,
  "subject": "CN=example.com",
  "issuer": "CN=Let's Encrypt Authority X3",
  "not_after": "2024-12-31T23:59:59"
}
```

**Response (Success - HTML):**
```html
HTTP/1.1 303 See Other
Location: /
```

**Response (Error - Connection Failed):**
```json
{
  "detail": "Connection failed: Could not connect to example.com:443"
}
```

**Response (Error - TLS Failed):**
```json
{
  "detail": "TLS handshake failed: [SSL: CERTIFICATE_VERIFY_FAILED]"
}
```

**Status Codes:**
- `200/303` - Success
- `400` - Connection or TLS handshake error
- `422` - Invalid input (hostname/port)
- `500` - Internal server error

### POST /scan/{cert_id}/rescan

Manually rescan an existing certificate entry.

**Request:**
```http
POST /scan/123/rescan HTTP/1.1
Accept: application/json
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `cert_id` | integer | Yes | Certificate ID to rescan |

**Response (Success):**
```json
{
  "success": true,
  "message": "Certificate 123 rescanned successfully",
  "certificate_id": 123,
  "subject": "CN=example.com",
  "not_after": "2024-12-31T23:59:59"
}
```

**Response (Error - Not Found):**
```json
{
  "detail": "Certificate 123 not found"
}
```

**Response (Error - Not Scanned):**
```json
{
  "detail": "Can only rescan certificates that were originally scanned"
}
```

---

## Certificate Upload (FR-03)

### POST /fr03-upload/upload

Upload a certificate file (.pem, .cer, .crt).

**Request:**
```http
POST /fr03-upload/upload HTTP/1.1
Content-Type: multipart/form-data
Accept: text/html

------FormBoundary
Content-Disposition: form-data; name="certificate"; filename="cert.pem"
Content-Type: application/x-pem-file

-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----
------FormBoundary
Content-Disposition: form-data; name="label"

Production API Server
------FormBoundary--
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `certificate` | file | Yes | Certificate file (.pem, .cer, .crt) |
| `label` | string | No | Custom display label |

**Supported Formats:**
- PEM encoded (Base64 with headers)
- DER encoded (binary)
- Files with multiple certificates (leaf + chain)

**Response (Success - HTML):**
```html
<!DOCTYPE html>
<html>
<head><title>Certificate Uploaded</title></head>
<body>
  <h1>Certificate Uploaded Successfully</h1>
  <div class="certificate-details">
    <p><strong>Subject:</strong> CN=example.com</p>
    <p><strong>Issuer:</strong> CN=Let's Encrypt Authority X3</p>
    <p><strong>Expiry:</strong> 2024-12-31 23:59:59 UTC</p>
    <p><strong>Fingerprint:</strong> a1b2c3d4...</p>
    <p><strong>Chain Count:</strong> 2</p>
  </div>
  <a href="/">Back to Dashboard</a>
</body>
</html>
```

**Response (Error - Invalid Format):**
```json
{
  "detail": "Invalid certificate file: Unable to parse certificate file. Must be PEM or DER format."
}
```

**Response (Error - Unsupported Extension):**
```json
{
  "detail": "Unsupported file extension: .txt. Allowed: .cer, .pem, .crt"
}
```

**Status Codes:**
- `200` - Success
- `400` - Empty file or read error
- `422` - Invalid file format or unsupported extension
- `500` - Failed to store certificate

---

## Alerts (FR-04)

### GET /alerts

View alert history and pending alerts.

**Request:**
```http
GET /alerts HTTP/1.1
Accept: text/html
```

**Response (HTML):**
- Alert history table
- Certificate details for each alert
- Status (pending/sent/failed)
- Send pending alerts button

### POST /alerts/send

Manually trigger sending of pending alerts.

**Request:**
```http
POST /alerts/send HTTP/1.1
Accept: application/json
```

**Response (Success - JSON):**
```json
{
  "success": true,
  "sent": 3,
  "failed": 0
}
```

**Response (Error - SMTP Not Configured):**
```json
{
  "detail": "Alert service not yet implemented"
}
```

**Response (Success - HTML):**
```html
HTTP/1.1 303 See Other
Location: /alerts
```

### GET /alerts/config

View current alert configuration.

**Request:**
```http
GET /alerts/config HTTP/1.1
Accept: text/html
```

**Response (HTML):**
- SMTP settings (host, port, from address)
- Alert recipients list
- Threshold configuration (leaf: 14/7/3/1 days, chain: 30/14/7 days)

---

## Scheduler (FR-05)

### GET /scheduler

View scheduler status and recent scan history.

**Request:**
```http
GET /scheduler HTTP/1.1
Accept: text/html
```

**Response (HTML):**
- Configuration (scan time, timezone, thresholds)
- Recent scan history table
- Manual scan trigger button

### POST /scheduler/scan

Manually trigger a scan cycle.

**Request:**
```http
POST /scheduler/scan HTTP/1.1
```

**Response:**
```html
HTTP/1.1 302 Found
Location: /scheduler
```

**Behavior:**
- Runs the same scan cycle as the scheduled daily scan
- Refreshes all SCANNED certificates
- Triggers alert evaluation
- Records scan history

### GET /scheduler/history

View full scan history.

**Request:**
```http
GET /scheduler/history HTTP/1.1
Accept: text/html
```

**Response (HTML):**
- Complete scan history table (up to 100 entries)
- Columns: ID, Started, Completed, Status, Hosts, Successful, Failed, Updated, Error

### GET /scheduler/status

Get scheduler status as JSON (API endpoint).

**Request:**
```http
GET /scheduler/status HTTP/1.1
Accept: application/json
```

**Response:**
```json
{
  "scan_time": "06:00",
  "scan_timezone": "UTC",
  "leaf_alert_thresholds": [14, 7, 3, 1],
  "chain_alert_thresholds": [30, 14, 7],
  "recent_scans": [
    {
      "id": 1,
      "started_at": "2024-01-15T06:00:00",
      "completed_at": "2024-01-15T06:05:23",
      "status": "SUCCESS",
      "total_hosts": 5,
      "successful_hosts": 5,
      "failed_hosts": 0,
      "updated_certificates": 5
    }
  ]
}
```

---

## Data Models

### Certificate

```json
{
  "id": 123,
  "certificate_type": "LEAF",
  "source": "SCANNED",
  "hostname": "example.com",
  "port": 443,
  "label": null,
  "subject": "CN=example.com",
  "issuer": "CN=Let's Encrypt Authority X3",
  "not_before": "2024-01-01T00:00:00",
  "not_after": "2024-12-31T23:59:59",
  "fingerprint": "a1b2c3d4e5f6...",
  "serial_number": "1234567890...",
  "chain_fingerprint": null,
  "chain_position": 0,
  "created_at": "2024-01-15T10:30:00",
  "updated_at": "2024-01-15T10:30:00",
  "last_scanned_at": "2024-01-15T10:30:00"
}
```

**Certificate Types:** `LEAF`, `INTERMEDIATE`, `ROOT`

**Sources:** `SCANNED`, `UPLOADED`

### Alert

```json
{
  "id": 456,
  "certificate_id": 123,
  "alert_type": "EXPIRY_WARNING",
  "days_remaining": 7,
  "status": "SENT",
  "recipient": "ops@example.com",
  "subject": "WARNING: Certificate Expires in 7 Days - example.com",
  "body": "Certificate Expiry Alert\n\nHostname: example.com\n...",
  "created_at": "2024-12-24T06:00:00",
  "sent_at": "2024-12-24T06:00:05"
}
```

**Alert Types:** `EXPIRY_WARNING`, `EXPIRED`, `SCAN_FAILURE`

**Alert Status:** `PENDING`, `SENT`, `FAILED`

### Scan History

```json
{
  "id": 789,
  "started_at": "2024-01-15T06:00:00",
  "completed_at": "2024-01-15T06:05:23",
  "status": "SUCCESS",
  "total_hosts": 5,
  "successful_hosts": 5,
  "failed_hosts": 0,
  "updated_certificates": 5,
  "error_message": null
}
```

**Scan Status:** `SUCCESS`, `PARTIAL`, `FAILURE`

---

## Error Responses

### Standard Error Format

```json
{
  "detail": "Error description here"
}
```

### HTTP Status Codes

| Code | Meaning | Typical Causes |
|------|---------|----------------|
| `200` | OK | Successful request |
| `302/303` | Redirect | Success with redirect (HTML mode) |
| `400` | Bad Request | Connection failure, invalid input |
| `404` | Not Found | Certificate ID doesn't exist |
| `422` | Unprocessable | Invalid file format, validation error |
| `500` | Server Error | Internal error, database failure |
| `503` | Service Unavailable | SMTP not configured, service not ready |

---

## Rate Limiting

v1 does not implement rate limiting. For production deployments:

1. Use a reverse proxy (nginx, traefik) for rate limiting
2. Monitor logs for abuse patterns
3. Consider implementing application-level rate limiting in v2

## CORS

v1 does not configure CORS. For API access from browsers:

1. Use a reverse proxy to handle CORS headers
2. Or modify `app_factory.py` to add CORS middleware (not recommended - file is frozen)

## WebSocket Support

v1 does not include WebSocket support. Real-time updates (if needed) can be implemented via:

1. HTMX polling (already used for partial dashboard updates)
2. Server-Sent Events (SSE)
3. WebSocket support planned for v2
