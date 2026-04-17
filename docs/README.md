# Cert-Watch

TLS certificate monitoring dashboard with automatic scanning and email alerts.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

Cert-watch monitors TLS certificates across your infrastructure, providing:

- **Dashboard View**: Color-coded certificate status (red/yellow/green) sorted by urgency
- **TLS Scanning**: Automatic certificate extraction via TLS handshake
- **File Upload**: Support for .pem, .cer, and .crt certificate files
- **Email Alerts**: Configurable thresholds before expiry (14/7/3/1 days for leaf, 30/14/7 for chain)
- **Daily Scanning**: Built-in scheduler to refresh scanned certificates

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/cert-watch.git
cd cert-watch

# Install with pip
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Configuration

Create a `.env` file in the project root:

```env
# Application
APP_NAME=cert-watch
DEBUG=false

# Database
DATABASE_URL=sqlite:///./data/cert_watch.db

# SMTP (required for email alerts)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASSWORD=your-password
SMTP_USE_TLS=true
SMTP_FROM_ADDR=cert-watch@example.com
ALERT_RECIPIENTS=ops@example.com,security@example.com

# Scheduler
SCAN_TIME=06:00
SCAN_TIMEZONE=UTC
```

### Running the Application

```bash
# Using the CLI
cert-watch

# Or using Python directly
python -m cert_watch.web.main

# With custom settings
APP_NAME="My Cert Watch" python -m cert_watch.web.main
```

The dashboard will be available at `http://localhost:8000`.

### First Steps

1. **Add a host for monitoring**:
   - Navigate to the dashboard
   - Click "Add Host"
   - Enter hostname (e.g., `example.com`) and port (default: 443)
   - The system will perform a TLS handshake and extract the certificate

2. **Upload an existing certificate**:
   - Click "Upload Certificate"
   - Select a .pem, .cer, or .crt file
   - Optionally add a custom label

3. **View the dashboard**:
   - Certificates are color-coded by urgency
   - Red: Expires in < 7 days
   - Yellow: Expires in < 30 days
   - Green: Expires in > 30 days

## Features

### Dashboard (FR-01)

The main dashboard displays all monitored certificates:
- Hostname/label, issuer, expiry date
- Days remaining until expiry
- Color-coded status indicators
- Sorted by urgency (most critical first)

### TLS Scanning (FR-02)

Automatically extract certificates via TLS handshake:
- Add any hostname with TLS enabled
- Extracts leaf and full certificate chain
- Updates existing entries on rescan
- Error handling for unreachable hosts

### Certificate Upload (FR-03)

Upload certificate files directly:
- Supports .pem, .cer, and .crt formats
- Parses PEM and DER encodings
- Extracts complete certificate chains
- Validates file format and content

### Email Alerts (FR-04)

Automated email notifications:
- Leaf certificates: alerts at 14, 7, 3, and 1 days before expiry
- Chain certificates: alerts at 30, 14, and 7 days before expiry
- Configurable SMTP settings
- Alert history tracking

### Daily Scheduler (FR-05)

Built-in background scheduler:
- Daily scan at configurable time (default: 06:00 UTC)
- Refreshes all scanned certificates
- Triggers alert evaluation
- Scan history with detailed logging

## Documentation

- [Architecture](ARCHITECTURE.md) - System design and data flow
- [Dependencies](DEPENDENCIES.md) - System requirements
- [Configuration](CONFIGURATION.md) - Environment variables and settings
- [Operations](OPERATIONS.md) - Deployment and troubleshooting
- [API Reference](API.md) - REST API documentation

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/web/routes/test_fr01_dashboard.py
```

### Project Structure

```
src/cert_watch/
├── core/           # Utilities, config, formatters, exceptions
├── models/         # Data models (certificate, alert, scan_history)
├── repositories/   # Database access (ABC + SQLite impl)
├── services/       # Business logic (alerts, scheduler)
└── web/            # Web layer
    ├── routes/     # Route modules (one per FR)
    ├── templates/  # Jinja2 templates
    ├── deps.py     # Dependency injection
    ├── app_factory.py  # App creation (auto-discovery)
    └── main.py     # Entry point
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Support

For issues and questions:
- Check the [troubleshooting guide](OPERATIONS.md#troubleshooting)
- Review [configuration options](CONFIGURATION.md)
- Open an issue on GitHub
