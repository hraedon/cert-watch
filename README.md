# cert-watch

TLS certificate monitoring dashboard with automatic scanning and email alerts.

## Quick Start

```bash
# Install dependencies
pip install -e .[dev]

# Run the application
cert-watch
# Or:
python -m cert_watch.web.main

# Run tests
pytest
```

## Architecture

See [CONVENTIONS.md](CONVENTIONS.md) for architectural conventions and guidelines.

## Features (MVP)

- Dashboard with color-coded certificate status
- TLS scanning for automatic certificate discovery
- Certificate file upload (.cer/.pem/.crt)
- Email alerts at configurable thresholds
- Daily automatic scan cycle

## Configuration

Configuration is loaded from environment variables or `.env` file:

```bash
# Database
DATABASE_URL=sqlite:///./cert_watch.db

# SMTP (for alerts)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASSWORD=secret
SMTP_FROM_ADDR=noreply@example.com
ALERT_RECIPIENTS=admin@example.com,ops@example.com

# Scan schedule
SCAN_TIME=06:00
SCAN_TIMEZONE=UTC
```
