# Configuration

This document describes all configuration options for cert-watch.

## Configuration Sources

Cert-watch uses the following configuration sources (in order of precedence):

1. **Environment variables** (highest priority)
2. **`.env` file** in project root
3. **Default values** (lowest priority)

## Environment Variables

### Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `cert-watch` | Application name shown in UI |
| `DEBUG` | `false` | Enable debug mode (boolean) |

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./cert_watch.db` | Database connection string |
| `DATA_DIR` | `./data` | Directory for data files |

**Note**: For v1, only SQLite is supported. The database file path is extracted from the `DATABASE_URL`.

### SMTP / Email Settings

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SMTP_HOST` | `null` | Yes* | SMTP server hostname |
| `SMTP_PORT` | `587` | No | SMTP server port |
| `SMTP_USER` | `null` | No | SMTP username |
| `SMTP_PASSWORD` | `null` | No | SMTP password |
| `SMTP_USE_TLS` | `true` | No | Use TLS for SMTP connection |
| `SMTP_FROM_ADDR` | `null` | Yes* | From address for alert emails |
| `ALERT_RECIPIENTS` | `[]` | Yes* | Comma-separated list of recipient emails |

*Required only if using email alerts (FR-04).

### Alert Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `LEAF_ALERT_THRESHOLDS` | `14,7,3,1` | Days before expiry for leaf cert alerts |
| `CHAIN_ALERT_THRESHOLDS` | `30,14,7` | Days before expiry for chain cert alerts |

### Scheduler Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_TIME` | `06:00` | Daily scan time (HH:MM format) |
| `SCAN_TIMEZONE` | `UTC` | Timezone for scan scheduling |

## Configuration File (.env)

### Minimal Configuration

For local development with just the dashboard:

```env
APP_NAME=cert-watch
DEBUG=false
DATABASE_URL=sqlite:///./data/cert_watch.db
```

### Production Configuration

Full configuration for production with email alerts:

```env
# Application
APP_NAME=CertWatch Production
DEBUG=false

# Database
DATABASE_URL=sqlite:///./data/cert_watch.db
DATA_DIR=./data

# SMTP Configuration (Gmail example)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
SMTP_FROM_ADDR=cert-alerts@yourcompany.com
ALERT_RECIPIENTS=ops@yourcompany.com,security@yourcompany.com

# Alert Thresholds
LEAF_ALERT_THRESHOLDS=14,7,3,1
CHAIN_ALERT_THRESHOLDS=30,14,7

# Scheduler
SCAN_TIME=06:00
SCAN_TIMEZONE=America/New_York
```

### Using SendGrid

```env
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=SG.your-api-key-here
SMTP_USE_TLS=true
SMTP_FROM_ADDR=alerts@yourdomain.com
ALERT_RECIPIENTS=team@yourdomain.com
```

### Using Amazon SES

```env
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=your-ses-username
SMTP_PASSWORD=your-ses-password
SMTP_USE_TLS=true
SMTP_FROM_ADDR=noreply@yourdomain.com
ALERT_RECIPIENTS=ops@yourdomain.com
```

## Programmatic Configuration

For testing or embedded usage, you can create a Settings instance directly:

```python
from cert_watch.core.config import Settings
from pathlib import Path

# Create custom settings
settings = Settings(
    app_name="My Cert Watch",
    debug=True,
    database_url="sqlite:///./test.db",
    smtp_host="smtp.example.com",
    smtp_port=587,
    alert_recipients=["test@example.com"],
)

# Use settings in app
from cert_watch.web.app_factory import create_app
app = create_app(settings)
```

## Configuration Validation

The application validates configuration at startup:

- **SMTP**: If any SMTP setting is provided, the system will attempt to validate the configuration
- **Database**: Parent directories are created automatically if they don't exist
- **Alert Recipients**: Must be valid email addresses (format validation only)

## Security Considerations

### Protecting Sensitive Data

**Never commit the following to version control:**
- `.env` files
- SMTP passwords
- Database URLs containing credentials

**Recommended practices:**
1. Use `.env.example` as a template (without real values)
2. Add `.env` to `.gitignore`
3. Use environment-specific configuration in production
4. Consider using a secrets manager for production deployments

### Example .gitignore

```gitignore
# Environment
.env
.env.local
.env.production

# Database
data/
*.db
*.sqlite3

# Logs
logs/
*.log
```

## Common Configuration Patterns

### Development Environment

```env
APP_NAME=cert-watch-dev
DEBUG=true
DATABASE_URL=sqlite:///./dev.db

# SMTP not configured - alerts disabled
```

### Staging Environment

```env
APP_NAME=cert-watch-staging
DEBUG=false
DATABASE_URL=sqlite:///./data/staging.db

# Test SMTP server
SMTP_HOST=smtp.mailtrap.io
SMTP_PORT=587
SMTP_USER=your-mailtrap-user
SMTP_PASSWORD=your-mailtrap-pass
SMTP_FROM_ADDR=staging@example.com
ALERT_RECIPIENTS=staging-team@example.com

SCAN_TIME=09:00
```

### Production Environment

```env
APP_NAME=cert-watch
DEBUG=false
DATABASE_URL=sqlite:///./data/cert_watch.db
DATA_DIR=./data

# Production SMTP
SMTP_HOST=smtp.yourcompany.com
SMTP_PORT=587
SMTP_USER=certwatch@yourcompany.com
SMTP_PASSWORD_FILE=/run/secrets/smtp_password  # Use secrets manager
SMTP_USE_TLS=true
SMTP_FROM_ADDR=certwatch@yourcompany.com
ALERT_RECIPIENTS=ops@yourcompany.com,security@yourcompany.com

# Aggressive alerting for production
LEAF_ALERT_THRESHOLDS=14,7,3,1
CHAIN_ALERT_THRESHOLDS=30,14,7

# Early morning scan
SCAN_TIME=06:00
SCAN_TIMEZONE=UTC
```

## Timezone Configuration

The scheduler supports timezone-aware scheduling:

```env
# UTC (default)
SCAN_TIMEZONE=UTC

# US Eastern Time
SCAN_TIMEZONE=America/New_York

# Central European Time
SCAN_TIMEZONE=Europe/Berlin

# Japan Standard Time
SCAN_TIMEZONE=Asia/Tokyo
```

**Note**: The timezone must be a valid IANA timezone identifier (e.g., `America/New_York`, not `EST`).

## Alert Threshold Customization

### Conservative (More Alerts)

```env
# Leaf certificates: 30, 14, 7, 3, 1 days
LEAF_ALERT_THRESHOLDS=30,14,7,3,1

# Chain certificates: 60, 30, 14, 7 days
CHAIN_ALERT_THRESHOLDS=60,30,14,7
```

### Minimal (Fewer Alerts)

```env
# Leaf certificates: only 7 and 1 day
LEAF_ALERT_THRESHOLDS=7,1

# Chain certificates: only 14 and 7 days
CHAIN_ALERT_THRESHOLDS=14,7
```

## Troubleshooting Configuration

### SMTP Connection Fails

1. Verify `SMTP_HOST` and `SMTP_PORT` are correct
2. Check firewall rules allow outbound SMTP
3. For Gmail: Use an "App Password" instead of your regular password
4. Verify `SMTP_USE_TLS` matches server requirements

### Database Permission Errors

```bash
# Ensure data directory exists and is writable
mkdir -p ./data
chmod 755 ./data
```

### Configuration Not Loading

1. Check `.env` file is in the project root
2. Verify file encoding is UTF-8
3. Ensure no spaces around `=` in key=value pairs

```bash
# View loaded configuration
python -c "from cert_watch.core.config import Settings; print(Settings.get().model_dump())"
```
