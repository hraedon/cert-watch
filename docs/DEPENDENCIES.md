# Dependencies

This document outlines all system requirements and external dependencies for cert-watch.

## System Requirements

### Minimum Requirements

- **Python**: 3.12 or higher
- **Operating System**: Linux, macOS, or Windows
- **Memory**: 256 MB RAM minimum
- **Disk**: 100 MB for application, plus storage for database and logs
- **Network**: Outbound access for TLS scanning and SMTP (if using alerts)

### Recommended

- **Python**: 3.12+
- **Memory**: 512 MB RAM
- **Disk**: 1 GB for database growth and logs
- **Network**: Stable outbound access for scheduled scanning

## Python Dependencies

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | >=0.110.0 | Web framework |
| `uvicorn[standard]` | >=0.29.0 | ASGI server |
| `jinja2` | >=3.1.0 | Template engine |
| `python-multipart` | >=0.0.9 | Form/multipart parsing |
| `cryptography` | >=42.0.0 | Certificate parsing and TLS |
| `apscheduler` | >=3.10.0 | Background scheduler |
| `pydantic` | >=2.6.0 | Data validation |
| `pydantic-settings` | >=2.2.0 | Configuration management |

### Development Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | >=8.0.0 | Testing framework |
| `pytest-timeout` | >=2.2.0 | Test timeouts |
| `pytest-asyncio` | >=0.23.0 | Async test support |
| `httpx` | >=0.27.0 | HTTP client for testing |
| `ruff` | >=0.3.0 | Linting and formatting |

## External System Dependencies

### For TLS Scanning (FR-02)

- **OpenSSL**: Required by the `cryptography` package for TLS operations
- **System CA Certificates**: Used for TLS certificate validation

### For Email Alerts (FR-04)

- **SMTP Server**: Any SMTP-compatible mail server
  - Supports TLS/STARTTLS
  - Supports authentication (user/password)
  - Compatible with Gmail, Outlook, SendGrid, Amazon SES, etc.

### Optional

- **NTP**: Recommended for accurate certificate expiry calculations
- **systemd** (Linux): For service management (see Operations guide)

## Installation

### Standard Installation

```bash
# From source
pip install -e .

# With development dependencies
pip install -e ".[dev]"
```

### Verify Installation

```bash
# Check Python version
python --version  # Should show 3.12+

# Verify dependencies
python -c "import fastapi; import cryptography; import apscheduler; print('OK')"

# Check cert-watch CLI
cert-watch --help
```

## Docker (Optional)

### Building

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ ./src/

RUN pip install -e .

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["cert-watch"]
```

### Running

```bash
# Build
docker build -t cert-watch .

# Run with env file
docker run -p 8000:8000 --env-file .env -v $(pwd)/data:/app/data cert-watch
```

## Network Requirements

### Inbound

| Port | Protocol | Purpose |
|------|----------|---------|
| 8000 | HTTP | Web dashboard and API |

### Outbound

| Port | Protocol | Purpose | Required |
|------|----------|---------|----------|
| 443 | HTTPS | TLS certificate scanning | Yes (for FR-02) |
| 587 | SMTP/TLS | Email alerts | No (only if using alerts) |
| 25 | SMTP | Email alerts (fallback) | No |
| 465 | SMTPS | Email alerts (alternative) | No |

## Platform-Specific Notes

### Linux

- Ensure `openssl` is installed:
  ```bash
  # Debian/Ubuntu
  sudo apt-get install openssl

  # RHEL/CentOS/Fedora
  sudo yum install openssl
  ```

### macOS

- OpenSSL is typically included with Xcode Command Line Tools
- If not present: `brew install openssl`

### Windows

- OpenSSL is bundled with the `cryptography` package wheels
- No additional installation required

## Dependency Updates

### Checking for Updates

```bash
# List outdated packages
pip list --outdated

# Check specific package
pip index versions fastapi
```

### Security Updates

Monitor these packages for security announcements:
- `cryptography` - TLS and certificate handling
- `fastapi` - Web framework
- `pydantic` - Data validation

## Troubleshooting Dependencies

### Common Issues

**Issue**: `ImportError: cannot import name '...' from 'cryptography'`

**Solution**: Upgrade cryptography:
```bash
pip install --upgrade cryptography
```

**Issue**: `ModuleNotFoundError: No module named 'cert_watch'`

**Solution**: Install in editable mode:
```bash
pip install -e .
```

**Issue**: `uvicorn not found`

**Solution**: Install with standard dependencies:
```bash
pip install "uvicorn[standard]>=0.29.0"
```

## License Compatibility

All dependencies use permissive licenses compatible with MIT:

- **FastAPI**: MIT
- **Uvicorn**: BSD-3-Clause
- **Cryptography**: Apache-2.0 OR BSD-3-Clause
- **APScheduler**: MIT
- **Pydantic**: MIT
- **Jinja2**: BSD-3-Clause
