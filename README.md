# cert-watch

[![Docker](https://img.shields.io/badge/docker-ready-blue?logo=docker)](https://docker.com)
[![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> TLS certificate monitoring dashboard with automatic scanning and email alerts.

cert-watch monitors TLS certificates across your infrastructure, alerting you before they expire. It automatically scans hosts for certificates, accepts manual certificate uploads, and sends email notifications at configurable thresholds.

![Dashboard Screenshot](docs/screenshot-placeholder.png)

## Features

- **📊 Web Dashboard** — View all monitored certificates with color-coded expiry status
- **🔍 Automatic Scanning** — Add hosts for TLS handshake scanning
- **📁 Manual Upload** — Upload certificate files (.cer, .pem, .crt)
- **📧 Email Alerts** — Configurable thresholds for leaf and chain certificates
- **⏰ Built-in Scheduler** — Daily automatic scan cycle
- **🐳 Docker & Kubernetes Ready** — Containerized for easy deployment

## Quick Start

### Docker

```bash
# Build image
docker build -t cert-watch:latest .

# Run with required environment variables
docker run -d \
  -p 8000:8000 \
  -v certwatch-data:/app/data \
  -e SMTP_HOST="smtp.gmail.com" \
  -e SMTP_USER="alerts@example.com" \
  -e SMTP_PASSWORD="your-app-password" \
  -e ALERT_RECIPIENTS="admin@example.com,ops@example.com" \
  cert-watch:latest

# Access dashboard
curl http://localhost:8000
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Create secrets (REQUIRED for email alerts)
kubectl create secret generic cert-watch-secrets \
  --from-literal=smtp-host='smtp.gmail.com' \
  --from-literal=smtp-user='alerts@example.com' \
  --from-literal=smtp-password='your-app-password' \
  --from-literal=smtp-from-addr='alerts@example.com' \
  --from-literal=alert-recipients='admin@example.com' \
  -n cert-watch

# Port-forward for local access
kubectl port-forward -n cert-watch svc/cert-watch 8000:8000
```

See [k8s/OPERATIONS.md](k8s/OPERATIONS.md) for production deployment details.

### Local Development

```bash
# Clone and setup
git clone <repo-url>
cd cert-watch
pip install -e ".[dev]"

# Run locally
uvicorn cert_watch.web.main:app --reload

# Or using the module
python -m cert_watch.web.main

# Run tests
pytest
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | No | `sqlite:///./cert_watch.db` | Database connection string |
| `DATA_DIR` | No | `./data` | Data directory for SQLite |
| `SMTP_HOST` | **Yes**¹ | — | SMTP relay hostname |
| `SMTP_PORT` | No | `587` | SMTP relay port |
| `SMTP_USER` | **Yes**¹ | — | SMTP auth username |
| `SMTP_PASSWORD` | **Yes**¹ | — | SMTP auth password |
| `SMTP_USE_TLS` | No | `true` | Enable SMTP TLS |
| `SMTP_FROM_ADDR` | **Yes**¹ | — | From address for alert emails |
| `ALERT_RECIPIENTS` | **Yes**¹ | — | Comma-separated list of alert recipients |
| `SCAN_TIME` | No | `06:00` | Daily scan time (HH:MM format) |
| `SCAN_TIMEZONE` | No | `UTC` | Timezone for scheduler |
| `LEAF_ALERT_THRESHOLDS` | No | `14,7,3,1` | Days before expiry for leaf cert alerts |
| `CHAIN_ALERT_THRESHOLDS` | No | `30,14,7` | Days before expiry for chain cert alerts |
| `DEBUG` | No | `false` | Enable debug mode |

¹Required for email alerts to function. Without SMTP configuration, the app runs but cannot send notifications.

**Note on database configuration:** `DATABASE_URL` controls the certificate database location (e.g., `sqlite:///./cert_watch.db`). `DATA_DIR` is used for auxiliary files. For most deployments, only `DATABASE_URL` matters — `DATA_DIR` is a legacy setting that will be removed in a future version.

## Alert Thresholds

### Leaf Certificates (End-Entity)

| Threshold | Days Before Expiry | Status |
|-----------|-------------------|--------|
| First Alert | 14 days | Yellow |
| Second Alert | 7 days | Yellow |
| Third Alert | 3 days | Red |
| Fourth Alert | 1 day | Red |

### Chain Certificates (Intermediate/Root CA)

| Threshold | Days Before Expiry | Status |
|-----------|-------------------|--------|
| First Alert | 30 days | Yellow |
| Second Alert | 14 days | Yellow |
| Third Alert | 7 days | Red |

Each threshold fires **at most once per certificate** to prevent alert spam.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     cert-watch                              │
├─────────────────────────────────────────────────────────────┤
│  Web Layer (FastAPI + Jinja2)                               │
│  ├── Dashboard (FR-01) — List view with color coding        │
│  ├── Host Scanning (FR-02) — TLS handshake extraction       │
│  └── Certificate Upload (FR-03) — File parsing            │
├─────────────────────────────────────────────────────────────┤
│  Services                                                   │
│  ├── Certificate Parser — X.509 extraction                  │
│  ├── TLS Scanner — Host scanning                            │
│  ├── Alert Service — Email notifications                    │
│  └── Scheduler — Daily scan cycle                           │
├─────────────────────────────────────────────────────────────┤
│  Data Layer                                                 │
│  ├── Repository Pattern (SQLite with MSSQL-ready ABCs)    │
│  └── SQLite — Default database (external DB future option)   │
└─────────────────────────────────────────────────────────────┘
```

See [CONVENTIONS.md](CONVENTIONS.md) for detailed architecture conventions.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard (HTML) |
| `/api/certs` | GET | List all certificates |
| `/api/certs` | POST | Add host for scanning |
| `/api/certs/upload` | POST | Upload certificate file |
| `/api/certs/{id}` | DELETE | Delete certificate entry |
| `/api/scan` | POST | Trigger manual scan |
| `/health` | GET | Health check |

## Project Structure

```
cert-watch/
├── src/cert_watch/           # Main package
│   ├── core/                 # Config and models
│   ├── db/                   # Database layer
│   ├── models/               # Domain models
│   ├── repositories/         # Repository pattern
│   ├── services/             # Business logic
│   └── web/                  # FastAPI routes
├── tests/                    # Test suite
├── k8s/                      # Kubernetes manifests
│   ├── namespace.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── pvc.yaml
│   ├── configmap.yaml
│   └── OPERATIONS.md         # Kubernetes ops guide
├── docs/                     # Documentation
├── CONVENTIONS.md            # Architecture conventions
├── pyproject.toml           # Project configuration
└── README.md                # This file
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cert_watch --cov-report=html

# Run specific test file
pytest tests/test_dashboard.py -v
```

### Code Organization

- **Models** in `models/` — Pure data containers
- **Business logic** in `services/` — Alert evaluation, scanning
- **Repositories** in `repositories/` — Data access abstraction
- **Web routes** in `web/` — FastAPI routes and templates

See [CONVENTIONS.md](CONVENTIONS.md) for full conventions.

## Operations

### Docker

Build and run:
```bash
docker build -t cert-watch:latest .
docker run -p 8000:8000 -e SMTP_HOST=smtp.example.com cert-watch:latest
```

### Kubernetes

See [k8s/OPERATIONS.md](k8s/OPERATIONS.md) for:
- Deployment procedures
- Scaling instructions
- Troubleshooting guide
- Upgrade procedures
- Backup/restore operations

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

- Follow existing code style (enforced by ruff)
- Add tests for new functionality
- Update documentation for API changes
- Ensure Docker build passes

## Future Roadmap

- [ ] MSSQL/PostgreSQL backend option
- [ ] Teams/Slack webhook notifications
- [ ] REST API authentication
- [ ] Certificate renewal automation
- [ ] Prometheus metrics export

## License

[MIT](LICENSE) — See LICENSE file for details.

---

**Built with:** Python · FastAPI · Jinja2 · HTMX · SQLite

**Deploy on:** Docker · Kubernetes · Bare Metal
