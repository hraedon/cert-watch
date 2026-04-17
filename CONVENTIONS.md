# cert-watch Conventions

This document defines architectural conventions for all implementing agents.

## Project Overview

- **Package Name:** `cert_watch`
- **Web Framework:** FastAPI
- **Database:** SQLite (with repository pattern for future extensibility)
- **Scheduler:** APScheduler
- **Language:** Python 3.12+

## Datetime Convention

**MUST USE:** Naive UTC datetimes throughout the codebase.

- Store all datetimes in UTC without timezone info
- Convert to UTC at system boundaries (parsing, display)
- Use `datetime.utcnow()` for current time
- Never use local time or timezone-aware datetimes internally

## Directory Structure

```
src/cert_watch/
├── core/           # Utilities, config, formatters
├── models/         # Data models (dataclasses)
├── repositories/   # Database access (ABC + SQLite impl)
├── services/       # Business logic services (ABC + impl)
├── web/            # Web layer
│   ├── routes/     # Route modules (one per FR)
│   ├── deps.py     # FastAPI dependencies
│   ├── app_factory.py  # App creation (FROZEN)
│   └── templates/  # Jinja2 templates
└── db/             # Database schema, migrations

tests/              # Test files
docs/               # Documentation
```

## Critical Rules for Implementing Agents

### 1. Route Isolation (CRITICAL)

**NEVER** edit `web/app_factory.py`. It is complete and auto-discovers routes.

**MUST DO:**
- Create ONE file per FR in `src/cert_watch/web/routes/`
- Export an `APIRouter` named `router` from your file
- Example: `fr01_dashboard.py` contains the FR-01 routes

**Route file template:**
```python
from fastapi import APIRouter, Request, Depends
from ...deps import get_repo

router = APIRouter(prefix="/optional-prefix")

@router.get("/")
async def my_handler(repo=Depends(get_repo)):
    pass
```

### 2. Database Access (CRITICAL)

**MUST NOT:**
- Import `sqlite3` directly in route files
- Create database connections in business logic
- Use raw SQL in route handlers

**MUST DO:**
- Use `Depends(get_repo())` for repository access
- Work with repository ABC interface only
- Let the repository handle all SQL

Example:
```python
from ..deps import get_repo
from ...repositories import CertificateRepository

@router.get("/")
async def list_certs(repo: CertificateRepository = Depends(get_repo())):
    return await repo.get_all()
```

### 3. Certificate Formatting (CRITICAL)

**MUST USE** `core/formatters.py` for all certificate field formatting:

- `format_subject(cert)` — canonical subject string
- `compute_thumbprint(cert)` — canonical fingerprint (SHA-256 hex)
- `format_datetime(dt)` — canonical datetime string for display
- `parse_certificate_file(data)` — parse uploaded certificate files
- `extract_certificate_from_tls(hostname, port)` — TLS handshake extraction

**NEVER** format certificate fields differently in different modules.

### 4. Configuration (CRITICAL)

**ONE config module:** `core/config.py`

Use `Settings.get()` to access configuration:
```python
from ...core.config import Settings

settings = Settings.get()
```

### 5. Model Usage

Models are dataclasses in `models/` directory. They contain:
- Field definitions only
- Simple computed properties (no complex logic)
- Type hints for all fields

Business logic belongs in services, not models.

### 6. Repository Pattern

All database access goes through repository ABC:
- `CertificateRepository` — certificate CRUD
- `AlertRepository` — alert history
- `ScanHistoryRepository` — scan logging

SQLite implementation is in `repositories/sqlite.py`.

### 7. Error Handling

- Use custom exceptions from `core/exceptions.py`
- Wrap external errors (TLS, SMTP) in domain exceptions
- Let FastAPI exception handlers format responses

### 8. Background Tasks

- Use FastAPI's `BackgroundTasks` for non-blocking work
- Use APScheduler (via `services/scheduler.py`) for scheduled work
- Never block the main thread with I/O

### 9. Testing

- Test files mirror the source structure under `tests/`
- Use pytest fixtures from `tests/conftest.py`
- Use the test client from `conftest.py` for web tests

## Dependencies

Install with: `pip install -e .[dev]`

Key dependencies:
- `fastapi` — web framework
- `uvicorn` — ASGI server
- `cryptography` — certificate parsing and TLS
- `apscheduler` — daily scanning scheduler
- `jinja2` — templates
- `pydantic` — validation and settings

## Color Coding Rules

Per spec FR-01:
- Red: < 7 days remaining
- Yellow: < 30 days remaining  
- Green: > 30 days remaining

## Alert Thresholds

Per spec FR-04:
- Leaf certificates: 14, 7, 3, 1 days before expiry
- Chain certificates: 30, 14, 7 days before expiry

## File Naming Conventions

- Route files: `fr{N}_{name}.py` (e.g., `fr01_dashboard.py`)
- Service files: `{name}_service.py`
- Repository files: `{name}_repository.py`
- Model files: `{name}.py` (singular)

## Import Style

Use absolute imports from package root:
```python
from cert_watch.models.certificate import Certificate
from cert_watch.core.formatters import format_subject
```

## Git Workflow

- Each FR agent works on their assigned file(s) only
- Never commit `app_factory.py`, `deps.py`, or shared utilities
- Use feature branches named `fr{N}-{description}`
