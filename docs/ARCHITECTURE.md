# Architecture

This document describes the system architecture, design decisions, and data flow for cert-watch.

## Overview

Cert-watch follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                        Web Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Dashboard  │  │    Scan     │  │   Alerts/Scheduler  │  │
│  │  (FR-01)    │  │(FR-02/FR-03)│  │   (FR-04/FR-05)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      Service Layer                           │
│  ┌─────────────────┐  ┌─────────────────────────────────────┐│
│  │ AlertService    │  │        ScanSchedulerService         ││
│  │ (thresholds,  │  │  (daily scan, certificate refresh)  ││
│  │  email sending)│  │                                     ││
│  └─────────────────┘  └─────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Repository Layer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Certificate│  │    Alert    │  │    Scan History     │  │
│  │ Repository │  │ Repository  │  │     Repository      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     Database Layer                           │
│                    SQLite (v1) / MSSQL (v2)                  │
└─────────────────────────────────────────────────────────────┘
```

## High-Level Design Decisions

### 1. Repository Pattern

**Decision**: All database access goes through repository ABCs with SQLite implementation for v1.

**Rationale**:
- Enables future database migration (MSSQL planned for v2)
- Simplifies testing with mock repositories
- Centralizes query logic

**Implementation**:
```python
# Abstract base class
class CertificateRepository(ABC):
    @abstractmethod
    async def get_all(self, limit: int = 1000) -> list[Certificate]: ...

# Concrete implementation
class SQLiteCertificateRepository(CertificateRepository):
    async def get_all(self, limit: int = 1000) -> list[Certificate]:
        # SQLite-specific implementation
```

### 2. Route Auto-Discovery

**Decision**: Routes are auto-discovered from `web/routes/` directory; no manual registration.

**Rationale**:
- Prevents merge conflicts when multiple agents add routes
- Enforces consistent naming conventions
- Eliminates forgotten route registrations

**Implementation**:
```python
# app_factory.py scans routes/ directory
for module_info in pkgutil.iter_modules([str(routes_dir)]):
    module = importlib.import_module(f"{routes.__name__}.{module_info.name}")
    if hasattr(module, "router"):
        app.include_router(module.router)
```

**Important**: Route files must NOT set explicit `prefix=` in `APIRouter()`. The prefix is extracted from the filename (`fr01_dashboard.py` → `/fr01-dashboard/`).

### 3. Naive UTC Datetimes

**Decision**: All datetimes are stored and compared in naive UTC.

**Rationale**:
- SQLite has limited timezone support
- Avoids timezone conversion bugs
- Simplifies comparison logic

**Convention**:
```python
# Always use utcnow()
now = datetime.utcnow()

# Store without timezone info
not_after: datetime  # Naive UTC
```

### 4. Centralized Formatters

**Decision**: All certificate formatting in `core/formatters.py`.

**Rationale**:
- Ensures consistent formatting across the application
- Single point for certificate parsing (PEM/DER/TLS)
- Canonical fingerprint computation

**Key Functions**:
- `format_subject(cert)` - Extract CN or fallback
- `compute_thumbprint(cert)` - SHA-256 fingerprint
- `parse_certificate_file(data)` - Parse PEM/DER files
- `extract_certificate_from_tls(hostname, port)` - TLS handshake

### 5. Service Layer for Business Logic

**Decision**: Complex business logic in service classes, not routes or models.

**Rationale**:
- Routes handle HTTP concerns only
- Models are pure data (dataclasses)
- Services are testable independently
- Enables different implementations (stub vs real)

**Structure**:
```
services/
├── base.py              # ABC definitions
├── alert_service_impl.py  # FR-04 implementation
└── scheduler_impl.py    # FR-05 implementation
```

## Data Flow

### Adding a Host (FR-02)

```
User → POST /scan/add-host
            ↓
    fr02_scan.py (validation)
            ↓
    extract_certificate_from_tls()
            ↓
    TLS Handshake → x509.Certificate
            ↓
    CertificateRepository.create()
            ↓
    SQLite INSERT
            ↓
    Redirect to Dashboard
```

### Uploading a Certificate (FR-03)

```
User → POST /fr03-upload/upload
            ↓
    fr03_upload.py (file validation)
            ↓
    parse_certificate_file(data)
            ↓
    Parse PEM/DER → x509.Certificate
            ↓
    CertificateRepository.create()
            ↓
    SQLite INSERT
            ↓
    HTML Response with details
```

### Daily Scan Cycle (FR-05)

```
APScheduler → CronTrigger (06:00 daily)
            ↓
    ScanSchedulerImpl.run_daily_scan()
            ↓
    Get all SCANNED certificates
            ↓
    For each certificate:
        ├─→ extract_certificate_from_tls()
        ├─→ Update certificate fields
        └─→ CertificateRepository.update()
            ↓
    ScanHistoryRepository.create()
            ↓
    AlertService.evaluate_alerts()
            ↓
    Send pending alerts
```

### Alert Evaluation (FR-04)

```
Scheduled or Manual Trigger
            ↓
    AlertService.evaluate_alerts()
            ↓
    Get all certificates
            ↓
    For each certificate:
        ├─→ Calculate days_remaining
        ├─→ Check thresholds (leaf: 14/7/3/1, chain: 30/14/7)
        ├─→ Check if alert already sent
        └─→ Create pending alert if needed
            ↓
    AlertRepository.create()
            ↓
    AlertService.send_pending_alerts()
            ↓
    SMTP send → Email delivered
```

## Database Schema

### Certificates Table

```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_type TEXT NOT NULL,  -- leaf, intermediate, root
    source TEXT NOT NULL,            -- scanned, uploaded
    hostname TEXT,                   -- For scanned entries
    port INTEGER,
    label TEXT,                      -- User-defined label
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,    -- Used for sorting/urgency
    fingerprint TEXT NOT NULL UNIQUE,  -- SHA-256 thumbprint
    serial_number TEXT NOT NULL,
    chain_fingerprint TEXT,          -- Links to parent leaf
    chain_position INTEGER DEFAULT 0,  -- 0 = leaf
    pem_data BLOB,                   -- Full certificate PEM
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    last_scanned_at TIMESTAMP,
    source_hostname TEXT,            -- For chain certs
    source_port INTEGER
);
```

### Alerts Table

```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL,        -- expiry_warning, expired, scan_failure
    days_remaining INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, sent, failed
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL,
    sent_at TIMESTAMP
);
```

### Scan History Table

```sql
CREATE TABLE scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'success',  -- success, partial, failure
    total_hosts INTEGER DEFAULT 0,
    successful_hosts INTEGER DEFAULT 0,
    failed_hosts INTEGER DEFAULT 0,
    updated_certificates INTEGER DEFAULT 0,
    error_message TEXT
);
```

## Component Details

### Models

Pure dataclasses with minimal logic:

```python
@dataclass
class Certificate:
    id: int | None = None
    certificate_type: CertificateType = CertificateType.LEAF
    source: CertificateSource = CertificateSource.SCANNED
    subject: str = ""
    issuer: str = ""
    not_after: datetime = field(default_factory=datetime.utcnow)
    fingerprint: str = ""
    
    @property
    def days_remaining(self) -> int:
        return compute_days_remaining(self.not_after)
    
    @property
    def status_color(self) -> str:
        return get_status_color(self.days_remaining)
```

### Repository Implementations

**SQLiteConnectionPool**: Manages database connections with:
- Context manager for automatic cleanup
- Thread-safe connection handling
- Automatic schema initialization

**SQLiteCertificateRepository**: Implements all CRUD operations with:
- Naive UTC datetime adapters
- Row-to-model conversion
- Query optimization with indexes

### Services

**AlertServiceImpl**:
- Threshold evaluation logic
- SMTP email sending
- Alert history tracking

**ScanSchedulerImpl**:
- APScheduler integration
- Daily scan orchestration
- Error isolation per host

## Security Considerations

1. **No Authentication**: v1 assumes network-level access control
2. **Database**: SQLite file permissions should restrict access
3. **SMTP**: Password stored in environment variables only
4. **TLS**: Uses system default SSL context with certificate validation

## Future Extensibility

### Planned for v2

1. **MSSQL Backend**: Alternative repository implementation
2. **Authentication**: User management and access control
3. **Webhook Notifications**: Alternative to email alerts
4. **Certificate Renewal**: Automated renewal workflows

### Extension Points

- New certificate sources: Add to `CertificateSource` enum
- New alert types: Add to `AlertType` enum
- New repositories: Implement repository ABCs
- New formatters: Add to `core/formatters.py`
