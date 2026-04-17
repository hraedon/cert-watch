# cert-watch Conventions

This document defines architectural conventions for all implementing agents.


## Factory Pattern Library

*⚠️ This section is auto-merged from factory templates. **DO NOT EDIT** — changes will be overwritten.*

## Factory Pattern Library

*This section is auto-merged from `factory/templates/CONVENTIONS.md`.  
**DO NOT EDIT** — changes here will be overwritten by factory updates.  
To update patterns, modify the factory template and regenerate.*

---

## ⚠️ CRITICAL PATTERNS (Read First)

### 1. Route Registration — Auto-Discovery Prefix Conflict

**The Bug:** Double-prefix causes 404 errors and is often masked by tests that accept 404 responses.

**When It Happens:**
- Using `web/routes/_registry.py` auto-discovery
- Filename follows pattern: `frNN_description.py`
- Code explicitly sets `prefix=` in `create_router()`

**The Problem:**
```python
# File: fr03_upload.py
router = APIRouter(prefix='/fr03-upload')  # Agent adds this

# _registry.py does this automatically:
app.include_router(router, prefix='/fr03-upload')  # From filename
```

**Result:** Routes registered at `/fr03-upload/fr03-upload/...` — unreachable!

**The Rule:**
- If using auto-discovery (filename = `frNN_*.py`): **NEVER** set explicit `prefix=` in `create_router()`
- Auto-discovery extracts prefix from filename automatically

**✅ Correct:**
```python
# fr03_upload.py
from fastapi import APIRouter

router = APIRouter()  # No prefix! Auto-discovery adds it from filename

@router.post("/")  # Full path: /fr03-upload/
async def upload(): ...
```

**❌ Wrong:**
```python
# fr03_upload.py
router = APIRouter(prefix='/fr03-upload')  # ❌ Double prefix bug!

@router.post("/")  # Full path: /fr03-upload/fr03-upload/
async def upload(): ...
```

**Detection:**
- Tests that accept 404 as valid response mask this bug
- Reviewer should check: router prefix + auto-discovery prefix = single prefix only

---

## Database Access Patterns

### Repository Pattern (Mandatory)

**The Rule:** All database access MUST use the repository pattern via FastAPI Depends.

**Why:** 
- Enables future MSSQL migration (abstraction layer)
- Prevents connection leaks
- Enables testing with mocks

**✅ Correct:**
```python
from web.deps import get_repo

@router.get("/certs")
async def list_certs(repo = Depends(get_repo)):
    return repo.get_all()
```

**❌ Wrong:**
```python
import sqlite3  # ❌ Never import directly

@router.get("/certs")
async def list_certs():
    conn = sqlite3.connect("/hardcoded/path")  # ❌ Hardcoded path
    # ❌ No cleanup, no DI
```

### Database Access — MUST/MUST NOT Rules

| Rule | Severity | Description |
|------|----------|-------------|
| **MUST** | Blocking | Use `Depends(get_repo())` from `web/deps.py` for all database access in route handlers |
| **MUST NOT** | Blocking | Import `sqlite3` or any database driver directly in route files |
| **MUST NOT** | Blocking | Open database connections outside of dependency injection context |
| **MUST NOT** | Blocking | Hardcode database paths — use config module via `get_db()` |
| **MUST** | Required | Close database connections via context managers or dependency yield |

**Why These Rules Exist:**
- Multiple agents implementing FRs in parallel must use ONE database access pattern
- Without these rules, each agent invents their own path resolution (cert-watch-4 had 5 different strategies)
- Connection leaks occur when agents open connections without proper cleanup

---

## Service Wiring Patterns

### ABC + Concrete + Factory + Lifespan (4-Layer Pattern)

**Purpose:** Ensure services are both testable AND actually run in production.

**The Pattern:**

1. **ABC Definition** (`services/scheduler.py`):
```python
class ScanScheduler(ABC):
    @abstractmethod
    async def schedule(self, callback: Callable): ...
```

2. **Concrete Implementation** (`services/scheduler_impl.py`):
```python
class APSchedulerImpl(ScanScheduler):
    def __init__(self): ...
```

3. **Factory Function** (`web/deps.py`):
```python
def get_scheduler() -> ScanScheduler:
    return APSchedulerImpl()
```

4. **Lifespan Wiring** (`web/app_factory.py`):
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = get_scheduler()
    await scheduler.start()  # ✅ Actually starts!
    app.state.scheduler = scheduler
    yield
    await scheduler.stop()
```

**Common Bug — Orphan Services:**
```python
# services/scheduler_impl.py
class APSchedulerImpl: ...  # Implemented but...

# app_factory.py — FORGOT to wire it!
# Scheduler exists but NEVER STARTS in production
```

**Detection:**
- Integration review checks for "orphan services"
- Service imported in tests but never in production code

---

## Testing Patterns

### Real vs Mock (Critical for DB/External)

**The Rule:** For database/external service tests, use REAL resources, not mocks.

**Why:** Catches type errors, connection issues, transaction bugs that mocks hide.

**✅ Correct:**
```python
@pytest.fixture
async def repo():
    conn = await aiosqlite.connect(':memory:')  # Real SQLite
    yield SqliteRepository(conn)
    await conn.close()
```

**❌ Wrong:**
```python
@pytest.fixture
async def repo():
    mock = MagicMock()  # ❌ Mocks return whatever you ask
    mock.get_all.return_value = [{"id": 1}]  # ❌ No validation!
```

---

## Merge Artifact Patterns

### What to Watch For

After merge (Stage 7), check for:

1. **Duplicate method definitions** — Two implementations merged
2. **Shadowed assignments** — Variable assigned twice, second overwrites first
3. **Import conflicts** — Same class imported from two different modules

**Detection:**
- Static analysis in Stage 7.5
- AST-based duplicate detection
- Integration review

---

## State Management Patterns

### Database Idempotency (NEVER Use In-Memory State)

**The Rule:** DELETE operations are already idempotent at the database level. NEVER implement idempotency tracking using in-memory state.

**The Bug:** Using function attributes or module-level dicts/sets to track "already deleted" items:

```python
# ❌ WRONG — Breaks on restart, leaks memory, no isolation
def _get_deleted_set(repo):
    if not hasattr(_get_deleted_set, "_deleted_sets"):
        _get_deleted_set._deleted_sets = {}  # ❌ Function attribute as global state
    return _get_deleted_set._deleted_sets.setdefault(id(repo), set())

@router.delete("/items/{id}")
def delete_item(id: int, repo = Depends(get_repo)):
    deleted = _get_deleted_set(repo)
    if id in deleted:
        return {"already_deleted": True}  # ❌ Only works in this process!
    repo.delete(id)
    deleted.add(id)  # ❌ Memory leak: grows forever
```

**Why This Fails:**
1. **Restart loses state** — After server restart, `deleted` is empty; re-deleting returns 404 instead of idempotent 200
2. **Memory leak** — Deleted IDs accumulate forever, never garbage collected
3. **No isolation** — All requests share the same set (no per-user/per-session isolation)
4. **Wrong abstraction** — `id(repo)` can be reused by Python GC for different objects

**The Truth:** Database DELETE is already idempotent:
- `DELETE FROM table WHERE id = ?` succeeds whether row exists or not
- `ON DELETE CASCADE` handles related rows
- Repository's `delete_entry()` should be a no-op for missing rows

**✅ Correct:**
```python
@router.delete("/items/{id}")
def delete_item(id: int, repo = Depends(get_repo)):
    # Just delete — database handles idempotency
    deleted = repo.delete_entry(id)  # Returns True if deleted, False if not found
    if not deleted:
        raise HTTPException(404, "Not found")
    return {"deleted": id}  # Same response for first or Nth delete
```

**Repository Contract:**
```python
class AbstractRepository(ABC):
    @abstractmethod
    def delete_entry(self, entry_id: int) -> bool:
        """Delete entry. Returns True if deleted, False if not found.
        
        Must be idempotent — no error if entry doesn't exist.
        """
```

**Related Anti-Pattern: Function Attribute State**

Never store mutable state on function objects:
```python
# ❌ NEVER do this
def handler():
    if not hasattr(handler, "_state"):
        handler._state = {}  # ❌ Module-level mutable state
    handler._state[key] = value  # ❌ Leaks, breaks on restart
```

Use these instead:
- **Database** — For persistent idempotency/state
- **Redis/Memcached** — For ephemeral but shared state
- **FastAPI app state** — For singleton service state (not per-request)
- **Request-scoped context** — For per-request state (doesn't leak)

---

## Import Safety Patterns

### No Side Effects at Module Level

**The Rule:** Never call functions that produce side effects at the top level of a module.

**The Bug:** Creating app instances, opening database connections, or making network calls
at module scope. These execute on `import`, which means:
- Tests importing the module trigger side effects (often crash without env vars)
- Other modules importing it get half-initialized state
- The object is shared across all contexts (test isolation breaks)

**❌ Wrong:**
```python
# app_factory.py — THIS CRASHES ON IMPORT IN TESTS
app = create_app()  # ❌ Calls Settings() which requires env vars!

def create_app():
    settings = Settings()  # Reads env vars — fails without them
    ...
```

**✅ Correct:**
```python
# app_factory.py
def create_app(settings: Settings | None = None):
    settings = settings or Settings()
    ...

# __main__.py or lifespan
if __name__ == "__main__":
    app = create_app()
    uvicorn.run(app)
```

**Detection:** Static analysis flags function calls at module scope (excluding
logging, dataclass, lru_cache, and class definitions).

---

### No Hardcoded Relative Paths

**The Rule:** Never hardcode paths like `"src/..."`, `"./data/db"`, or `"../config"`.
Use `Path(__file__).parent` or configuration variables.

**❌ Wrong:**
```python
templates = Jinja2Templates(directory="src/myapp/web/templates")  # ❌ Breaks when CWD differs
conn = sqlite3.connect("./data/app.db")  # ❌ Relative to CWD, not project
```

**✅ Correct:**
```python
from pathlib import Path
BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))
```

---

## Error Handling Patterns

### Catch Specific Exceptions, Not Strings

**The Rule:** Never classify exceptions by searching for substrings in error messages.
Error messages change between library versions, locales, and Python versions.

**❌ Wrong:**
```python
except Exception as e:
    if "invalidcredentials" in str(e):  # ❌ Fragile!
        raise AuthError("bad creds")
    if "timeout" in str(e).lower():  # ❌ Breaks if library changes wording
        raise TimeoutError("conn timeout")
```

**✅ Correct:**
```python
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

except LDAPBindError:
    raise AuthError("bad creds")
except LDAPSocketOpenError:
    raise TimeoutError("conn timeout")
```

---

## Implementation Completeness

### No NotImplementedError Stubs in Production

**The Rule:** Every method in production code must be implemented. If a method is
intentionally unimplemented, mark it with `@abstractmethod` in an ABC.

**❌ Wrong:**
```python
class PyWinRMService:  # Concrete class, not ABC
    def execute(self, host, command):
        raise NotImplementedError  # ❌ Crashes at runtime!
```

**✅ Correct (option A — implement it):**
```python
class PyWinRMService:
    def execute(self, host, command):
        session = winrm.Session(host, auth=...)
        result = session.run_cmd(command)
        return WinRMResult(exit_code=result.status_code, ...)
```

**✅ Correct (option B — make it abstract):**
```python
class WinRMService(ABC):
    @abstractmethod
    def execute(self, host, command): ...
```

---

## Shared Utilities

### No Duplicate Functions Across Modules

**The Rule:** If two modules define the same utility function, extract it to a shared module.

**❌ Wrong:**
```python
# routes/fr02_dashboard.py
def format_duration(seconds):
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

# routes/fr04_bulk.py  — same function copied!
def format_duration(seconds):
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
```

**✅ Correct:**
```python
# web/formatting.py
def format_duration(seconds):
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

# routes/fr02_dashboard.py
from web.formatting import format_duration
```

---

---

## Version History

- **v1.4** (2026-04-16): Restructured with Project-Specific and Factory Pattern Library sections (breadcrumb 113)
- **v1.3** (2026-04-16): Added explicit MUST/MUST NOT rules table for database access (breadcrumb 100)
- **v1.2** (2026-04-16): Added import safety, hardcoded paths, exception handling, stub detection, cross-module duplication
- **v1.1** (2026-04-14): Added database idempotency + function-attribute-state anti-pattern
- **v1.0** (2026-04-14): Initial template — double-prefix bug, repository pattern, orphan services

---




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


## Auto-detected conventions

- [web_framework] FastAPI
- [datetime_convention] naive UTC (datetime.utcnow()). All datetimes are naive, compared against datetime.utcnow().
- [config_module] cert_watch/core/config
- [repository_abc] src/cert_watch/repositories/base.py
- [database] SQLite (via sqlite3 module)
- [package_name] cert_watch
