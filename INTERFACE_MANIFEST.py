# Interface manifest — auto-generated after Phase 1.
# Read this before writing any code that calls into existing modules.

### src/cert_watch/core/config.py [FR-01] ###
class Settings(BaseSettings): ...
    """Application settings loaded from environment or .env file."""
@property ...
    """Get the SQLite database file path."""
@classmethod ...
    """Get the singleton settings instance.
    
    This is the ONLY way to access settings in the application.
    In tests, pass a settings instance to use that instead of the singleton."""
def ensure_data_dirs(self) -> None: ...
    """Create data directories if they don't exist."""

### src/cert_watch/core/exceptions.py [unknown] ###
class CertWatchError(Exception): ...
    """Base exception for cert-watch."""
class CertificateError(CertWatchError): ...
    """Certificate-related errors."""
class CertificateParseError(CertificateError): ...
    """Failed to parse certificate file."""
class TLSError(CertWatchError): ...
    """TLS handshake errors."""
class TLSConnectionError(TLSError): ...
    """Failed to establish TLS connection."""
class TLSHandshakeError(TLSError): ...
    """TLS handshake failed."""
class AlertError(CertWatchError): ...
    """Email alert errors."""
class SMTPConfigurationError(AlertError): ...
    """SMTP not configured properly."""
class AlertSendError(AlertError): ...
    """Failed to send alert email."""
class RepositoryError(CertWatchError): ...
    """Database repository errors."""
class NotFoundError(RepositoryError): ...
    """Record not found in database."""

### src/cert_watch/core/formatters.py [fr-01] ###
def format_subject(cert: x509.Certificate) -> str: ...
    """Format certificate subject as a canonical string.
    
    Extracts the Common Name (CN) from the subject. Falls back to
    organizational fields if CN is not present.
    
    Args:
        cert: The X.509 certificate
    
    Returns:
        Canonical subject string"""
def format_issuer(cert: x509.Certificate) -> str: ...
    """Format certificate issuer as a canonical string.
    
    Args:
        cert: The X.509 certificate
    
    Returns:
        Canonical issuer string"""
def compute_thumbprint(cert: x509.Certificate) -> str: ...
    """Compute SHA-256 fingerprint of certificate.
    
    Args:
        cert: The X.509 certificate
    
    Returns:
        Hex-encoded SHA-256 fingerprint (lowercase, no colons)"""
def format_datetime(dt: datetime) -> str: ...
    """Format datetime for display in canonical format.
    
    Args:
        dt: The datetime (naive UTC)
    
    Returns:
        ISO 8601 format string (YYYY-MM-DD HH:MM:SS UTC)"""
def compute_days_remaining(not_after: datetime) -> int: ...
    """Compute days remaining until expiry.
    
    Args:
        not_after: Certificate expiry datetime (naive UTC)
    
    Returns:
        Days remaining (negative if expired)"""
def get_status_color(days_remaining: int) -> str: ...
    """Get color code based on days remaining.
    
    Per spec FR-01:
    - Red: < 7 days
    - Yellow: < 30 days
    - Green: > 30 days
    
    Args:
        days_remaining: Days until expiry
    
    Returns:
        Color code: "red", "yellow", or "green""""
def parse_certificate_file(data: bytes) -> tuple[x509.Certificate, list[x509.Certificate]]: ...
    """Parse certificate file and extract chain.
    
    Handles PEM and DER encoded files.
    
    Args:
        data: Raw certificate file bytes
    
    Returns:
        Tuple of (leaf certificate, list of chain certificates)
    
    Raises:
        CertificateParseError: If parsing fails"""
async def extract_certificate_from_tls(hostname: str, port: int) -> tuple[x509.Certificate, list[x509.Certificate]]: ...
    """Extract certificate via TLS handshake.
    
    Args:
        hostname: Target hostname
        port: Target port
    
    Returns:
        Tuple of (leaf certificate, list of chain certificates)
    
    Raises:
        TLSConnectionError: If connection fails
        TLSHandshakeError: If handshake fails"""
def serialize_certificate(cert: x509.Certificate) -> bytes: ...
    """Serialize certificate to PEM format.
    
    Args:
        cert: The X.509 certificate
    
    Returns:
        PEM-encoded certificate bytes"""

### src/cert_watch/models/alert.py [unknown] ###
class AlertType(Enum): ...
    """Type of alert."""
class AlertStatus(Enum): ...
    """Status of alert."""
@dataclass ...
    """Alert model representing a sent or pending alert."""

### src/cert_watch/models/certificate.py [unknown] ###
class CertificateType(Enum): ...
    """Type of certificate entry."""
class CertificateSource(Enum): ...
    """Source of certificate entry."""
@dataclass ...
    """Certificate model representing a monitored certificate."""
@property ...
    """Check if certificate has expired."""
@property ...
    """Compute days remaining until expiry."""
@property ...
    """Get status color based on days remaining."""
@property ...
    """Get display name for this certificate."""
@property ...
    """Check if this is a leaf certificate."""
@property ...
    """Check if this is a chain certificate."""

### src/cert_watch/models/scan_history.py [unknown] ###
class ScanStatus(Enum): ...
    """Status of a scan operation."""
@dataclass ...
    """Scan history model representing a scan cycle."""

### src/cert_watch/repositories/base.py [unknown] ###
class CertificateRepository(ABC): ...
    """Repository for certificate CRUD operations."""
class AlertRepository(ABC): ...
    """Repository for alert CRUD operations."""
class ScanHistoryRepository(ABC): ...
    """Repository for scan history operations."""
@abstractmethod ...
    """Get certificate by ID."""
@abstractmethod ...
    """Get certificate by fingerprint."""
@abstractmethod ...
    """Get all certificates, sorted by urgency (days remaining ascending)."""
@abstractmethod ...
    """Get certificates by hostname."""
@abstractmethod ...
    """Create new certificate entry."""
@abstractmethod ...
    """Update existing certificate."""
@abstractmethod ...
    """Delete certificate by ID."""
@abstractmethod ...
    """Get chain certificates for a given leaf."""
@abstractmethod ...
    """Get alert by ID."""
@abstractmethod ...
    """Get all pending alerts."""
@abstractmethod ...
    """Get alerts for a specific certificate."""
@abstractmethod ...
    """Create new alert."""
@abstractmethod ...
    """Mark alert as sent."""
@abstractmethod ...
    """Mark alert as failed with error message."""
@abstractmethod ...
    """Get scan history by ID."""
@abstractmethod ...
    """Get recent scan history entries."""
@abstractmethod ...
    """Create new scan history entry."""
@abstractmethod ...
    """Mark scan as complete with status and results."""

### src/cert_watch/services/base.py [unknown] ###
class CertificateService(ABC): ...
    """Service for certificate business logic."""
class AlertService(ABC): ...
    """Service for alert business logic."""
class ScanSchedulerService(ABC): ...
    """Service for scheduled scanning."""
class CertificateServiceStub(CertificateService): ...
    """Stub implementation of CertificateService for parallel development.
    
    This stub allows other agents to import and reference the service
    while the actual implementation is being developed."""
class AlertServiceStub(AlertService): ...
    """Stub implementation of AlertService for parallel development.
    
    This stub allows other agents to import and reference the service
    while the actual implementation is being developed."""
class ScanSchedulerServiceStub(ScanSchedulerService): ...
    """Stub implementation of ScanSchedulerService for parallel development.
    
    This stub allows other agents to import and reference the service
    while the actual implementation is being developed."""
@abstractmethod ...
    """Scan host for certificates via TLS handshake.
    
    Returns:
        Tuple of (leaf certificate, chain certificates)"""
@abstractmethod ...
    """Upload and parse certificate file.
    
    Args:
        data: Raw certificate file bytes
        label: Optional user-defined label
    
    Returns:
        Created certificate entry"""
@abstractmethod ...
    """Evaluate all certificates and create pending alerts.
    
    Returns:
        List of created alert IDs"""
@abstractmethod ...
    """Send all pending alerts.
    
    Returns:
        Tuple of (sent count, failed count)"""
@abstractmethod ...
    """Run the daily scan cycle."""
@abstractmethod ...
    """Start the background scheduler."""
@abstractmethod ...
    """Stop the background scheduler."""
async def scan_host(self, hostname: str, port: int=443) -> tuple[Certificate, list[Certificate]]: ...
    """Stub - raises NotImplementedError."""
async def upload_certificate(self, data: bytes, label: str | None=None) -> Certificate: ...
    """Stub - raises NotImplementedError."""
async def evaluate_alerts(self) -> list[int]: ...
    """Stub - raises NotImplementedError."""
async def send_pending_alerts(self) -> tuple[int, int]: ...
    """Stub - raises NotImplementedError."""
async def run_daily_scan(self) -> None: ...
    """Stub - raises NotImplementedError."""
def start_scheduler(self) -> None: ...
    """Stub - raises NotImplementedError."""
def stop_scheduler(self) -> None: ...
    """Stub - raises NotImplementedError."""

### src/cert_watch/web/app_factory.py [FR-03] ###
def create_app(settings: Settings | None=None) -> FastAPI: ...
    """Create and configure the FastAPI application.
    
    This function auto-discovers and registers all route modules.
    Implementing agents create new files in routes/ - they do NOT edit this file.
    
    Args:
        settings: Application settings (uses Settings.get() if None)
    
    Returns:
        Configured FastAPI application"""
@app.exception_handler(CertWatchError) ...

### src/cert_watch/web/deps.py [fr-02] ###
async def get_db(request: Request) -> AsyncGenerator[SQLiteConnectionPool, None]: ...
    """Get database connection pool dependency.
    
    Yields the connection pool for use in route handlers."""
def get_repo(request: Request) -> CertificateRepository: ...
    """Create repository dependency.
    
    Usage: repo: CertificateRepository = Depends(get_repo)"""
def get_alert_repo(request: Request) -> AlertRepository: ...
    """Get AlertRepository dependency."""
def get_scan_repo(request: Request) -> ScanHistoryRepository: ...
    """Get ScanHistoryRepository dependency."""

### src/cert_watch/web/main.py [unknown] ###
def main(): ...
    """Run the cert-watch application."""

### src/cert_watch/web/routes/fr01_dashboard.py [FR-01] ###
@router.get('/', response_class=HTMLResponse) ...
    """Main dashboard displaying all certificates.
    
    Shows certificates with:
    - Hostname/label
    - Issuer
    - Expiry date
    - Days remaining
    - Color-coded status (red <7 days, yellow <30 days, green >30 days)
    
    Sorted by urgency (days remaining ascending)."""

### src/cert_watch/web/routes/fr02_scan.py [fr-02] ###
@router.post('/scan/add-host') ...
    """Add a host for TLS scanning.
    
    Accepts form data with hostname and port, performs TLS handshake,
    extracts the certificate and chain, and stores them."""
@router.post('/scan/{cert_id}/rescan') ...
    """Manually rescan an existing certificate entry.
    
    Re-performs TLS handshake for the certificate's hostname and port,
    updating the stored certificate data."""

### src/cert_watch/web/routes/fr03_upload.py [fr-03] ###
@router.post('/upload') ...
    """Handle certificate file upload.
    
    Accepts .cer, .pem, and .crt files. Parses the certificate(s),
    extracts metadata, and creates database entries.
    
    Args:
        request: FastAPI request object
        certificate: Uploaded certificate file
        label: Optional user-provided label
        repo: Certificate repository for database operations
    
    Returns:
        Redirect to result page or error response"""

### tests/conftest.py [fr-02] ###
@pytest.fixture ...
    """Create test settings with temporary database."""
@pytest_asyncio.fixture ...
    """Create a real SQLite connection pool for testing.
    
    This fixture provides a REAL database connection pool using aiosqlite.
    Tests using this fixture perform actual database operations."""
@pytest_asyncio.fixture ...
    """Create a real CertificateRepository using SQLite.
    
    This fixture provides the ACTUAL repository implementation,
    not a mock. Tests using this verify real database behavior."""
@pytest_asyncio.fixture ...
    """Create a real AlertRepository using SQLite."""
@pytest_asyncio.fixture ...
    """Create a real ScanHistoryRepository using SQLite."""
@pytest.fixture ...
    """Generate a set of test X.509 certificates with various expiry dates.
    
    Returns a dict with:
        - expired: Certificate expired 10 days ago
        - critical: Expires in 3 days (red status)
        - warning: Expires in 15 days (yellow status)
        - good: Expires in 60 days (green status)
        - root_ca: Root CA certificate
        - intermediate: Intermediate CA certificate"""
@pytest.fixture ...
    """Create certificate files in various formats.
    
    Returns a dict with file paths for:
        - pem: PEM-encoded certificate
        - cer: DER-encoded certificate (.cer)
        - crt: PEM-encoded certificate (.crt)
        - pem_with_chain: PEM file with certificate + chain"""
@pytest.fixture ...
    """Create a sample Certificate model instance."""
@pytest.fixture ...
    """Create a sample chain Certificate model instance."""
@pytest.fixture ...
    """Create a sample Alert model instance."""
@pytest.fixture ...
    """Create a sample ScanHistory model instance."""
@pytest.fixture ...
    """Create test FastAPI application."""
@pytest.fixture ...
    """Create test client."""
@pytest_asyncio.fixture ...
    """Create async test client for async route testing."""
@pytest.fixture ...
    """Mock SMTP connection for email tests."""
@pytest.fixture ...
    """Mock TLS connection for scanning tests.
    
    Yields a context manager that patches ssl.create_connection and
    ssl.SSLContext.wrap_socket to return mock certificates."""
def cert_to_model(cert: x509.Certificate, **kwargs) -> Certificate: ...
    """Convert an X.509 certificate to a Certificate model."""
@pytest.fixture ...
    """Create a certificate repository populated with test data.
    
    Returns the repository with several certificates already inserted."""

### tests/test_integration_flows.py [unknown] ###
@pytest.mark.asyncio ...
    """Flow Test: Add host → TLS scan → verify chain → dashboard with color coding.
    
    This flow tests:
    - FR-02: Add host and TLS scanning
    - FR-01: Dashboard display with color coding
    - Chain extraction from TLS handshake"""
@pytest.mark.asyncio ...
    """Flow Test: Upload cert file → view in dashboard → verify color coding.
    
    This flow tests:
    - FR-03: Certificate upload and parsing
    - FR-01: Dashboard display with color coding"""
@pytest.mark.asyncio ...
    """Flow Test: Mixed scanned and uploaded certificates in dashboard.
    
    This flow tests:
    - FR-01: Dashboard with mixed sources
    - FR-02: Scanned entries
    - FR-03: Uploaded entries
    - Proper sorting by urgency across all sources"""
@pytest.mark.asyncio ...
    """Flow tests for error scenarios across multiple FRs."""
async def test_complete_flow_add_host_scan_chain_dashboard(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: User adds host, system scans, chains extracted, dashboard shows color coding.
    
    ACT:
    1. User submits add-host form with hostname and port
    2. System performs TLS handshake (mocked network)
    3. System extracts leaf and chain certificates
    4. System stores all certificates
    5. User views dashboard
    
    ASSERT:
    - Leaf certificate stored with source=SCANNED
    - Chain certificates stored and linked to leaf
    - Dashboard shows all certificates
    - Color coding matches days remaining (critical=red)"""
async def test_flow_scan_updates_existing_certificate(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: Rescan updates existing certificate entry.
    
    ACT:
    1. Add host and scan (creates entry)
    2. Rescan the same host
    3. View dashboard
    
    ASSERT:
    - Original entry updated (not duplicated)
    - Updated timestamp reflects rescan
    - Dashboard shows updated information"""
async def test_complete_flow_upload_parse_dashboard(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: User uploads certificate, views in dashboard with correct color.
    
    ACT:
    1. User uploads .pem certificate file (60 days = green)
    2. System parses and stores certificate
    3. User views dashboard
    
    ASSERT:
    - Certificate stored with source=UPLOADED
    - Dashboard shows uploaded certificate
    - Color coding is GREEN (>30 days)
    - Certificate details displayed correctly"""
async def test_flow_upload_with_chain_displays_all_in_dashboard(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: Upload certificate with chain, all entries visible.
    
    ACT:
    1. Upload .pem file containing leaf + intermediate + root
    2. View dashboard
    
    ASSERT:
    - Leaf certificate stored and visible
    - Chain certificates stored
    - All entries have correct type labels"""
async def test_mixed_scanned_and_uploaded_sorted_by_urgency(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: Dashboard shows mixed sources sorted by urgency.
    
    ACT:
    1. Upload certificate (60 days, green)
    2. Scan host and get certificate (3 days, red, critical)
    3. View dashboard
    
    ASSERT:
    - Both certificates visible
    - Critical (3 days) appears before Green (60 days)
    - Correct color coding for each"""
async def test_flow_multiple_scans_same_host_different_times(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: Multiple scans of same host create/update single entry.
    
    ACT:
    1. Scan host.example.com (initial scan)
    2. Scan host.example.com again (update scan)
    3. View dashboard
    
    ASSERT:
    - Single entry for host (or updated entry)
    - No duplicates in dashboard
    - Latest certificate data shown"""
async def test_flow_continues_after_scan_failure(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: Dashboard works even after scan failure.
    
    ACT:
    1. Have existing certificate in dashboard
    2. Attempt scan that fails
    3. View dashboard
    
    ASSERT:
    - Error handled gracefully
    - Existing certificates still visible
    - Dashboard functional"""
async def test_flow_upload_failure_does_not_affect_existing(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """E2E Flow: Failed upload doesn't affect existing certificates.
    
    ACT:
    1. Have existing certificate
    2. Attempt invalid file upload
    3. View dashboard
    
    ASSERT:
    - Upload rejected
    - Existing certificates unaffected"""

### tests/test_type_contracts.py [unknown] ###
@pytest.mark.asyncio ...
    """Type contracts for data flow from HTTP routes to repository."""
@pytest.mark.asyncio ...
    """Type contracts for certificate parser output."""
@pytest.mark.asyncio ...
    """Type contracts for repository method return values."""
@pytest.mark.asyncio ...
    """Type contracts for formatter utility functions."""
@pytest.mark.asyncio ...
    """Type contracts for computed model properties."""
async def test_upload_route_passes_certificate_model_to_repo(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """Upload route passes Certificate model to repo, not dict.
    
    BOUNDARY: HTTP request → Certificate model → repository
    
    This catches the bug where route builds a dict like:
        cert_data = {"subject": "...", ...}
        repo.create(cert_data)  # ❌ Type error in production!
    
    Instead of:
        cert = Certificate(subject="...", ...)
        repo.create(cert)  # ✓ Correct"""
async def test_scan_route_passes_certificate_model_to_repo(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """Scan route passes Certificate model to repo, not dict.
    
    BOUNDARY: TLS scan → Certificate model → repository"""
async def test_parse_certificate_file_returns_x509_certificate_objects(self, test_certificates): ...
    """Parser returns X.509 Certificate objects, not dicts or strings.
    
    BOUNDARY: Raw bytes → cryptography.x509.Certificate
    
    This catches bugs where parser returns:
        {"subject": "...", "not_after": "..."}  # ❌ Dict
    
    Instead of:
        x509.Certificate(...)  # ✓ Proper object"""
async def test_parse_certificate_file_not_after_is_datetime(self, test_certificates): ...
    """Parser returns datetime for not_after, not string.
    
    BOUNDARY: Certificate ASN.1 → Python datetime
    
    Common bug: returning ISO string instead of datetime object."""
async def test_extract_certificate_from_tls_returns_x509_objects(self, test_certificates): ...
    """TLS extractor returns X.509 Certificate objects.
    
    BOUNDARY: SSL socket → cryptography.x509.Certificate"""
async def test_repo_get_by_id_returns_certificate_or_none(self, cert_repo: CertificateRepository, sample_certificate): ...
    """get_by_id returns Certificate or None, never dict.
    
    BOUNDARY: Database row → Certificate model
    
    Catches: Repository returning raw sqlite3.Row instead of model."""
async def test_repo_get_all_returns_list_of_certificates(self, cert_repo: CertificateRepository, sample_certificate): ...
    """get_all returns list[Certificate], not list[dict] or list[Row].
    
    BOUNDARY: Database query → List[Certificate model]"""
async def test_repo_create_returns_certificate_with_id(self, cert_repo: CertificateRepository, sample_certificate): ...
    """Create returns Certificate with id populated.
    
    BOUNDARY: Insert → Certificate model with generated id"""
async def test_repo_returns_naive_utc_datetimes(self, cert_repo: CertificateRepository, sample_certificate): ...
    """Repository returns naive UTC datetimes, not strings or aware datetimes.
    
    BOUNDARY: SQLite timestamp → Python datetime
    
    Per convention: "MUST USE: Naive UTC datetimes throughout""""
async def test_format_subject_returns_string(self, test_certificates): ...
    """format_subject returns str, not Name object.
    
    BOUNDARY: x509.Name → str"""
async def test_compute_thumbprint_returns_string(self, test_certificates): ...
    """compute_thumbprint returns hex string, not bytes.
    
    BOUNDARY: Certificate bytes → hex fingerprint string"""
async def test_compute_days_remaining_returns_int(self, test_certificates): ...
    """compute_days_remaining returns int, not float or timedelta.
    
    BOUNDARY: datetime → int days"""
async def test_get_status_color_returns_string(self): ...
    """get_status_color returns color string, not enum or int.
    
    BOUNDARY: int days → str color code"""
async def test_certificate_days_remaining_returns_int(self, sample_certificate): ...
    """Certificate.days_remaining returns int.
    
    BOUNDARY: Model property → int"""
async def test_certificate_status_color_returns_string(self, sample_certificate): ...
    """Certificate.status_color returns str.
    
    BOUNDARY: Model property → str"""
async def test_certificate_is_expired_returns_bool(self, sample_certificate): ...
    """Certificate.is_expired returns bool.
    
    BOUNDARY: Model property → bool"""
async def test_certificate_is_leaf_returns_bool(self, sample_certificate): ...
    """Certificate.is_leaf returns bool.
    
    BOUNDARY: Model property → bool"""
async def test_certificate_is_chain_returns_bool(self, sample_chain_certificate): ...
    """Certificate.is_chain returns bool.
    
    BOUNDARY: Model property → bool"""
async def tracking_create(cert): ...
async def tracking_create(cert): ...

### tests/test_wiring.py [unknown] ###
@pytest.mark.asyncio ...
    """Verify CertificateService implementation is wired to routes."""
@pytest.mark.asyncio ...
    """Verify repositories are properly wired through deps module."""
@pytest.mark.asyncio ...
    """Verify formatters are used by routes and services."""
@pytest.mark.asyncio ...
    """Verify routes are auto-discovered by app_factory."""
@pytest.mark.asyncio ...
    """Verify routes don't have double-prefix bug.
    
    Per convention: "NEVER set explicit prefix= in create_router()
    when using auto-discovery.""""
@pytest.mark.asyncio ...
    """Verify database connections are properly managed."""
async def test_scan_route_invokes_certificate_service(self, client: TestClient): ...
    """Scan route actually invokes CertificateService.scan_host().
    
    This test verifies that when a user submits the add-host form,
    the CertificateService is actually invoked (not bypassed or mocked
    only in tests)."""
async def test_upload_route_invokes_certificate_service(self, client: TestClient): ...
    """Upload route invokes CertificateService.upload_certificate().
    
    Verifies that uploaded certificates go through the service layer."""
async def test_certificate_service_is_imported_in_routes(self): ...
    """CertificateService is imported by at least one route module.
    
    This catches orphan implementations - if the service exists but
    no route imports it, it's not wired."""
async def test_deps_provides_repository_to_routes(self, client: TestClient): ...
    """Repository is provided to routes via Depends(get_repo()).
    
    Verifies the dependency injection chain is functional."""
async def test_repository_is_sqlite_implementation(self): ...
    """Production uses SQLite repository implementation.
    
    Verifies the concrete implementation is wired."""
async def test_repository_uses_connection_pool(self): ...
    """Repository uses the singleton connection pool.
    
    Verifies connection management is centralized."""
async def test_formatter_functions_are_imported(self): ...
    """Canonical formatters are imported by implementing modules.
    
    Per convention: "MUST USE core/formatters.py for all certificate
    field formatting.""""
async def test_formatter_imports_are_consistent(self): ...
    """All modules use consistent import pattern for formatters.
    
    Ensures no module uses a different import style."""
async def test_fr01_route_module_exists(self): ...
    """FR-01 dashboard route module exists."""
async def test_fr02_route_module_exists(self): ...
    """FR-02 scan route module exists."""
async def test_fr03_route_module_exists(self): ...
    """FR-03 upload route module exists."""
async def test_route_modules_export_router(self): ...
    """Route modules export 'router' attribute for auto-discovery.
    
    Per convention: "Export an APIRouter named 'router' from your file""""
async def test_routes_dont_set_explicit_prefix(self): ...
    """Route modules don't set explicit prefix (auto-discovery handles it)."""
async def test_no_direct_sqlite3_imports_in_routes(self): ...
    """Routes don't import sqlite3 directly (use deps instead).
    
    Per convention: "MUST NOT import sqlite3 or any database driver
    directly in route files""""
async def test_no_hardcoded_database_paths(self): ...
    """No hardcoded database paths in route files.
    
    Per convention: "MUST NOT hardcode database paths""""

### tests/web/routes/test_fr01_dashboard.py [unknown] ###
@pytest.mark.asyncio ...
    """Test suite for FR-01 Dashboard Display requirements."""
@pytest.mark.asyncio ...
    """Integration tests using real database (no mocks)."""
@pytest.mark.asyncio ...
    """Tests for HTMX interactions on dashboard."""
async def test_dashboard_shows_all_certificates(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.1: Dashboard displays all monitored certificates.
    
    Given: Multiple certificates in the database
    When: User accesses the dashboard
    Then: All certificates are displayed in the list"""
async def test_dashboard_shows_hostname_issuer_expiry_days_remaining(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.2: Dashboard shows hostname/label, issuer, expiry date, days remaining.
    
    Given: A certificate with all fields populated
    When: Viewing the dashboard
    Then: All required fields are visible"""
async def test_dashboard_color_coding_red_under_7_days(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.3: Color coding - red for <7 days remaining.
    
    Given: Certificate expiring in 3 days
    When: Viewing dashboard
    Then: Certificate is displayed with red status indicator"""
async def test_dashboard_color_coding_yellow_under_30_days(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.4: Color coding - yellow for <30 days remaining.
    
    Given: Certificate expiring in 15 days
    When: Viewing dashboard
    Then: Certificate is displayed with yellow status indicator"""
async def test_dashboard_color_coding_green_over_30_days(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.5: Color coding - green for >30 days remaining.
    
    Given: Certificate expiring in 60 days
    When: Viewing dashboard
    Then: Certificate is displayed with green status indicator"""
async def test_dashboard_sorted_by_urgency_ascending(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.6: Certificates sorted by days remaining ascending.
    
    Given: Multiple certificates with varying expiry dates
    When: Viewing dashboard
    Then: Most urgent (expiring soonest) appears first"""
async def test_dashboard_empty_state(self, client: TestClient): ...
    """AC-01.7: Dashboard handles empty database gracefully.
    
    Given: No certificates in database
    When: Viewing dashboard
    Then: Empty state message shown, no errors"""
async def test_dashboard_color_boundary_red_at_7_days(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.8: Boundary test - exactly 7 days shows red.
    
    Given: Certificate expiring in exactly 7 days
    When: Viewing dashboard
    Then: Status is red (boundary condition)"""
async def test_dashboard_color_boundary_yellow_at_30_days(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-01.9: Boundary test - exactly 30 days shows yellow.
    
    Given: Certificate expiring in exactly 30 days
    When: Viewing dashboard
    Then: Status is yellow (boundary condition)"""
async def test_repository_integration_returns_actual_datetimes(self, cert_repo: CertificateRepository, test_certificates): ...
    """Verify repository returns datetime objects, not strings.
    
    This catches type mismatches that mocked tests miss."""
async def test_get_all_sorted_by_urgency(self, cert_repo: CertificateRepository, test_certificates): ...
    """Repository returns certificates sorted by days remaining."""
async def test_dashboard_htmx_partial_content(self, client: TestClient, cert_repo: CertificateRepository, sample_certificate): ...
    """Dashboard supports HTMX partial content requests."""
async def test_dashboard_refresh_via_htmx(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """Dashboard can be refreshed via HTMX request."""

### tests/web/routes/test_fr02_scan.py [fr-02] ###
@pytest.mark.asyncio ...
    """Test suite for FR-02 TLS Scanning requirements."""
@pytest.mark.asyncio ...
    """Tests for manual scan triggering (part of FR-05 dependency)."""
@pytest.mark.asyncio ...
    """Integration tests with real certificate processing."""
async def test_add_host_form_accepts_hostname_and_port(self, client: TestClient): ...
    """AC-02.1: Input form accepts hostname and port.
    
    Given: A valid hostname and port
    When: Submitting the add host form
    Then: Form is accepted and processed"""
async def test_add_host_form_validates_hostname_required(self, client: TestClient): ...
    """AC-02.2: Form validation - hostname is required.
    
    Given: Form submission without hostname
    When: Submitting the form
    Then: Validation error is returned"""
async def test_add_host_form_uses_default_port_443(self, client: TestClient): ...
    """AC-02.3: Port defaults to 443 if not specified.
    
    Given: Hostname without port
    When: Submitting the form
    Then: Port 443 is used by default"""
async def test_tls_handshake_extracts_certificate(self, client: TestClient, cert_repo: CertificateRepository, test_certificates, mock_tls_connection): ...
    """AC-02.4: TLS handshake extracts certificate and stores it.
    
    Given: A reachable host with TLS
    When: Scanning the host
    Then: Certificate is extracted and stored in database"""
async def test_leaf_and_chain_stored_separately(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-02.5: Leaf and chain certificates stored separately.
    
    Given: Host with complete certificate chain
    When: Scanning the host
    Then: Leaf and intermediate certificates stored as separate entries"""
async def test_chain_certificates_linked_to_leaf(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-02.6: Chain certificates linked to leaf via chain_fingerprint.
    
    Given: Host with certificate chain
    When: Scanning the host
    Then: Chain certificates reference leaf via chain_fingerprint"""
async def test_error_handling_unreachable_host(self, client: TestClient): ...
    """AC-02.7: Error handling for unreachable hosts.
    
    Given: An unreachable hostname
    When: Attempting to scan
    Then: User-friendly error message displayed"""
async def test_error_handling_tls_handshake_failure(self, client: TestClient): ...
    """AC-02.8: Error handling for TLS handshake failures.
    
    Given: Host that rejects TLS handshake
    When: Attempting to scan
    Then: TLS error is handled gracefully"""
async def test_port_validation_rejects_invalid_ports(self, client: TestClient): ...
    """AC-02.9: Port validation rejects invalid values.
    
    Given: Invalid port numbers
    When: Submitting the form
    Then: Validation error returned"""
async def test_hostname_validation_rejects_invalid_hostnames(self, client: TestClient): ...
    """AC-02.10: Hostname validation rejects invalid values.
    
    Given: Invalid hostnames
    When: Submitting the form
    Then: Validation error returned"""
async def test_scan_result_shows_certificate_details(self, client: TestClient, test_certificates): ...
    """AC-02.11: Scan result page shows extracted certificate details.
    
    Given: Successful scan
    When: Viewing results
    Then: Certificate subject, issuer, expiry are displayed"""
async def test_manual_scan_endpoint_exists(self, client: TestClient, cert_repo: CertificateRepository, sample_certificate, test_certificates): ...
    """Manual scan endpoint is accessible.
    
    Given: Existing certificate entry
    When: Triggering manual rescan
    Then: Endpoint accepts the request"""
async def test_manual_scan_updates_certificate(self, client: TestClient, cert_repo: CertificateRepository, sample_certificate, test_certificates): ...
    """Manual scan updates certificate data.
    
    Given: Existing certificate entry
    When: Manual scan completes
    Then: Certificate data is updated"""
async def test_extract_certificate_from_tls_returns_x509_objects(self, test_certificates): ...
    """Verify TLS extraction returns proper X.509 objects.
    
    This is a type contract test ensuring the extractor returns
    cryptography.x509.Certificate objects, not dicts or strings."""
async def test_scan_service_integration_with_real_repository(self, cert_repo: CertificateRepository, test_certificates): ...
    """Scan service uses real repository for storage.
    
    Tests the integration between scan service and repository
    without mocking the repository layer."""

### tests/web/routes/test_fr03_upload.py [unknown] ###
@pytest.mark.asyncio ...
    """Test suite for FR-03 Certificate Upload requirements."""
@pytest.mark.asyncio ...
    """Integration tests for certificate parsing (real parser, no mocks)."""
@pytest.mark.asyncio ...
    """Type contract tests for upload data flow."""
async def test_upload_accepts_pem_format(self, client: TestClient, test_certificates): ...
    """AC-03.1: File upload accepts .pem format.
    
    Given: A valid PEM-encoded certificate file
    When: Uploading the file
    Then: Upload is accepted and certificate is created"""
async def test_upload_accepts_cer_format(self, client: TestClient, test_certificates): ...
    """AC-03.2: File upload accepts .cer (DER) format.
    
    Given: A valid DER-encoded certificate file
    When: Uploading the file
    Then: Upload is accepted and certificate is created"""
async def test_upload_accepts_crt_format(self, client: TestClient, test_certificates): ...
    """AC-03.3: File upload accepts .crt format.
    
    Given: A valid .crt certificate file (PEM)
    When: Uploading the file
    Then: Upload is accepted and certificate is created"""
async def test_upload_parses_expiry_date(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-03.4: Upload parses expiry date from certificate.
    
    Given: A certificate file with known expiry date
    When: Uploading and parsing
    Then: Correct expiry date is extracted and stored"""
async def test_upload_extracts_chain_certificates(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-03.5: Upload extracts chain certificates from file.
    
    Given: A PEM file containing leaf + intermediate + root
    When: Uploading the file
    Then: All certificates in chain are extracted and stored"""
async def test_upload_rejects_invalid_format(self, client: TestClient): ...
    """AC-03.6: Upload validates file format and rejects invalid files.
    
    Given: An invalid file (not a certificate)
    When: Attempting to upload
    Then: Validation error is returned"""
async def test_upload_rejects_unsupported_extensions(self, client: TestClient): ...
    """AC-03.7: Upload rejects unsupported file extensions.
    
    Given: File with unsupported extension (.txt, .jpg, etc.)
    When: Attempting to upload
    Then: Validation error is returned"""
async def test_upload_with_label_creates_labeled_entry(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-03.8: Upload with label creates entry with that label.
    
    Given: Certificate file with user-provided label
    When: Uploading with label
    Then: Entry created with specified label"""
async def test_upload_without_label_uses_subject_cn(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """AC-03.9: Upload without label uses certificate subject CN.
    
    Given: Certificate file without user-provided label
    When: Uploading without label
    Then: Entry created with subject CN as display name"""
async def test_upload_displays_result_page(self, client: TestClient, test_certificates): ...
    """AC-03.10: Upload shows result page with certificate details.
    
    Given: Successful certificate upload
    When: Viewing results
    Then: Certificate details are displayed"""
async def test_parse_certificate_file_returns_x509_objects(self, test_certificates): ...
    """Parser returns X.509 Certificate objects, not dicts.
    
    This is a critical type contract test. The parser must return
    proper cryptography.x509.Certificate objects."""
async def test_parse_certificate_file_extracts_correct_fields(self, test_certificates): ...
    """Parser extracts correct certificate fields.
    
    Verifies the parser extracts the expected fields from the
    certificate file."""
async def test_parse_certificate_file_with_chain(self, test_certificates): ...
    """Parser extracts complete chain from PEM file.
    
    Given: PEM file with multiple certificates
    When: Parsing
    Then: All certificates extracted in correct order"""
async def test_parse_certificate_file_rejects_invalid_data(self): ...
    """Parser rejects invalid certificate data.
    
    Given: Invalid data (not a certificate)
    When: Attempting to parse
    Then: CertificateParseError raised"""
async def test_parse_der_format(self, test_certificates): ...
    """Parser handles DER-encoded certificates.
    
    Given: DER-encoded certificate file
    When: Parsing
    Then: Certificate extracted correctly"""
async def test_upload_route_passes_certificate_model_to_repository(self, client: TestClient, cert_repo: CertificateRepository, test_certificates): ...
    """Upload route passes Certificate model (not dict) to repository.
    
    This test verifies the type contract between the route handler
    and repository layer."""
async def tracking_create(cert): ...
