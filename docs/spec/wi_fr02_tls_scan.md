# Interface Specification: FR-02 TLS Scanning

## Dependencies

- `interface_ref`: `certificate_model`
- `interface_ref`: `database_layer`
- `interface_ref`: `cert_chain_library`

## AC-01: Scan Host Function
A function `scan_host(hostname: str, port: int = 443) -> ScannedEntry | ScanError` must accept a hostname and optional port.

## AC-02: TLS Handshake
The function must perform a TLS handshake to the target host and extract the presented leaf certificate.

## AC-03: Chain Extraction
The function must extract the full certificate chain presented during the handshake, returning chain certificates separately from the leaf.

## AC-04: Scanned Entry Creation
The function must return a `ScannedEntry` dataclass containing:
- `host: str`
- `port: int`
- `leaf: Certificate` (from the locked `certificate_model` interface)
- `chain: list[Certificate]`
- `scanned_at: datetime`

The returned `ScannedEntry.leaf` must equal `parse_certificate(handshake_der)` from the `certificate_model` module — the test must call `parse_certificate` on the raw handshake DER bytes and assert equality, not construct a `Certificate` from literals.

## AC-05: Connection Failure
If the TLS connection fails or no certificate is presented, the function must return `ScanError` with `error_message: str`.

## AC-06: Timeout
The function must enforce a 10-second connection timeout; exceeding it returns `ScanError`.

## AC-07: Store Scanned Entry
A function `store_scanned(entry: ScannedEntry, repo: CertificateRepository) -> str` must persist the leaf certificate (and chain certificates) via the repository and return the certificate ID.

## AC-08: Scan Error Type
`ScanError` must be a dataclass with `hostname: str`, `port: int`, `error_message: str`.