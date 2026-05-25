# Interface Specification: FR-03 Certificate Upload

## Dependencies

- `interface_ref`: `certificate_model`
- `interface_ref`: `database_layer`
- `interface_ref`: `cert_chain_library`

## AC-01: Supported Formats
A function `upload_certificate(file_path: Path) -> UploadedEntry | ParseError` must accept `.pem`, `.cer`, and `.crt` files.

## AC-02: PEM Parsing
For PEM-encoded files, the function must decode base64 content, parse the DER bytes, and produce a `Certificate`.

## AC-03: DER Parsing
For raw DER files, the function must parse directly and produce a `Certificate`.

## AC-04: Uploaded Entry Creation
The function must return an `UploadedEntry` dataclass containing:
- `file_name: str`
- `leaf: Certificate` (from the locked `certificate_model` interface)
- `chain: list[Certificate]` (extracted if the file contains multiple certificates)
- `uploaded_at: datetime`

## AC-05: Unsupported File
If the file format is not supported or the content is invalid, the function must return `ParseError` with `error_message: str`.

## AC-06: Store Uploaded Entry
A function `store_uploaded(entry: UploadedEntry, repo: CertificateRepository) -> str` must persist the leaf certificate (and any chain certificates) via the repository and return the certificate ID.