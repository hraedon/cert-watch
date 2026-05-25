# Interface Specification: Certificate Model (cert-parser)

## Dependencies

None.

## AC-01: Certificate Dataclass
A `Certificate` dataclass must expose:
- `subject: str` — the leaf certificate's subject DN
- `issuer: str` — the leaf certificate's issuer DN
- `not_before: datetime` — validity period start
- `not_after: datetime` — validity period end
- `san_dns_names: list[str]` — Subject Alternative Names (DNS), empty list if none
- `fingerprint_sha256: str` — hex-encoded, lowercase, no colons
- `raw_der: bytes` — the raw DER bytes of the leaf certificate

## AC-02: Days Until Expiry
The `Certificate` dataclass must provide `days_until_expiry() -> int` returning the number of whole days between now (UTC) and `not_after`.

## AC-03: Parse from DER
A standalone function `parse_certificate(der_bytes: bytes) -> Certificate | MalformedCertificateError` must parse a DER-encoded X.509 certificate. On success it returns a `Certificate`; on failure it returns a `MalformedCertificateError`.

## AC-04: Error on Malformed Input
If the input is not a valid DER-encoded X.509 certificate, `parse_certificate` must return a `MalformedCertificateError` instance with `message: str`.

## AC-05: Parse PEM
A standalone function `parse_pem_certificate(pem_text: str) -> Certificate | MalformedCertificateError` must parse a PEM-encoded X.509 certificate (with `-----BEGIN CERTIFICATE-----` markers). On success it returns a `Certificate`; on failure it returns a `MalformedCertificateError`.

## AC-06: Error Type
`MalformedCertificateError` must be a dataclass with `message: str`.

## AC-07: Is Leaf Predicate
The `Certificate` dataclass must provide `is_leaf: bool` property defaulting to `True`.

## AC-08: Display Name
The `Certificate` dataclass must provide `display_name: str` property returning the subject DN if non-empty, otherwise the SAN's first DNS name, otherwise `"unknown"`.

## AC-09: Chain Extraction
A standalone function `extract_chain_from_pem(pem_text: str) -> list[Certificate]` must extract all certificates from a PEM file containing multiple certificates. Returns a list of `Certificate` objects (leaf first, then chain intermediates). Returns empty list if no valid certificates found.