# Interface Specification: Certificate Chain Library

## Dependencies

- `interface_ref`: `certificate_model`

## Notes

This module is a shared utility library with no direct FR mapping. It provides helper functions used by `fr02_tls_scan` and `fr03_upload` for chain validation and manipulation. Not every module in a real codebase maps to a user-visible feature requirement — this module exists to verify the pipeline tolerates non-FR work-items.

## AC-01: Extract Chain from DER
A function `extract_chain(der_bytes: bytes) -> list[Certificate]` must extract all certificates from a DER-encoded PKCS#7 or concatenated DER blob. Returns a list of `Certificate` objects (leaf first). Returns an empty list if no valid certificates found.

## AC-02: Validate Chain Order
A function `validate_chain_order(chain: list[Certificate]) -> bool` must return `True` if each certificate in the chain was issued by the next certificate (i.e., `chain[i].issuer == chain[i+1].subject`). Returns `False` if the chain is empty, has one element, or is out of order.

## AC-03: Split Leaf and Intermediates
A function `split_leaf_intermediates(certificates: list[Certificate]) -> tuple[Certificate | None, list[Certificate]]` must return a 2-tuple of (leaf, intermediates). The leaf is the first certificate whose `is_leaf` property is `True`, or the first certificate if none have `is_leaf == True`. Intermediates are all remaining certificates.

## AC-04: Deduplicate Chain
A function `deduplicate_chain(certificates: list[Certificate]) -> list[Certificate]` must remove duplicate certificates (by `fingerprint_sha256`) while preserving order.
