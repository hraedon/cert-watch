"""Certificate file upload (PEM/DER/CER/CRT + PKCS#12 .pfx). See spec wi_fr03_upload.md.

Note: PKCS#12 support extends the original spec per the MVP requirements.
"""

# TODO: upload_certificate, store_uploaded, UploadedEntry, ParseError; .pfx via
# cryptography.hazmat.primitives.serialization.pkcs12.
