"""Debug script to test upload route."""

import sys
import tempfile
from pathlib import Path
import io

sys.path.insert(0, "src")

from fastapi.testclient import TestClient
from cert_watch.web.app_factory import create_app
from cert_watch.core.config import Settings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# Create a test certificate
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ]
)
issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
    ]
)
now = datetime.utcnow()
builder = x509.CertificateBuilder()
builder = builder.subject_name(subject)
builder = builder.issuer_name(issuer)
builder = builder.not_valid_before(now - timedelta(days=30))
builder = builder.not_valid_after(now + timedelta(days=60))
builder = builder.serial_number(int(now.timestamp()))
builder = builder.public_key(private_key.public_key())
cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
pem_data = cert.public_bytes(serialization.Encoding.PEM)

# Create app
with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "test.db"
    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        debug=True,
    )

    app = create_app(settings)

    # Debug: Print all route details
    from fastapi.routing import APIRoute

    print("=== Registered Routes ===")
    for r in app.routes:
        if isinstance(r, APIRoute):
            print(f"Path: {r.path!r}")
            print(f"Methods: {r.methods}")
            print(f"Endpoint: {r.endpoint}")
            print(f"---")

    client = TestClient(app, raise_server_exceptions=False)

    # Test POST with explicit debug
    print("\n=== Testing POST /upload ===")

    files = {"certificate": ("test.pem", io.BytesIO(pem_data), "application/x-pem-file")}
    data = {"label": "Test Upload"}

    try:
        post_response = client.post("/upload", files=files, data=data)
        print(f"Status: {post_response.status_code}")
        print(f"Headers: {dict(post_response.headers)}")
        print(f"Body: {post_response.text[:1000]}")
    except Exception as e:
        print(f"Exception: {e}")
        import traceback

        traceback.print_exc()
