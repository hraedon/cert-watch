#!/usr/bin/env bash
# ldap-e2e.sh — run the LDAP E2E test against a real LDAP/AD instance
# Usage: CW_LDAP_E2E=1 pytest -m ldap_real -q
set -euo pipefail

# Use the vault login broker to get credentials
eval "$(scripts/vault-login.sh)" 2>/dev/null

# Launch cert-watch in background
DATA_DIR=$(mktemp -d)
export CERT_WATCH_DATA_DIR="$DATA_DIR"
PORT=8443

python -m cert_watch &
CW_PID=$!
trap "kill $CW_PID 2>/dev/null || true" EXIT

# Wait for startup
for i in $(seq 1 30); do
    curl -sf http://127.0.0.1:8443/healthz && break
    sleep 0.5
done

# Run E2E tests
CW_LDAP_E2E=1 pytest -m ldap_real
