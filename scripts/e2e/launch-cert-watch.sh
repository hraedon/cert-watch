#!/usr/bin/env bash
# launch-cert-watch.sh — Start cert-watch for E2E testing
# Uses Vault-seeded secrets from the credential broker.
set -euo pipefail

DATA_DIR="${CERT_WATCH_DATA_DIR:-/tmp/cert-watch-e2e}"
PORT="${CERT_WATCH_PORT:-8443}"

# 1. Obtain a Vault token (see vault-login.sh)
# shellcheck disable=SC2312
if [ -z "${VAULT_TOKEN:-}" ]; then
    eval "$(scripts/vault-login.sh)"
fi

# 2. Pull LDAP secrets from Vault (if available)
if [ -n "${VAULT_TOKEN:-}" ]; then
    # Read LDAP bind password from Vault KV
    LDAP_BIND_PASSWORD=$(vault kv get -field=password kv/cert-watch/ldap) || true
    export LDAP_BIND_PASSWORD="${LDAP_BIND_PASSWORD:-}"
fi

export CERT_WATCH_DATA_DIR="${CERT_WATCH_DATA_DIR:-/tmp/cert-watch-data}"
mkdir -p "$CERT_WATCH_DATA_DIR"

python -m cert_watch \
    --host 0.0.0.0 \
    --port "${CERT_WATCH_PORT:-8443}" \
    "$@"
