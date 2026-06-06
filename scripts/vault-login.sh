#!/usr/bin/env bash
# vault-login.sh — Obtain a Vault token using the best available method.
#
# Usage:
#   eval "$(scripts/vault-login.sh)"
#
# Methods tried in order:
#   1. Already-set VAULT_TOKEN → passthrough
#   2. Kubernetes service account → k8s auth
#   3. AppRole (VAULT_ROLE_ID + VAULT_SECRET_ID)
#   4. Fail
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"

die() { echo "vault-login: $*" >&2; exit 1; }

# ── Method 0: already authenticated ───────────────────────────────
if [ -n "${VAULT_TOKEN:-}" ]; then
    echo "export VAULT_TOKEN='${VAULT_TOKEN}'"
    exit 0
fi

# ── Method 1: k8s service account → Vault k8s auth ──────────
try_k8s() {
    local jwt=""
    # Read SA token if we're in a pod
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        jwt=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) || true
    fi
    # Fallback: mint a token via kubectl
    if [ -z "$jwt" ]; then
        jwt=$(kubectl create token cert-watch-agent --duration=5m 2>/dev/null) || true
    fi
    [ -z "$jwt" ] && return 1

    local role="${VAULT_K8S_ROLE:-cert-watch-agent}"
    local resp
    resp=$(curl -sf -X POST \
        "${VAULT_ADDR}/v1/auth/kubernetes/login" \
        -d "{\"jwt\":\"${jwt}\",\"role\":\"${role}\"}" 2>/dev/null) || return 1

    local token
    token=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null) || return 1
    if [ -n "$token" ]; then
        echo "export VAULT_TOKEN=$token"
        return 0
    fi
    return 1
}

# ── Method 2: AppRole ───────────────────────────────────────────────
try_approle() {
    [ -z "${VAULT_ROLE_ID:-}" ] && return 1
    [ -z "${VAULT_SECRET_ID:-}" ] && return 1

    local resp
    resp=$(curl -sf -X POST \
        "${VAULT_ADDR}/v1/auth/approle/login" \
        -d "role_id=${VAULT_ROLE_ID}&secret_id=${VAULT_SECRET_ID}") || return 1

    local token
    token=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null) || return 1
    if [ -n "$token" ]; then
        echo "export VAULT_TOKEN=$token"
        return 0
    fi
    return 1
}

# ── Main ──────────────────────────────────────────────────────────

if try_k8s || try_approle; then
    exit 0
fi

die "no authentication method succeeded"
