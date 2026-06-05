# Vault policy: E2E test runner (CI job / in-network runner).
# Reads the test-identity passwords + the OAuth client secret so the Playwright
# process can authenticate. Does NOT grant the TOTP code path — the runner types
# passwords; the agent (separate policy) supplies the second factor. Keeping them
# split means a leak of one credential plane never yields the other.
#
# Bind via AppRole or GitHub OIDC->JWT auth (no long-lived token). KV v1: drop /data/.

path "kv/data/cert-watch/entra/*" {
  capabilities = ["read"]
}

# LDAP test path (synthetic uses no secret; the lab directory bind password does):
path "kv/data/cert-watch/ldap/*" {
  capabilities = ["read"]
}

# The scripted test PROCESS needs the second factor too (unlike the agent, which
# gets codes via the codes-only MCP policy). Read-only on the TOTP codes.
path "totp/code/entra-*" {
  capabilities = ["read"]
}
