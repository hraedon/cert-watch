# Vault policy: TOTP code broker for the agentic layer (Vault MCP / agent).
# The ONE capability the agent gets: read ephemeral 30-second TOTP codes. It can
# NOT read any KV secret (no passwords, no client secret, no seeds). The seed
# lives only inside the TOTP secrets engine and never leaves Vault; the agent
# only ever receives a short-lived code. Every read is audit-logged.
#
# This is deliberately the narrowest policy in the set — an agent's context is
# the least-trusted boundary, so it sees codes and nothing else.

path "totp/code/entra-*" {
  capabilities = ["read"]
}
