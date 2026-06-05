# cert-watch-setup: the reusable automation identity that stands up and maintains
# cert-watch's Vault wiring. Powerful, but strictly path-scoped — it manages only
# the cert-watch policies, the TOTP engine, and the kubernetes/approle auth used
# by cert-watch. It cannot read other engines' secrets, other policies, or root.
#
# Tighten after first bootstrap: once `totp/` and `kubernetes/` exist, the
# `sys/mounts/totp` and `sys/auth/kubernetes` create grants can be dropped.

# Manage cert-watch ACL policies (the cert-watch-app/e2e-runner/totp-mcp set).
path "sys/policies/acl/cert-watch-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Inspect mounts to detect KV v1 vs v2 (read-only).
path "sys/mounts" {
  capabilities = ["read"]
}

# Enable + tune the TOTP secrets engine (one-time enable).
# `sudo` is required: sys/mounts and sys/auth are sudo-protected paths.
path "sys/mounts/totp" {
  capabilities = ["create", "read", "update", "sudo"]
}
# Manage TOTP keys + read codes for cert-watch test identities only.
path "totp/keys/entra-*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "totp/code/entra-*" {
  capabilities = ["read"]
}

# Enable + configure the Kubernetes auth method (one-time), and manage the app role.
# `sudo` required (sys/auth is a sudo-protected path).
path "sys/auth/kubernetes" {
  capabilities = ["create", "read", "update", "sudo"]
}
path "auth/kubernetes/config" {
  capabilities = ["create", "read", "update"]
}
path "auth/kubernetes/role/cert-watch" {
  capabilities = ["create", "read", "update", "delete"]
}

# Enable + manage the AppRole auth method for the runner / MCP identities.
path "sys/auth/approle" {
  capabilities = ["create", "read", "update"]
}
path "auth/approle/role/cert-watch-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/approle/role/cert-watch-*/role-id" {
  capabilities = ["read"]
}
path "auth/approle/role/cert-watch-*/secret-id" {
  capabilities = ["create", "update"]
}

# Manage the cert-watch KV subtree (seed/read app + entra + ldap secrets).
# NOTE: this Vault mounts KV v2 at `kv/` (not the default `secret/`).
path "kv/data/cert-watch/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "kv/metadata/cert-watch/*" {
  capabilities = ["read", "list", "delete"]
}
