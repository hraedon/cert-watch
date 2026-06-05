# Vault policy: cert-watch application (runtime).
# Bound to the pod ServiceAccount via the k8s auth method. Read-only on the
# app's own secret tree; no TOTP, no write.
#
# KV v2 paths use the /data/ (read) and /metadata/ (list) prefixes. If your
# `secret/` mount is KV v1, drop `/data/` and `/metadata/` and use
#   path "secret/cert-watch/*" { capabilities = ["read","list"] }

path "kv/data/cert-watch/*" {
  capabilities = ["read"]
}

path "kv/metadata/cert-watch/*" {
  capabilities = ["read", "list"]
}
