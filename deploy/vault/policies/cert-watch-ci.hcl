# policy: cert-watch-ci  (read-only, exactly the test creds)
path "kv/data/cert-watch/ldap/*"     { capabilities = ["read"] }
path "kv/metadata/cert-watch/ldap/*" { capabilities = ["read","list"] }
