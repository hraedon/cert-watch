# cert-watch threat model

Last reviewed: 2026-09-23, against `main` at `ea6cf16`. Method: source, test
and deployment-manifest review; no live environment was assessed.

Every control below names the code that implements it and the test that fails
if it regresses. Code paths are relative to `src/cert_watch/` unless they
start with `.github/`, `scripts/`, `deploy/` or `tests/`. A claim with no test
is marked *(untested)*. When you change
code named here, update this file in the same change (see
[Review triggers](#review-triggers)).

## What cert-watch is

A single FastAPI process with a server-rendered UI, a JSON API, a CLI and an
in-process scheduler, persisting to one local SQLite database. It inventories
certificates, connects to operator-chosen TLS/STARTTLS endpoints, and sends
alerts and audit events to configured sinks. Supported deployments run exactly
one instance; the Kubernetes manifest pins `replicas: 1` with a `Recreate`
strategy (`deploy/k8s/deployment.yaml`).

## Assets

| Asset | What must hold |
| --- | --- |
| Inventory: hosts, certificates, tags, owners, notes, scan history, posture, alert state | Confidential to authorized viewers (and their tag scope); integrity |
| Identity data: local password hashes (scrypt), session versions, API-key hashes, roles, role mappings | Integrity; least privilege; revocability |
| Root signing secret (`CERT_WATCH_AUTH_SECRET` or `data_dir/.auth_secret`) | Confidentiality. Session MACs, OAuth state MACs, the API-key pepper, the default CSRF key and the settings-encryption key all derive from it |
| Integration credentials: LDAP bind, OAuth client secret, SMTP, PagerDuty key, webhook URLs/headers, HEC token | Confidentiality; destination integrity |
| Trust anchors | Integrity: they change chain validation for the whole fleet |
| Audit log and delivery evidence | Integrity; availability |
| Release images and deployment image pointers | Provenance; controlled publication |

## Adversaries

**In scope**

- An unauthenticated network client reaching the HTTP port.
- An authenticated user trying to exceed their tier (viewer, operator, admin)
  or their tag scope, including through the JSON API.
- A holder of a stolen session cookie or API key.
- A cross-site attacker driving a signed-in user's browser (CSRF, framing).
- A hostile scan target, or a certificate carrying hostile CRL/OCSP URLs.
- A hostile or compromised sink or IdP response (malformed, oversized, slow,
  redirecting).
- A fork pull request trying to reach CI secrets or learn the identifier
  denylist.

**Out of scope** (the application cannot defend against these by design)

- Anyone with read access to both the SQLite file and the root signing secret:
  they can forge sessions and decrypt stored credentials.
- A compromised host, container runtime, cluster, IdP, directory, SMTP relay or
  SIEM.
- A malicious administrator. Admins choose sink destinations, trust anchors,
  role mappings and API keys by design.
- Repository maintainers and anyone holding GitHub release authority.
- Network attackers on links the operator runs in cleartext by choice (plain
  LDAP, SMTP without STARTTLS, syslog (UDP or TCP, no TLS), HTTP between
  ingress and pod).

## Trust boundaries and controls

### 1. Browser to application

| Control | Code | Enforcing test |
| --- | --- | --- |
| An exposed first run provisions a local admin or refuses to start; open mode requires loopback or `CERT_WATCH_ALLOW_UNAUTH=1` | `firstrun.py`, `app.py` (`_provision_initial_admin`, lifespan) | `tests/test_firstrun_posture.py::test_first_run_action_truth_table`, `tests/test_secure_by_default.py::test_fails_closed_when_provisioning_fails_on_exposed_bind` |
| Every non-public path requires a session or API key; the public list is explicit and has no `/auth/` prefix rule | `auth/request_context.py` (`_PUBLIC_PATHS`, `auth_middleware`) | `tests/test_oauth_callback.py::test_only_listed_auth_paths_are_public` |
| One guard family: every mutating route declares exactly one `MutationGuard`, and every `MutationGuard` checks CSRF; only `/login`, `/setup` and `/auth/logout` are exempt, and each calls `check_csrf` itself | `auth/guards.py` | `tests/test_route_guards.py::test_every_mutating_route_has_exactly_one_mutation_guard`, `::test_mutation_guard_cannot_be_built_without_csrf` |
| Every mutating route's outcome is pinned for 16 principals, each with and without a CSRF token | the guards + services | `tests/test_authz_characterization.py::test_authz_matrix_matches_golden` (golden file `tests/fixtures/authz_matrix.json`) |
| CSRF is a double-submit token HMAC'd to the `cw_auth` session cookie with a 2-hour lifetime. Query-string tokens are rejected | `security/csrf.py` | `tests/test_csp_csrf_hardening.py::test_csrf_query_param_token_rejected`, `::test_post_without_token_rejected` |
| Session cookie is `HttpOnly`, `SameSite=Strict`, `Secure` by default. `cw_sid` is also `HttpOnly` | `routes/auth.py`, `security/csrf.py` | `tests/test_csp_csrf_hardening.py::test_cw_sid_cookie_is_httponly` |
| Sessions are HMAC-SHA256 with a format tag inside the MAC (`cert-watch-session-v2`), so pre-1.0 tokens are rejected. TTL is enforced, and a per-username version enables revocation on logout, password change, role change and user rename, create or delete | `auth/session.py`, `routes/settings/roles.py` | `tests/test_local_user_authz.py::test_pre_upgrade_unmarked_session_is_signed_out`, `::test_renamed_user_old_cookie_is_revoked`, `::test_delete_revokes_before_the_row_goes`, `tests/test_session.py::test_old_session_token_invalidated_after_logout` |
| CSP with a per-request nonce and no `unsafe-inline`, plus `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, and HSTS when cookies are Secure | `security/headers.py` | `tests/test_csp_csrf_hardening.py::test_security_headers_present`, `::test_csp_nonce_rendered_and_per_request` |
| Login is throttled to 10 attempts per 5 minutes per (client IP, NFKC-normalised case-folded username), with a looser ceiling of 50 per 5 minutes per IP. Passwords over 1024 characters are refused before hashing | `routes/auth.py` | `tests/test_security_hardening.py::test_login_tight_limit_is_per_ip_and_normalized_username`, `::test_login_keeps_looser_per_ip_ceiling` |
| Request bodies are capped at 12 MiB at the ASGI layer, before any multipart or JSON parsing. Both declared `Content-Length` and bytes actually streamed are counted. Oversize requests get 413 and are logged | `security/body_limit.py`, `middleware.py` | `tests/test_security_hardening.py::test_request_body_limit_rejects_declared_oversize_before_parsing`, `::test_request_body_limit_counts_actual_streamed_bytes` |
| JSON API bodies are parsed only up to 1 MiB and 64 levels of nesting, checked on the decoded value (so the body's encoding doesn't matter), and never by relying on `RecursionError`, which CPython 3.14.7 no longer raises for deep input. Over either bound is `400` | `routes/api/_shared.py` (`json_body`) | `tests/test_security_hardening.py::test_json_nesting_is_bounded_explicitly_not_by_recursion`, `::test_json_body_size_is_capped_below_the_request_limit`, `::test_json_writes_reject_extreme_nesting_without_500` |
| In open (auth-disabled) mode the `Host` header must be loopback, `localhost` or the `CERT_WATCH_BASE_URL` host, which blocks DNS rebinding. Only `GET`/`HEAD` on `/healthz` and `/readyz` are exempt, for kubelet probes | `security/host_header.py` | `tests/test_security_hardening.py::test_open_mode_rejects_untrusted_host_header`, `::test_open_mode_allows_configured_base_url_host`, `::test_open_mode_probe_exemption_is_exact` |
| In open mode, JSON mutations still require CSRF when the request looks like it came from a browser (it carries a cookie, `Origin` or `Sec-Fetch-Site`) | `auth/guards.py` (`MutationGuard.__call__`) | `tests/test_security_hardening.py::test_open_mode_browser_mutations_require_csrf` |
| `/metrics` accepts either the `CERT_WATCH_METRICS_TOKEN` bearer or an admin browser session. Non-admin or tag-scoped sessions and API keys are refused; unauthenticated scrapers get 401 | `auth/guards.py` (`MetricsGuard`), `routes/metrics.py` | `tests/test_security_hardening.py::test_metrics_requires_admin_session_when_no_bearer_token`, `::test_metrics_rejects_admin_application_api_key`, `::test_metrics_token_gate_rejects_unauthenticated_browser_when_auth_enabled` |

### 2. Authorization model (sessions and API keys)

| Control | Code | Enforcing test |
| --- | --- | --- |
| Services own authorization. Every mutating service requires an `AuthContext` principal; `None` or any other object raises. Trusted internal and auth-disabled work uses the explicit `AuthContext.system()` | `auth/scope.py` (`require_auth_context`), `services/*.py` | `tests/test_service_scope.py::test_invalid_auth_context_fails_closed`, `::test_explicit_system_principal_is_unrestricted` |
| Tag scope is checked inside the service's write lock. Scope matching ignores case. Per-tag tiers ("operator for prod, viewer for edge") are enforced per resource | `auth/scope.py`, `auth/rbac.py` (`may_write_tags`) | `tests/test_service_scope.py::test_scope_is_checked_while_holding_the_write_lock`, `::test_read_only_tier_on_the_tag_is_refused` |
| Reads are scope-filtered across browse, detail, events, calendar, analytics, readiness, policy, CSV export and scan history, and out-of-scope objects look nonexistent | route/query layer, `database` scope clauses | `tests/test_tag_scoped_access.py::test_browse_views_never_render_another_team`, `::test_html_and_api_hide_existence_and_audit_scope_denials`, `tests/test_scope_and_admin_gates.py::test_scan_history_hides_out_of_scope_hosts`, `tests/test_wi128_api_scope_filtering.py` |
| Local accounts take their role only from the users table, never from the role map. A missing or deleted role means viewer. Break-glass is a reserved session claim that IdP claims cannot carry (`cw:` prefix stripped) | `auth/rbac.py` (`build_auth_context`, `claims_for_session`) | `tests/test_local_user_authz.py::test_local_user_whose_role_was_deleted_is_viewer`, `::test_reserved_session_claims_cannot_come_from_an_idp`, `::test_directory_user_named_like_local_user_does_not_inherit_its_role` |
| The Settings → Roles mapping is keyed by role id, so renaming or deleting a role cannot grant access. Once a mapping has existed, a "configured" flag keeps an emptied map least-privilege. An unreadable map at startup fails closed through a sentinel entry | `auth/rbac.py`, `config/settings.py` (`with_kv`), `app.py` | `tests/test_local_user_authz.py::test_renaming_a_mapped_role_does_not_grant_admin`, `::test_clearing_the_last_mapping_does_not_restore_full_access`, `::test_startup_role_map_failure_fails_closed`, `::test_malformed_stored_role_map_fails_closed` |
| With no role map, `CERT_WATCH_ADMINS` and `CERT_WATCH_WRITE_USERS` are enforced, and admin implies write | `auth/rbac.py` (`_legacy_list_context`) | `tests/test_legacy_admins_list.py::test_unlisted_legacy_user_cannot_reach_settings`, `::test_non_writer_cannot_administer_when_only_write_users_is_set` |
| Trust-anchor add and delete are admin-only (HTML and JSON) | `routes/certificates.py`, `routes/api/certificates.py`, `services/certificate_management.py` | `tests/test_scope_and_admin_gates.py::test_scoped_writer_cannot_add_trust_anchor`, `::test_trust_anchor_add_enforces_csrf_for_admin` |
| API keys (`cwk_…`) are stored as HMAC-SHA256 with a pepper derived from the signing secret. Scope `read`/`write`/`admin` maps to viewer/operator/admin. Bearer requests skip CSRF (they carry no ambient credential). Settings forms marked browser-only refuse API keys | `database/api_keys.py`, `auth/request_context.py`, `auth/guards.py` | `tests/test_api_keys.py::test_create_returns_prefixed_token_and_stores_only_hash`, `::test_require_write_denies_read_scope`, `::test_require_admin_requires_admin_scope` |
| Listing, creating and revoking API keys (JSON and HTML) requires an admin browser session, so a key cannot mint or revoke keys | `routes/api/keys.py`, `routes/settings/api_keys.py` (`session_only` guards) | `tests/test_security_hardening.py::test_admin_api_key_cannot_create_or_revoke_api_keys`, `::test_admin_api_key_cannot_use_html_key_management` |
| The JSON API and the HTML forms share per-action rate-limit buckets. Host bodies are strict: no type coercion, no unknown fields | `routes/api/hosts.py`, `security/ratelimit.py` | `tests/test_api_write_security.py::test_html_and_json_share_each_action_rate_limit`, `::test_api_create_host_rejects_type_confusion_without_calling_service` |
| JSON-body writes require `Content-Type: application/json` (415 otherwise), including in open mode. Bodies are parsed strictly: non-objects, duplicate keys, `NaN`/`Infinity`, extreme nesting and lone surrogates are refused with 400/422, never a 500 | `auth/guards.py` (`json_write_guard`), `routes/api/_shared.py` (`json_body`) | `tests/test_security_hardening.py::test_json_write_rejects_text_plain_even_when_auth_is_disabled`, `::test_json_writes_reject_non_object_bodies_without_500`, `::test_json_writes_reject_duplicate_keys_and_non_finite_numbers`, `::test_json_writes_reject_extreme_nesting_without_500`, `::test_json_writes_reject_lone_surrogates_without_500` |
| `/api/*` is limited to 60 requests per minute per client IP. The limiter is SQLite-backed and shared across workers | `security/ratelimit.py` | `tests/test_csp_csrf_hardening.py::test_rate_limit_dependency_returns_429_on_api_route` |

### 3. Directory and IdP

| Control | Code | Enforcing test |
| --- | --- | --- |
| OAuth start (`/auth/login`) is public. The state cookie is `SameSite=Lax` so the IdP's top-level redirect carries it back | `routes/auth.py` | `tests/test_oauth_callback.py::test_oauth_start_is_public_and_state_cookie_is_lax` |
| OAuth state is HMAC-signed in its own MAC domain (`cert-watch-oauth-state-v1`), so a state token can never pass as a session and vice versa. The callback compares it to the cookie in constant time | `auth/session.py`, `routes/auth.py` | `tests/test_local_user_authz.py::test_session_token_is_not_a_valid_oauth_state`, `::test_oauth_state_is_not_a_valid_session_token`, `tests/test_oauth_callback.py::test_callback_state_param_does_not_match_cookie` |
| The ID token is checked for issuer, audience, nonce and signature, and only asymmetric algorithms are allowed. PKCE is used. The group/role allowlist is applied at the callback | `auth/oauth_provider.py` | `tests/test_auth.py::test_issuer_mismatch_rejected`, `::test_audience_mismatch_rejected`, `::test_safe_algs_filters_unsafe`, `tests/test_oauth_callback.py::test_callback_authz_denied_when_not_in_allowed_group` |
| LDAP filter input is escaped. `ldaps://` or StartTLS validates the server certificate (`CERT_REQUIRED`), optionally against a private CA | `auth/ldap_provider.py` | `tests/test_auth.py::test_ldaps_ca_cert_builds_tls_with_cert_required` |
| A simple bind over plain `ldap://` is refused (at login and in the Settings probe) unless StartTLS is on or `CERT_WATCH_LDAP_ALLOW_INSECURE=1` is set | `auth/ldap_provider.py` (`insecure_ldap_error`) | `tests/test_security_hardening.py::test_plain_ldap_login_is_refused_by_default`, `::test_settings_ldap_probe_refuses_plain_bind`, `::test_plain_ldap_can_be_explicitly_allowed` |

### 4. Scan targets and certificate-embedded URLs

| Control | Code | Enforcing test |
| --- | --- | --- |
| Every resolved address is checked. Loopback, `0.0.0.0/8`, link-local (including `169.254.169.254`) the unspecified address and the AWS IPv6 metadata range `fd00:ec2::/32` are always blocked. The same holds when an address is wrapped in IPv4-mapped, 6to4, Teredo or NAT64 form (both `64:ff9b::/96` and local-use `64:ff9b:1::/48` are unwrapped). Private ranges (RFC 1918, ULA, CGNAT `100.64.0.0/10`) follow `CERT_WATCH_ALLOW_PRIVATE_IPS` and `CERT_WATCH_ALLOWED_SUBNETS`. Scans and HTTP sinks share this check | `scan_resolver.py`, `http_client.py` | `tests/test_ssrf_csrf_ratelimit.py::test_is_blocked_ip_6to4_wrapped_metadata_always`, `::test_is_blocked_ip_teredo_always_blocked`, `tests/test_allowlist_ssrf.py::test_allowlist_scopes_private_ranges`, `tests/test_security_hardening.py::test_ipv6_imds_is_always_blocked_for_scans_and_webhooks`, `::test_local_use_nat64_unwraps_embedded_ipv4_for_scans_and_webhooks`, `::test_cgnat_follows_private_policy_for_webhooks` |
| Connections are pinned to the validated IP. HTTP redirects are re-resolved, re-validated and re-pinned at each hop. CRL/OCSP URLs taken from certificates follow the same policy | `http_client.py`, `posture.py` | `tests/test_http_client_integration.py::test_redirect_blocked_on_second_hop`, `tests/test_ssrf_integration.py::test_redirect_to_blocked_private_ip_caught` |
| STARTTLS protocols are allowlisted. The openssl subprocess has an overall timeout and a 1 MiB output cap | `scan_conn.py` | `tests/test_starttls_scan.py::test_unknown_starttls_mode_not_forwarded` |
| Uploads are capped at 10 MiB per route, 100 certificates per bundle and 50 per chain. PKCS#12 private keys are parsed only in memory and are never stored or logged | `routes/certificates.py`, `upload.py` | `tests/test_upload.py::test_upload_malformed`, `::test_upload_pfx_discards_private_key_from_storage_and_logs` |

### 5. Outbound sinks: SMTP, webhooks, PagerDuty, SIEM

| Control | Code | Enforcing test |
| --- | --- | --- |
| Webhook, PagerDuty, renewal-webhook and HEC destinations go through the pinned, redirect-checked client | `alerting/transports/webhook.py`, `renewal_webhook.py`, `siem.py` | `tests/test_allowlist_ssrf.py::test_webhook_url_validate_blocks_metadata_ip` |
| SMTP host is address-checked and pinned. STARTTLS and SMTPS use a verifying default context. Credentials are never sent without TLS | `alerting/transports/smtp.py` | `tests/test_alerts.py::test_negotiate_starttls_uses_verifying_default_context`, `tests/test_http_client.py::test_resolve_smtp_host_returns_the_validated_pin` |
| Alert delivery uses claims and expiring leases. A worker whose lease expired cannot complete the row | `database/alert_store.py` | `tests/test_alert_lifecycle.py::test_expired_lease_is_reclaimed_and_old_owner_cannot_complete` |
| SIEM export runs after the audit row commits and the write lock is released. Export failure never blocks the write | `audit.py` (`record_audit`, `export_audit`) | `tests/test_audit_outside_write_lock.py::test_route_audits_export_after_the_write_lock_is_released`, `tests/test_siem.py::test_hec_failure_is_swallowed` |

### 6. Local secrets and SQLite

| Control | Code | Enforcing test |
| --- | --- | --- |
| A configured `<NAME>_FILE` that is missing, empty or unreadable is a startup error, and the error names neither the path nor the content. Every sensitive setting read from the environment accepts `_FILE` | `config/helpers.py` (`_read_secret_file`) | `tests/test_config_golden.py::test_explicit_secret_file_failures_are_configuration_errors`, `tests/test_config_field_table.py::test_every_env_backed_sensitive_spec_supports_file` |
| Sensitive `Settings` fields are left out of `repr` | `config/settings.py` | `tests/test_config_field_table.py::test_settings_repr_redacts_every_sensitive_field` |
| Sensitive stored settings are Fernet-encrypted under an HKDF-derived key. A generated signing secret is written `0600`. The container runs as non-root with a read-only root filesystem | `database/encryption.py`, `config/helpers.py`, `deploy/k8s/deployment.yaml` | `tests/test_encryption_migration.py::test_v1_to_v2_migration_round_trip`, `tests/test_webhook_headers_sensitive.py::test_save_alerts_route_encrypts_webhook_headers` |

### 7. CI and release supply chain

| Control | Code | Enforcing test |
| --- | --- | --- |
| The identifier gate fails closed: it fails when its denylist secret is unset, and fork PRs are rejected without checkout or secret. CI output is redacted and never prints the identifier, the matching line or a path | `.github/workflows/identifier-gate.yml`, `scripts/check_committed_identifiers.py` | `tests/test_identifier_gate.py::test_workflow_fork_pr_fails_closed_without_secret_or_checkout`, `::test_unset_secret_fails_closed_for_a_public_repo`, `::test_redacted_ci_output_omits_identifier_and_source_line` |
| Release runs only after CI, e2e and deploy-smoke pass on the same commit. The image is Trivy-scanned before push and gets SBOM plus SLSA provenance. It is keyless cosign-signed by digest and `cosign verify`'d against the release workflow identity. The attestations must name the commit before the digest-pinned deployment pointer moves | `.github/workflows/release.yml`, `scripts/verify_release_attestations.py` | `tests/test_release_workflow.py::test_published_image_is_signed_and_attested`, `::test_the_signature_is_verified_before_the_deployment_pointer_moves`, `tests/test_verify_release_attestations.py::test_provenance_for_another_commit_is_refused` |

## Residual risks and accepted gaps

These are true of the current code. Operators should plan around them.

1. **API keys cover the whole fleet.** A key's `AuthContext` carries no tag
   scope, so a `write` key can change any host. Keys never expire; revoke
   them by hand. (Keys can no longer mint keys; key management requires an
   admin browser session.)
2. **No role map and no user lists means every directory user is admin.**
   This keeps upgrades from older installs working, and it applies until a
   mapping is first saved or a list is set.
3. **Directory group changes take effect only at the next login.** A
   session's IdP groups are fixed when the user signs in. Removing someone
   from an IdP group does not end their session; the TTL (8 hours by
   default) or a logout does.
4. **Private-network reach is on by default.** `CERT_WATCH_ALLOW_PRIVATE_IPS`
   defaults to true, and the Kubernetes and IIS manifests set it explicitly.
   So write access, certificates you scan (through their CRL/OCSP URLs) and
   admin-chosen sinks can make cert-watch connect to internal addresses. HEC
   always allows private addresses, and syslog is not address-checked.
   Loopback, link-local and cloud-metadata ranges stay blocked.
5. **Rate limits key on client IP.** Behind an ingress without
   `CERT_WATCH_TRUST_PROXY` (the checked-in Kubernetes manifest does not set
   it; the IIS config does), every user shares the ingress address. One
   client can then exhaust the 60/minute `/api/*` budget or the 50 per 5
   minutes login ceiling for everyone, or lock a named account out of login.
   If SQLite errors, the limiter falls back to per-process counters (fail
   open).
6. **Single writer.** The write lock is per process. Two instances on the same
   database are unsupported and unprotected.
7. **Alert delivery is at least once.** A worker that sends and then dies
   before recording completion causes a resend after its lease expires.
8. **SIEM export is best effort.** Failures are logged and dropped, with no
   retry. The SQLite audit log is the record of truth, and it is not
   tamper-evident against someone with database access.
9. **Some weaker paths are still allowed.** SMTP without credentials sends
   in clear when the relay offers no STARTTLS. The OAuth userinfo fallback (no
   `id_token`) proceeds without nonce binding when the IdP omits the nonce.
   `CERT_WATCH_LDAP_ALLOW_INSECURE=1` re-enables plaintext LDAP binds, with a
   warning.
10. **Legacy API-key hashes still verify.** Keys hashed under an earlier
    pepper or unkeyed SHA-256 are accepted and upgraded when next used. Rotate
    old keys.
11. **Possession of the signing secret is total.** It keys sessions, OAuth
    state and the API-key pepper, and it derives the CSRF and settings
    encryption keys. Protect the PVC or data directory and its backups
    together with the secret store.

## Review triggers

Update this model in the same change when code or deployment configuration
alters: authentication, sessions, CSRF, the guard family, API keys, role
mapping or tag scoping; public paths or metrics exposure; scan or sink address
policy, DNS pinning or redirects; upload bounds or trust-anchor authority;
secret loading, encryption, SQLite topology or file paths; sink payloads,
credentials or delivery semantics; proxy trust or security headers; or release
authority and image provenance. Name the affected assets and boundaries, point
at the enforcing test, and list anything unresolved under residual risks
rather than assuming it is accepted.

See also: [access control](access-control.md) for how roles, scopes and keys
are configured, and [SECURITY.md](../SECURITY.md) for reporting.
