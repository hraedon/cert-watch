"""Migration registry — import this to register all known migrations."""

from cert_watch.migrations import runner
from cert_watch.migrations.m0001_baseline import upgrade as baseline_upgrade
from cert_watch.migrations.m0002_audit_log import upgrade as audit_log_upgrade
from cert_watch.migrations.m0003_rate_limits import upgrade as rate_limits_upgrade
from cert_watch.migrations.m0004_tls_verified import upgrade as tls_verified_upgrade
from cert_watch.migrations.m0005_composite_indexes import (
    upgrade as composite_indexes_upgrade,
)
from cert_watch.migrations.m0006_cert_tags import upgrade as cert_tags_upgrade
from cert_watch.migrations.m0007_kv_store import upgrade as kv_store_upgrade
from cert_watch.migrations.m0008_alert_groups import upgrade as alert_groups_upgrade
from cert_watch.migrations.m0009_cert_history import upgrade as cert_history_upgrade
from cert_watch.migrations.m0010_alert_extra_recipients import (
    upgrade as alert_extra_recipients_upgrade,
)
from cert_watch.migrations.m0011_session_versions import (
    upgrade as session_versions_upgrade,
)
from cert_watch.migrations.m0012_scan_degraded import (
    upgrade as scan_degraded_upgrade,
)
from cert_watch.migrations.m0013_verify_requested import (
    upgrade as verify_requested_upgrade,
)
from cert_watch.migrations.m0014_alert_read import (
    upgrade as alert_read_upgrade,
)
from cert_watch.migrations.m0015_api_keys import (
    upgrade as api_keys_upgrade,
)
from cert_watch.migrations.m0016_chain_status import (
    upgrade as chain_status_upgrade,
)
from cert_watch.migrations.m0017_caa_per_scan import (
    upgrade as caa_per_scan_upgrade,
)
from cert_watch.migrations.m0018_ct_issuer_first_seen import (
    upgrade as ct_issuer_first_seen_upgrade,
)
from cert_watch.migrations.m0019_users_roles import (
    upgrade as users_roles_upgrade,
)
from cert_watch.migrations.m0020_alert_hostname_subject import (
    upgrade as alert_hostname_subject_upgrade,
)
from cert_watch.migrations.m0021_event_log import (
    upgrade as event_log_upgrade,
)
from cert_watch.migrations.m0022_hosts_expected_issuers import (
    upgrade as hosts_expected_issuers_upgrade,
)
from cert_watch.migrations.m0023_cert_history_not_before import (
    upgrade as cert_history_not_before_upgrade,
)
from cert_watch.migrations.m0024_role_tiers import (
    upgrade as role_tiers_upgrade,
)
from cert_watch.migrations.m0025_alert_group_config import (
    upgrade as alert_group_config_upgrade,
)
from cert_watch.migrations.m0026_role_alert_group_link import (
    upgrade as role_alert_group_link_upgrade,
)
from cert_watch.migrations.m0027_host_starttls import (
    upgrade as host_starttls_upgrade,
)

runner.register("0001", "baseline: snapshot of pre-migration schema", baseline_upgrade)
runner.register("0002", "add audit_log table (Plan 008)", audit_log_upgrade)
runner.register("0003", "add rate_limits table (BC-049)", rate_limits_upgrade)
runner.register("0004", "add tls_verified column to scan_posture (BC-064)", tls_verified_upgrade)
runner.register(
    "0005", "add composite indexes for hostname/port queries",
    composite_indexes_upgrade,
)
runner.register("0006", "add tags column to certificates (plan 013)", cert_tags_upgrade)
runner.register("0007", "add kv_store table (Plan 014)", kv_store_upgrade)
runner.register("0008", "add alert_groups tables (Plan 015)", alert_groups_upgrade)
runner.register("0009", "add cert_history table (Plan 016)", cert_history_upgrade)
runner.register(
    "0010", "add extra_recipients column to alerts (BC-051)",
    alert_extra_recipients_upgrade,
)
runner.register(
    "0011", "add session_versions table for session revocation (BC-081)",
    session_versions_upgrade,
)
runner.register(
    "0012", "add chain_incomplete column to scan_posture (BC-108)",
    scan_degraded_upgrade,
)
runner.register(
    "0013", "rename tls_verified to verify_requested in scan_posture (BC-125)",
    verify_requested_upgrade,
)
runner.register(
    "0014", "add read flag to alerts for unread tracking (BC-127)",
    alert_read_upgrade,
)
runner.register(
    "0015", "add api_keys table for M2M auth (Plan 039 / BC-104)",
    api_keys_upgrade,
)
runner.register(
    "0016", "add chain_status column to scan_posture (BC-100)",
    chain_status_upgrade,
)
runner.register(
    "0017", "add CAA columns to scan_posture (BC-121)",
    caa_per_scan_upgrade,
)
runner.register(
    "0018", "add ct_issuer_first_seen table (BC-151)",
    ct_issuer_first_seen_upgrade,
)
runner.register(
    "0019", "add users and roles tables for local auth (Plan 040)",
    users_roles_upgrade,
)
runner.register(
    "0020", "add hostname and subject columns to alerts",
    alert_hostname_subject_upgrade,
)
runner.register(
    "0021", "add event_log table for event streaming (Plan 044)",
    event_log_upgrade,
)
runner.register(
    "0022", "add expected_issuers column to hosts (WI-007)",
    hosts_expected_issuers_upgrade,
)
runner.register(
    "0023", "add not_before column to cert_history (Plan 048 WI-2.1)",
    cert_history_not_before_upgrade,
)
runner.register(
    "0024", "add permission_tier and scope_tag to roles (WI-050 / WI-052)",
    role_tiers_upgrade,
)
runner.register(
    "0025", "add threshold_days and digest_cadence_days to alert_groups (WI-056)",
    alert_group_config_upgrade,
)
runner.register(
    "0026", "add alert_group_id to roles for joint alert routing (WI-061)",
    role_alert_group_link_upgrade,
)
runner.register(
    "0027", "add starttls_mode to hosts for STARTTLS scanning",
    host_starttls_upgrade,
)
