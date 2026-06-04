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