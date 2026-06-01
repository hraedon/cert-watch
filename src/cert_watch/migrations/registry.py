"""Migration registry — import this to register all known migrations."""

from cert_watch.migrations import runner
from cert_watch.migrations.m0001_baseline import upgrade as baseline_upgrade
from cert_watch.migrations.m0002_audit_log import upgrade as audit_log_upgrade
from cert_watch.migrations.m0003_rate_limits import upgrade as rate_limits_upgrade
from cert_watch.migrations.m0004_tls_verified import upgrade as tls_verified_upgrade
from cert_watch.migrations.m0005_composite_indexes import upgrade as composite_indexes_upgrade
from cert_watch.migrations.m0006_cert_tags import upgrade as cert_tags_upgrade

runner.register("0001", "baseline: snapshot of pre-migration schema", baseline_upgrade)
runner.register("0002", "add audit_log table (Plan 008)", audit_log_upgrade)
runner.register("0003", "add rate_limits table (BC-049)", rate_limits_upgrade)
runner.register("0004", "add tls_verified column to scan_posture (BC-064)", tls_verified_upgrade)
runner.register(
    "0005", "add composite indexes for hostname/port queries",
    composite_indexes_upgrade,
)
runner.register("0006", "add tags column to certificates (plan 013)", cert_tags_upgrade)