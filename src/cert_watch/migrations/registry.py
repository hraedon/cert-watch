"""Migration registry — import this to register all known migrations."""

from cert_watch.migrations import runner
from cert_watch.migrations.m0001_baseline import upgrade as baseline_upgrade
from cert_watch.migrations.m0002_audit_log import upgrade as audit_log_upgrade

runner.register("0001", "baseline: snapshot of pre-migration schema", baseline_upgrade)
runner.register("0002", "add audit_log table (Plan 008)", audit_log_upgrade)