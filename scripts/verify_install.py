#!/usr/bin/env python3
"""Verify a cert-watch deployment and emit an agent-friendly report.

The Linux/container counterpart to ``scripts/Verify-Install.ps1``. It runs a
battery of acceptance checks against an installed cert-watch deployment
(systemd, Docker/Compose, or Kubernetes) plus live HTTP health, and gathers a
self-contained diagnostics bundle. The result is a single structured JSON
document (the *same* schema the PowerShell verifier emits) so an agent or a
human can triage a failed deploy without shelling into the host, plus a
readable console summary.

Stdlib only -- it runs with the system Python, outside the app venv, which
matters for the container/k8s targets where you verify from the operator's
machine. Read-only: it inspects state and never modifies the deployment.

Exit code is 0 when no check fails (warnings allowed) and 1 otherwise, so CI
and change-control gates can branch on it.

Examples:
    # Native / systemd install on this host
    python3 scripts/verify_install.py --target systemd

    # Docker Compose, streaming JSON to an automated triage step
    python3 scripts/verify_install.py --target docker --json

    # Kubernetes (HTTP checks need a reachable URL, e.g. via port-forward)
    python3 scripts/verify_install.py --target k8s --namespace cert-watch \
        --base-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.request

SCHEMA_VERSION = "1.0"
TOOL_VERSION = "0.1.0"
RUNBOOK = "docs/runbook.md / deploy/<target>/"


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def cap(text: str, max_chars: int = 4000) -> str:
    """Truncate keeping the tail (most relevant log lines live at the end)."""
    if text is None:
        return ""
    text = str(text)
    if len(text) <= max_chars:
        return text
    return f"...[truncated {len(text) - max_chars} chars]...\n" + text[-max_chars:]


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(args: list[str], timeout: int = 20) -> dict:
    """Run a command; never raise. Returns {rc, out} (out = stdout+stderr)."""
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
        return {"rc": p.returncode, "out": p.stdout or ""}
    except FileNotFoundError:
        return {"rc": 127, "out": f"command not found: {args[0]}"}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": f"timed out after {timeout}s: {' '.join(args)}"}
    except Exception as exc:  # noqa: BLE001 - diagnostics must never crash the run
        return {"rc": 1, "out": f"error running {' '.join(args)}: {exc}"}


def http_get(url: str, insecure: bool = False, timeout: int = 10) -> dict:
    out = {"url": url, "ok": False, "code": 0, "body": "", "error": ""}
    ctx = None
    if url.lower().startswith("https") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:
            out["ok"] = True
            out["code"] = int(getattr(resp, "status", 0) or 0)
            out["body"] = resp.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        out["code"] = int(exc.code)
        out["error"] = f"HTTP {exc.code}"
        with contextlib.suppress(Exception):
            out["body"] = exc.read(2048).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    return out


# --------------------------------------------------------------------------- #
# Verifier
# --------------------------------------------------------------------------- #
class Verifier:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.checks: list[dict] = []
        self.diagnostics: dict[str, str] = {}
        self.health_base = ""  # first base URL that answered /healthz

    def add(
        self,
        cid: str,
        title: str,
        category: str,
        severity: str,
        status: str,
        detail: str,
        evidence: str = "",
        remediation: str = "",
    ) -> None:
        self.checks.append(
            {
                "id": cid,
                "title": title,
                "category": category,
                "severity": severity,
                "status": status,
                "detail": detail,
                "evidence": cap(evidence, 3000),
                "remediation": remediation,
            }
        )

    # -- target detection -------------------------------------------------- #
    def detect_target(self) -> str:
        unit = self.args.unit
        if have("systemctl") and run(["systemctl", "status", unit]).get("rc") in (0, 3):
            # rc 3 = unit known but inactive; both mean the unit exists.
            return "systemd"
        if have("docker") and run(["docker", "inspect", self.args.container]).get("rc") == 0:
            return "docker"
        if have("kubectl") and run(
            ["kubectl", "-n", self.args.namespace, "get", "deploy", self.args.deployment]
        ).get("rc") == 0:
            return "k8s"
        return "http"

    # -- HTTP checks (all targets) ----------------------------------------- #
    def check_http(self, candidates: list[str]) -> None:
        last = ""
        for base in candidates:
            r = http_get(base + "/healthz", self.args.insecure)
            last = f"{r['url']} -> code {r['code']} {r['error']}"
            if r["ok"] and r["code"] == 200:
                self.health_base = base
                self.add(
                    "HTTP-001", "Health endpoint returns 200", "http", "critical",
                    "pass", f"{base}/healthz returned 200", r["body"],
                )
                break
        if not self.health_base:
            self.add(
                "HTTP-001", "Health endpoint returns 200", "http", "critical",
                "fail", f"no probe URL returned 200; last: {last}", last,
                "Check the app logs (journalctl / docker logs / kubectl logs). "
                "If the process is up, confirm the bind address/port and that no "
                "proxy in front is returning the error.",
            )
            return

        r = http_get(self.health_base + "/readyz", self.args.insecure)
        if r["ok"] and r["code"] == 200:
            self.add("HTTP-002", "Readiness endpoint returns 200", "http", "high",
                     "pass", "readyz 200", r["body"])
        else:
            self.add(
                "HTTP-002", "Readiness endpoint returns 200", "http", "high",
                "fail", f"readyz code {r['code']} {r['error']}", r["body"] + r["error"],
                "readyz failing while healthz passes usually means the data dir / "
                "SQLite DB is not writable by the runtime user.",
            )

        r = http_get(self.health_base + "/login", self.args.insecure)
        if r["ok"] and r["code"] == 200:
            self.add("HTTP-003", "Login page renders", "http", "medium", "pass",
                     "login page served")
        else:
            self.add("HTTP-003", "Login page renders", "http", "medium", "warn",
                     f"login code {r['code']} {r['error']}")

    # -- systemd ----------------------------------------------------------- #
    def check_systemd(self) -> None:
        unit = self.args.unit
        if not have("systemctl"):
            self.add("SYS-000", "systemctl available", "systemd", "high", "skip",
                     "systemctl not on PATH (not a systemd host)")
            return

        active = run(["systemctl", "is-active", unit])
        if active["out"].strip() == "active":
            self.add("SYS-001", f"Unit {unit} is active", "systemd", "critical",
                     "pass", "active", active["out"])
        else:
            self.add(
                "SYS-001", f"Unit {unit} is active", "systemd", "critical", "fail",
                f"is-active reported: {active['out'].strip() or 'unknown'}", active["out"],
                f"Start it: systemctl start {unit}; then `journalctl -u {unit}` for why "
                "it is not running.",
            )

        enabled = run(["systemctl", "is-enabled", unit])
        if enabled["out"].strip() == "enabled":
            self.add("SYS-002", f"Unit {unit} is enabled at boot", "systemd", "medium",
                     "pass", "enabled")
        else:
            self.add("SYS-002", f"Unit {unit} is enabled at boot", "systemd", "medium",
                     "warn", f"is-enabled: {enabled['out'].strip() or 'unknown'}",
                     remediation=f"systemctl enable {unit} so it survives a reboot.")

        data_dir = self.args.data_dir
        if os.path.isdir(data_dir):
            try:
                st = os.stat(data_dir)
                mode = oct(st.st_mode & 0o777)
                writable = os.access(data_dir, os.W_OK)
                detail = f"{data_dir} (mode {mode}, uid {st.st_uid})"
                if writable or os.geteuid() != st.st_uid:
                    # We may not be the service user; presence + mode is the signal.
                    self.add("SYS-003", "Data directory exists", "systemd", "high",
                             "pass", detail)
                else:
                    self.add("SYS-003", "Data directory exists", "systemd", "high",
                             "warn", detail + " (not writable by current user)")
            except Exception as exc:  # noqa: BLE001
                self.add("SYS-003", "Data directory exists", "systemd", "high", "warn",
                         f"stat failed: {exc}")
        else:
            self.add("SYS-003", "Data directory exists", "systemd", "high", "fail",
                     f"not found: {data_dir}",
                     remediation="Create the data dir owned by the cert-watch user "
                     "(see deploy/systemd and docs/runbook.md).")

        # Secret persistence: pinned via env, or sessions will not survive restart.
        show = run(["systemctl", "show", unit, "--property=Environment"])
        env_blob = show["out"]
        secret_file = os.path.join(data_dir, "auth_secret")
        if ("CERT_WATCH_AUTH_SECRET=" in env_blob and "CERT_WATCH_CSRF_SECRET=" in env_blob) \
                or "CERT_WATCH_AUTH_SECRET_FILE=" in env_blob \
                or os.path.exists(secret_file):
            self.add("SYS-004", "Signing secrets are pinned (sessions survive restart)",
                     "systemd", "high", "pass", "auth/csrf secret configured",
                     cap(env_blob, 600))
        else:
            self.add(
                "SYS-004", "Signing secrets are pinned (sessions survive restart)",
                "systemd", "high", "warn",
                "no CERT_WATCH_AUTH_SECRET/CSRF in the unit env and no persisted "
                "secret file; every restart will log all users out",
                cap(env_blob, 600),
                "Set CERT_WATCH_AUTH_SECRET and CERT_WATCH_CSRF_SECRET (or their "
                "*_FILE variants) in the unit, like the k8s Secret does.",
            )

    def diag_systemd(self) -> None:
        unit = self.args.unit
        self.diagnostics["systemctl_status"] = cap(
            run(["systemctl", "status", unit, "--no-pager", "--full"])["out"], 4000)
        self.diagnostics["journal_tail"] = cap(
            run(["journalctl", "-u", unit, "-n", "120", "--no-pager"])["out"], 6000)
        self.diagnostics["data_dir_listing"] = cap(
            run(["ls", "-la", self.args.data_dir])["out"], 2000)

    # -- docker / compose -------------------------------------------------- #
    def check_docker(self) -> None:
        name = self.args.container
        if not have("docker"):
            self.add("DOC-000", "docker available", "docker", "high", "skip",
                     "docker not on PATH")
            return
        inspect = run(["docker", "inspect", name])
        if inspect["rc"] != 0:
            self.add("DOC-001", f"Container {name} exists", "docker", "critical", "fail",
                     f"docker inspect failed for {name}", inspect["out"],
                     "Start the stack: docker compose up -d (deploy/compose).")
            return
        try:
            data = json.loads(inspect["out"])[0]
        except Exception as exc:  # noqa: BLE001
            self.add("DOC-001", f"Container {name} exists", "docker", "critical", "warn",
                     f"could not parse inspect output: {exc}", cap(inspect["out"], 1500))
            return

        state = data.get("State", {})
        running = bool(state.get("Running"))
        self.add("DOC-001", f"Container {name} is running", "docker", "critical",
                 "pass" if running else "fail",
                 "running" if running else f"state: {state.get('Status')}",
                 remediation=None if running else "docker start " + name)

        health = (state.get("Health") or {}).get("Status")
        if health is None:
            self.add("DOC-002", "Container healthcheck", "docker", "high", "skip",
                     "no HEALTHCHECK reported")
        elif health == "healthy":
            self.add("DOC-002", "Container healthcheck", "docker", "high", "pass", "healthy")
        else:
            self.add("DOC-002", "Container healthcheck", "docker", "high", "fail",
                     f"health status: {health}",
                     cap(json.dumps((state.get("Health") or {}).get("Log", []), indent=0), 1500),
                     "Inspect the failing healthcheck: docker inspect " + name)

        restarts = int(state.get("RestartCount", 0) or 0)
        if restarts <= 2:
            self.add("DOC-003", "Container is not crash-looping", "docker", "medium",
                     "pass", f"restart count {restarts}")
        else:
            self.add("DOC-003", "Container is not crash-looping", "docker", "medium",
                     "warn", f"restart count {restarts} (possible crash loop)",
                     remediation="Check docker logs " + name)

    def diag_docker(self) -> None:
        name = self.args.container
        self.diagnostics["docker_ps"] = cap(
            run(["docker", "ps", "-a", "--filter", f"name={name}"])["out"], 1500)
        self.diagnostics["docker_logs_tail"] = cap(
            run(["docker", "logs", "--tail", "120", name])["out"], 6000)
        ins = run(["docker", "inspect", name])
        self.diagnostics["docker_inspect"] = cap(ins["out"], 4000)

    # -- kubernetes -------------------------------------------------------- #
    def check_k8s(self) -> None:
        ns = self.args.namespace
        dep = self.args.deployment
        if not have("kubectl"):
            self.add("K8S-000", "kubectl available", "k8s", "high", "skip",
                     "kubectl not on PATH")
            return
        getj = run(["kubectl", "-n", ns, "get", "deploy", dep, "-o", "json"])
        if getj["rc"] != 0:
            self.add("K8S-001", f"Deployment {dep} exists", "k8s", "critical", "fail",
                     f"deployment not found in namespace {ns}", getj["out"],
                     "kubectl apply -k deploy/k8s")
            return
        try:
            d = json.loads(getj["out"])
        except Exception as exc:  # noqa: BLE001
            self.add("K8S-001", f"Deployment {dep} exists", "k8s", "critical", "warn",
                     f"could not parse deployment json: {exc}", cap(getj["out"], 1500))
            return

        self.add("K8S-001", f"Deployment {dep} exists", "k8s", "high", "pass", "found")

        spec_replicas = (d.get("spec", {}) or {}).get("replicas", 1)
        status = d.get("status", {}) or {}
        ready = status.get("readyReplicas", 0) or 0
        if ready >= spec_replicas and ready > 0:
            self.add("K8S-002", "All replicas are ready", "k8s", "critical", "pass",
                     f"{ready}/{spec_replicas} ready")
        else:
            self.add("K8S-002", "All replicas are ready", "k8s", "critical", "fail",
                     f"{ready}/{spec_replicas} ready",
                     cap(json.dumps(status, indent=0), 1500),
                     f"kubectl -n {ns} rollout status deploy/{dep}; then describe the pods.")

        rollout = run(["kubectl", "-n", ns, "rollout", "status", f"deploy/{dep}",
                       "--timeout=5s"])
        if rollout["rc"] == 0:
            self.add("K8S-003", "Rollout is complete", "k8s", "high", "pass",
                     rollout["out"].strip())
        else:
            self.add("K8S-003", "Rollout is complete", "k8s", "high", "warn",
                     rollout["out"].strip() or "rollout not complete",
                     remediation=f"kubectl -n {ns} get pods -l app.kubernetes.io/name={dep}")

        # Crash-loop / restart signal across pods.
        pods = run(["kubectl", "-n", ns, "get", "pods",
                    "-l", f"app.kubernetes.io/name={dep}", "-o", "json"])
        try:
            items = json.loads(pods["out"]).get("items", [])
            total_restarts = 0
            for pod in items:
                for cs in (pod.get("status", {}) or {}).get("containerStatuses", []) or []:
                    total_restarts += int(cs.get("restartCount", 0) or 0)
            if total_restarts <= 3:
                self.add("K8S-004", "Pods are not crash-looping", "k8s", "medium", "pass",
                         f"{total_restarts} restarts across {len(items)} pod(s)")
            else:
                self.add("K8S-004", "Pods are not crash-looping", "k8s", "medium", "warn",
                         f"{total_restarts} restarts across {len(items)} pod(s)",
                         remediation=f"kubectl -n {ns} logs -l "
                         f"app.kubernetes.io/name={dep} --previous")
        except Exception:  # noqa: BLE001
            self.add("K8S-004", "Pods are not crash-looping", "k8s", "medium", "skip",
                     "could not read pod restart counts")

        secret = run(["kubectl", "-n", ns, "get", "secret", "cert-watch-secrets"])
        if secret["rc"] == 0:
            self.add("K8S-005", "Signing-secret object exists", "k8s", "high", "pass",
                     "cert-watch-secrets present")
        else:
            self.add("K8S-005", "Signing-secret object exists", "k8s", "high", "fail",
                     "cert-watch-secrets not found",
                     remediation="Create the Secret (see deploy/k8s/secret-example.yaml); "
                     "without it sessions break on pod restart.")

    def diag_k8s(self) -> None:
        ns = self.args.namespace
        dep = self.args.deployment
        self.diagnostics["k8s_get"] = cap(
            run(["kubectl", "-n", ns, "get", "deploy,pods,svc,ingress", "-o", "wide"])["out"],
            3000)
        self.diagnostics["k8s_describe_deploy"] = cap(
            run(["kubectl", "-n", ns, "describe", "deploy", dep])["out"], 4000)
        self.diagnostics["k8s_logs_tail"] = cap(
            run(["kubectl", "-n", ns, "logs", f"deploy/{dep}", "--tail=120"])["out"], 6000)
        self.diagnostics["k8s_events"] = cap(
            run(["kubectl", "-n", ns, "get", "events", "--sort-by=.lastTimestamp"])["out"],
            3000)

    # -- orchestration ----------------------------------------------------- #
    def http_candidates(self) -> list[str]:
        if self.args.base_url:
            return [self.args.base_url.rstrip("/")]
        # Sensible per-target default; k8s has no default route from outside.
        if self.target == "k8s":
            return []
        return ["http://127.0.0.1:8000"]

    def run_all(self) -> dict:
        self.target = self.args.target
        if self.target == "auto":
            self.target = self.detect_target()

        if self.target == "systemd":
            self.check_systemd()
        elif self.target in ("docker", "compose"):
            self.check_docker()
        elif self.target == "k8s":
            self.check_k8s()

        candidates = self.http_candidates()
        if candidates:
            self.check_http(candidates)
        else:
            self.add("HTTP-001", "Health endpoint returns 200", "http", "critical",
                     "skip", "no base URL; pass --base-url (e.g. via kubectl port-forward)")

        passed = sum(1 for c in self.checks if c["status"] == "pass")
        failed = sum(1 for c in self.checks if c["status"] == "fail")
        warned = sum(1 for c in self.checks if c["status"] == "warn")
        skipped = sum(1 for c in self.checks if c["status"] == "skip")
        overall = "fail" if failed else ("warn" if warned else "pass")

        if self.args.full_diagnostics or overall != "pass":
            if self.target == "systemd":
                self.diag_systemd()
            elif self.target in ("docker", "compose"):
                self.diag_docker()
            elif self.target == "k8s":
                self.diag_k8s()
            for c in self.checks:
                if c["category"] == "http" and c["status"] in ("fail", "warn") and c["evidence"]:
                    self.diagnostics.setdefault("http_bodies", "")
                    self.diagnostics["http_bodies"] += f"\n[{c['id']}] {c['evidence']}"
        else:
            self.diagnostics["note"] = (
                "all checks passed; run with --full-diagnostics to force a full bundle")

        next_actions = [
            f"{c['id']}: {c['remediation']}"
            for c in self.checks
            if c["status"] == "fail" and c["remediation"]
        ]

        return {
            "schemaVersion": SCHEMA_VERSION,
            "tool": "cert-watch verify",
            "toolVersion": TOOL_VERSION,
            "generatedAtUtc": datetime.datetime.now(datetime.UTC).isoformat(),
            "host": {
                "name": socket.gethostname(),
                "os": platform.platform(),
                "python": platform.python_version(),
            },
            "target": {
                "kind": self.target,
                "baseUrl": self.health_base or ", ".join(candidates),
                "namespace": self.args.namespace,
                "deployment": self.args.deployment,
                "container": self.args.container,
                "unit": self.args.unit,
                "dataDir": self.args.data_dir,
            },
            "summary": {
                "total": len(self.checks),
                "passed": passed,
                "failed": failed,
                "warned": warned,
                "skipped": skipped,
                "overall": overall,
            },
            "checks": self.checks,
            "nextActions": next_actions,
            "diagnostics": self.diagnostics,
        }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_console(report: dict) -> None:
    s = report["summary"]
    print()
    print(f"cert-watch verify [{report['target']['kind']}]  ::  "
          f"overall={s['overall'].upper()}  "
          f"({s['passed']} pass / {s['failed']} fail / "
          f"{s['warned']} warn / {s['skipped']} skip)")
    print()
    for c in report["checks"]:
        tag = f"[{c['status'].upper()}]".ljust(7)
        print(f"{tag}{c['id']}  {c['title']}")
        if c["status"] in ("fail", "warn"):
            print(f"         {c['detail']}")
    if report["nextActions"]:
        print("\nNext actions:")
        for a in report["nextActions"]:
            print(f"  - {a}")


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# cert-watch deployment verification",
        "",
        f"- Host: {report['host']['name']}",
        f"- Target: {report['target']['kind']}",
        f"- Generated (UTC): {report['generatedAtUtc']}",
        f"- Overall: {s['overall'].upper()} "
        f"({s['passed']} pass / {s['failed']} fail / {s['warned']} warn / {s['skipped']} skip)",
        "",
        "| Status | ID | Check | Detail |",
        "|---|---|---|---|",
    ]
    for c in report["checks"]:
        detail = c["detail"].replace("|", "/")
        lines.append(f"| {c['status'].upper()} | {c['id']} | {c['title']} | {detail} |")
    if report["nextActions"]:
        lines += ["", "## Next actions"] + [f"- {a}" for a in report["nextActions"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Verify a cert-watch deployment.")
    ap.add_argument("--target", default="auto",
                    choices=["auto", "systemd", "docker", "compose", "k8s", "http"])
    ap.add_argument("--base-url", default="",
                    help="URL to probe for health (default http://127.0.0.1:8000 "
                         "except k8s, which has no default route).")
    ap.add_argument("--unit", default="cert-watch", help="systemd unit name")
    ap.add_argument("--container", default="cert-watch", help="docker container name")
    ap.add_argument("--namespace", default="cert-watch", help="k8s namespace")
    ap.add_argument("--deployment", default="cert-watch", help="k8s deployment name")
    ap.add_argument("--data-dir", default="/var/lib/cert-watch")
    ap.add_argument("--output", default="", help="path to write the JSON report")
    ap.add_argument("--json", action="store_true", help="also print JSON to stdout")
    ap.add_argument("--markdown", action="store_true", help="also write a .md report")
    ap.add_argument("--insecure", action="store_true",
                    help="accept self-signed TLS when probing https")
    ap.add_argument("--full-diagnostics", action="store_true",
                    help="gather the full diagnostics bundle even when all pass")
    args = ap.parse_args(argv)

    report = Verifier(args).run_all()
    json_text = json.dumps(report, indent=2)

    out_path = args.output or f"verify-report-{report['target']['kind']}.json"
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(json_text)
        wrote = out_path
    except Exception as exc:  # noqa: BLE001
        wrote = f"(failed to write {out_path}: {exc})"

    if args.markdown:
        md_path = os.path.splitext(out_path)[0] + ".md"
        try:
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(report))
        except Exception:  # noqa: BLE001
            pass

    render_console(report)
    print(f"\nreport: {wrote}")
    if args.json:
        print(json_text)

    return 1 if report["summary"]["overall"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
