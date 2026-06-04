"""k8s smoke test: deploy to a cluster and verify /healthz and /readyz.

Supports two modes:
  - **kind** (CI): creates a throwaway kind cluster, loads the image, applies
    manifests, waits for readiness, polls health endpoints, tears down.
  - **existing cluster** (local dev): uses the current kubeconfig context,
    deploys to a test namespace, polls via port-forward, cleans up.

The mode is controlled by the ``DEPLOY_K8S_MODE`` env var:
  - ``kind``  — use kind (default if ``kind`` is on PATH)
  - ``cluster`` — use the current kubeconfig context
  - ``auto`` — kind if available, else existing cluster, else skip
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

pytestmark = pytest.mark.deploy

TEST_NS = "cert-watch-deploy-test"
APP_LABEL = "app.kubernetes.io/name=cert-watch"


def _detect_mode() -> str:
    mode = os.environ.get("DEPLOY_K8S_MODE", "auto").lower()
    if mode == "auto":
        if shutil.which("kind"):
            return "kind"
        try:
            subprocess.run(
                ["kubectl", "cluster-info"],
                check=True, capture_output=True, timeout=10,
            )
            return "cluster"
        except (FileNotFoundError, subprocess.CalledProcessError):
            return "skip"
    if mode == "skip":
        return "skip"
    return mode


def _kubectl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["kubectl", *args],
        capture_output=True, text=True, check=check,
    )


def _build_deployment_manifest(image_tag: str) -> str:
    import textwrap

    return textwrap.dedent(f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: cert-watch
          namespace: {TEST_NS}
          labels:
            app.kubernetes.io/name: cert-watch
        spec:
          replicas: 1
          strategy:
            type: Recreate
          selector:
            matchLabels:
              app.kubernetes.io/name: cert-watch
          template:
            metadata:
              labels:
                app.kubernetes.io/name: cert-watch
            spec:
              enableServiceLinks: false
              securityContext:
                fsGroup: 999
              containers:
                - name: cert-watch
                  image: {image_tag}
                  imagePullPolicy: Never
                  securityContext:
                    runAsNonRoot: true
                    runAsUser: 999
                    runAsGroup: 999
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    capabilities:
                      drop: ["ALL"]
                  ports:
                    - name: http
                      containerPort: 8000
                  env:
                    - name: CERT_WATCH_DATA_DIR
                      value: /var/lib/cert-watch
                    - name: CERT_WATCH_CSRF_SECRET
                      valueFrom:
                        secretKeyRef:
                          name: cert-watch-secrets
                          key: csrf-secret
                    - name: CERT_WATCH_ALLOW_UNAUTH
                      value: "1"
                  readinessProbe:
                    httpGet:
                      path: /readyz
                      port: http
                    initialDelaySeconds: 3
                    periodSeconds: 10
                  livenessProbe:
                    httpGet:
                      path: /healthz
                      port: http
                    initialDelaySeconds: 15
                    periodSeconds: 30
                  resources:
                    requests:
                      cpu: 25m
                      memory: 64Mi
                    limits:
                      cpu: 500m
                      memory: 256Mi
                  volumeMounts:
                    - name: data
                      mountPath: /var/lib/cert-watch
                    - name: tmp
                      mountPath: /tmp
              volumes:
                - name: data
                  emptyDir: {{}}
                - name: tmp
                  emptyDir: {{}}
    """)


def _kubectl_apply_manifests(image_tag: str) -> None:
    import textwrap

    manifests = [
        textwrap.dedent(f"""\
            apiVersion: v1
            kind: Namespace
            metadata:
              name: {TEST_NS}
        """),
        textwrap.dedent(f"""\
            apiVersion: v1
            kind: Secret
            metadata:
              name: cert-watch-secrets
              namespace: {TEST_NS}
            type: Opaque
            stringData:
              csrf-secret: "test-deploy-smoke-csrf-secret-value"
              auth-secret: "test-deploy-smoke-auth-secret-value"
        """),
        _build_deployment_manifest(image_tag),
        textwrap.dedent(f"""\
            apiVersion: v1
            kind: Service
            metadata:
              name: cert-watch
              namespace: {TEST_NS}
            spec:
              selector:
                app.kubernetes.io/name: cert-watch
              ports:
                - name: http
                  port: 80
                  targetPort: http
        """),
    ]
    for manifest in manifests:
        r = subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=manifest, capture_output=True, text=True,
        )
        if r.returncode != 0:
            pytest.fail(f"kubectl apply failed:\n{r.stderr}\nManifest:\n{manifest}")


class _KindCluster:
    CLUSTER_NAME = "cert-watch-deploy-test"

    def __init__(self, image_tag: str):
        self.image_tag = image_tag

    def create(self) -> None:
        subprocess.run(
            ["kind", "create", "cluster",
             "--name", self.CLUSTER_NAME,
             "--wait", "120s",
             "--retain"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["kind", "load", "docker-image", self.image_tag,
             "--name", self.CLUSTER_NAME],
            check=True, capture_output=True, text=True,
        )

    def destroy(self) -> None:
        subprocess.run(
            ["kind", "delete", "cluster", "--name", self.CLUSTER_NAME],
            capture_output=True, text=True,
        )


class _ExistingCluster:
    def __init__(self, image_tag: str):
        self.image_tag = image_tag
        self._image_loaded = False

    def load_image(self) -> None:
        save = subprocess.run(
            ["docker", "save", self.image_tag],
            capture_output=True,
        )
        if save.returncode != 0:
            return
        ctr_sockets = [
            "/run/k3s/containerd/containerd.sock",
            "/run/containerd/containerd.sock",
        ]
        for sock in ctr_sockets:
            if not os.path.exists(sock):
                continue
            r = subprocess.run(
                [
                    "ctr", "-a", sock, "-n", "k8s.io",
                    "images", "import", "--all-platforms", "/dev/stdin",
                ],
                input=save.stdout,
                capture_output=True,
            )
            if r.returncode == 0:
                self._image_loaded = True
                return

    def cleanup(self) -> None:
        _kubectl("delete", "namespace", TEST_NS, "--ignore-not-found=true", "--wait=true")


@pytest.fixture(scope="module")
def k8s_cluster(docker_image):
    mode = _detect_mode()
    if mode == "skip":
        pytest.skip("No k8s cluster available and kind not installed")
    if mode == "kind":
        if not shutil.which("kind"):
            pytest.skip("kind not installed (set DEPLOY_K8S_MODE=cluster to use existing cluster)")
        cluster = _KindCluster(docker_image)
        cluster.create()
        yield
        _kubectl("delete", "namespace", TEST_NS, "--ignore-not-found=true", "--wait=false")
        cluster.destroy()
    else:
        cluster = _ExistingCluster(docker_image)
        cluster.load_image()
        yield
        cluster.cleanup()


@pytest.fixture(scope="module", autouse=True)
def k8s_deploy(k8s_cluster, docker_image):
    _kubectl("delete", "namespace", TEST_NS, "--ignore-not-found=true", "--wait=true")
    time.sleep(1)
    _kubectl_apply_manifests(docker_image)
    wait = subprocess.run(
        [
            "kubectl", "wait",
            "--for=condition=ready", "pod",
            "-l", APP_LABEL,
            "-n", TEST_NS,
            "--timeout=180s",
        ],
        capture_output=True, text=True,
    )
    if wait.returncode != 0:
        _kubectl("logs", "-l", APP_LABEL, "-n", TEST_NS, check=False)
        _kubectl("describe", "pod", "-l", APP_LABEL, "-n", TEST_NS, check=False)
        pytest.fail(f"Pod never became ready:\n{wait.stderr}")


def test_healthz_via_port_forward(waiter):
    port = 18889
    pf = subprocess.Popen(
        ["kubectl", "port-forward",
         "service/cert-watch", f"{port}:80",
         "-n", TEST_NS],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        w = waiter(f"http://127.0.0.1:{port}", timeout=30)
        body = w.poll_healthy()
        assert body["status"] == "ok", f"unexpected healthz: {body}"
    finally:
        pf.terminate()
        pf.wait(timeout=10)


def test_readyz_via_port_forward(waiter):
    port = 18890
    pf = subprocess.Popen(
        ["kubectl", "port-forward",
         "service/cert-watch", f"{port}:80",
         "-n", TEST_NS],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        w = waiter(f"http://127.0.0.1:{port}", timeout=30)
        body = w.poll_ready()
        assert body["status"] == "ok", f"unexpected readyz: {body}"
        assert body.get("checks", {}).get("database") == "ok"
    finally:
        pf.terminate()
        pf.wait(timeout=10)
