"""Each k8s overlay's NetworkPolicy must admit the controller its Ingress names.

A namespaceSelector that matches no namespace silently denies all traffic: the
pod stays Ready and the only symptom is a 502 from the ingress controller. That
shipped twice (deploy/k8s named a nonexistent ``ingress`` namespace; the demo
overlay named its own namespace), so pin the relationship statically. The lab's
Traefik controllers run in a namespace named after their ingress class.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
OVERLAYS = ["k8s", "k8s-demo"]


def _load(overlay: str, name: str) -> dict:
    return yaml.safe_load((DEPLOY / overlay / name).read_text(encoding="utf-8"))


def _admitted_namespaces(policy: dict) -> set[str]:
    names: set[str] = set()
    for rule in policy["spec"].get("ingress", []):
        for peer in rule.get("from", []):
            labels = (peer.get("namespaceSelector") or {}).get("matchLabels", {})
            if "kubernetes.io/metadata.name" in labels:
                names.add(labels["kubernetes.io/metadata.name"])
    return names


@pytest.mark.parametrize("overlay", OVERLAYS)
def test_networkpolicy_admits_the_ingress_controller_namespace(overlay: str) -> None:
    ingress_class = _load(overlay, "ingress.yaml")["spec"]["ingressClassName"]
    assert ingress_class in _admitted_namespaces(_load(overlay, "networkpolicy.yaml"))
