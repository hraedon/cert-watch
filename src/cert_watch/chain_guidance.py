"""Explain chain validation using only the certificates already stored locally.

An absent issuer's name is evidence; whether it is a root or intermediate is
not generally knowable without that certificate. Never fetch or trust it here.
"""
from __future__ import annotations

from dataclasses import dataclass

from cert_watch.cert_chain import _issuer_bytes, _subject_bytes
from cert_watch.certificate_model import Certificate


@dataclass(frozen=True)
class ChainGuidance:
    kind: str
    title: str
    explanation: str
    remediation: str = ""
    expected_issuer: str = ""


def describe_chain(leaf: Certificate, chain: list[Certificate], status: str) -> ChainGuidance:
    """Describe a validation result without changing the trust decision."""
    if status in ("public", "private"):
        return ChainGuidance(
            "complete", "Chain complete",
            f"The stored chain verifies to a trusted {status} root. "
            "The root does not need to be sent by the TLS server.",
        )
    if status == "self-signed":
        return ChainGuidance(
            "self_signed", "Self-signed certificate",
            "The leaf names itself as its issuer and is not anchored in the trust store.",
            "Use a certificate issued by a trusted CA. For private PKI, configure the "
            "verified issuing CA in Settings → Trust anchors.",
        )

    bundle_hint = (
        "Configure the TLS endpoint with its leaf certificate and required intermediate "
        "certificates, in issuer order, then scan again."
        if leaf.source == "scanned" else
        "Upload the leaf certificate and its required intermediate certificates as a "
        "complete bundle, in issuer order."
    )
    full = [leaf, *chain]
    for child, parent in zip(full, full[1:], strict=False):
        if _issuer_bytes(child) != _subject_bytes(parent):
            present = any(_issuer_bytes(child) == _subject_bytes(c) for c in chain)
            return ChainGuidance(
                "order" if present else "missing_issuer",
                "Chain certificates are out of order" if present else "Missing issuer certificate",
                f"The next certificate after {child.subject} does not match its issuer.",
                bundle_hint,
                child.issuer,
            )

    if status == "invalid":
        return ChainGuidance(
            "invalid", "Chain could not be verified",
            "Issuer names line up, but the stored certificates could not be "
            "cryptographically verified.",
            "Obtain the correct issuing chain from the CA and check that the certificates "
            "belong to this leaf. " + bundle_hint,
        )
    last = full[-1]
    if _subject_bytes(last) == _issuer_bytes(last):
        return ChainGuidance(
            "untrusted_root", "Root certificate is present but not trusted",
            f"The chain reaches {last.subject}, but that root is not trusted by this instance.",
            "For private PKI, verify the root with your CA and add it in Settings → Trust "
            "anchors. For a public CA, check this instance's system CA bundle. "
            "Sending the root from the server does not make it trusted.",
        )
    return ChainGuidance(
        "missing_issuer", "Unable to reach a trusted root",
        f"The stored chain ends at {last.subject}. Its expected issuer is unavailable "
        "to this instance; it may be an intermediate or a root absent from its trust store.",
        "Check the CA's chain bundle for the expected issuer. " + bundle_hint + " "
        "If the issuer is a private root, verify it and add it in Settings → Trust anchors "
        "instead. Public roots normally come from the system CA bundle.",
        last.issuer,
    )
