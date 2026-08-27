"""Bounded extraction of declared security-domain evidence from explicit documentation."""

from __future__ import annotations

import re
from pathlib import Path

from before_deploy.inventory import RepositoryInventory
from before_deploy.models import EvidenceKind, EvidenceSignal, Location

EVIDENCE_VERSION = "0.3.0"
MAX_DOCUMENT_CHARACTERS = 200_000

_DOMAIN_PATTERNS = {
    "API": re.compile(r"\b(?:rest(?:ful)?\s+api|api\s+endpoint|graphql)\b", re.IGNORECASE),
    "AUTHENTICATION": re.compile(
        r"\b(?:authentication|login|sign[ -]?in|jwt|oauth(?:2)?|session\s+cookie)\b",
        re.IGNORECASE,
    ),
    "AUTHORIZATION": re.compile(
        r"\b(?:"
        r"authori[sz](?:ation(?!\s+header\b)|e|es|ed|ing)"
        r"|(?:role[- ]based\s+)?access\s+control"
        r"|rbac|access\s+control\s+list|acl|permission[- ]based\s+access\s+control"
        r")\b",
        re.IGNORECASE,
    ),
    "EXTERNAL-URL-FETCH": re.compile(
        r"\b(?:"
        r"(?:fetch|retrieve|request|download)\s+(?:an?\s+)?(?:external|remote)\s+(?:url|uri|resource)"
        r"|outbound\s+(?:http|https)\s+request"
        r")\b",
        re.IGNORECASE,
    ),
    "FILE-UPLOAD": re.compile(r"\b(?:file\s+upload|upload(?:ed|ing)?\s+file|attachment)\b", re.IGNORECASE),
    "PAYMENT": re.compile(
        r"\b(?:payment(?:s|\s+processing)?|checkout|billing|subscription|stripe)\b",
        re.IGNORECASE,
    ),
    "PERSONAL-DATA": re.compile(r"\b(?:personal\s+data|personally\s+identifiable|pii|gdpr)\b", re.IGNORECASE),
}

_DOMAIN_TITLES = {
    "API": "API exposure",
    "AUTHENTICATION": "Authentication",
    "AUTHORIZATION": "Authorization",
    "EXTERNAL-URL-FETCH": "External URL fetching",
    "FILE-UPLOAD": "File upload",
    "PAYMENT": "Payment processing",
    "PERSONAL-DATA": "Personal data",
}


def collect_requirements_evidence(inventory: RepositoryInventory) -> tuple[EvidenceSignal, ...]:
    """Return one traceable declared-domain signal per bounded document pattern.

    The collector does not preserve matching sentences, infer implementation, or inspect dependency
    manifests such as ``requirements.txt``. It records only a stable domain identifier and location.
    """
    matches: dict[str, EvidenceSignal] = {}
    for path in inventory.files:
        relative_path = path.relative_to(inventory.root)
        if not _is_requirements_document(relative_path):
            continue
        try:
            document = path.read_text(encoding="utf-8", errors="ignore")[:MAX_DOCUMENT_CHARACTERS]
        except OSError:
            continue
        for line_number, line in enumerate(document.splitlines(), start=1):
            for domain, pattern in _DOMAIN_PATTERNS.items():
                if domain in matches or not pattern.search(line):
                    continue
                matches[domain] = EvidenceSignal(
                    signal_id=f"REQUIREMENT-{domain}",
                    signal_version=EVIDENCE_VERSION,
                    kind=EvidenceKind.REQUIREMENT,
                    title=f"Declared security domain: {_DOMAIN_TITLES[domain]}",
                    location=Location(path=relative_path.as_posix(), start_line=line_number),
                    metadata={"classification": "declared", "domain": domain},
                )
    return tuple(matches[domain] for domain in sorted(matches))


def _is_requirements_document(relative_path: Path) -> bool:
    name = relative_path.name.lower()
    if name in {"architecture.md", "design.md", "requirements.md", "spec.md", "specification.md"}:
        return True
    if name.startswith("readme.") and relative_path.parent == Path("."):
        return True
    return relative_path.parts[0] == "docs" and relative_path.suffix.lower() == ".md"
