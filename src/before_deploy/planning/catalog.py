"""Versioned, approved catalog metadata for deterministic analysis planning."""

from __future__ import annotations

CATALOG_VERSION = "0.1.0"

ADAPTER_CONTROL_IDS = frozenset(
    {
        "SEC-DEP-VULN-001",
        "SEC-PROVENANCE-001",
        "SEC-SAST-SEMGREP-001",
        "SEC-SECRET-GITLEAKS-001",
    }
)

DOMAIN_CAPABILITIES = {
    "API security": frozenset({"SEC-API-001"}),
    "CI/CD": frozenset({"SEC-CICD-001"}),
    "Dependency manifests": frozenset({"SEC-DEP-001", "SEC-DEP-VULN-001"}),
    "Framework: FastAPI": frozenset({"SEC-API-001", "SEC-CONFIG-001", "SEC-CONFIG-002"}),
    "Framework: GitHub Actions": frozenset({"SEC-CICD-001"}),
    "Framework: Next.js": frozenset(
        {"SEC-NEXT-ENV-001", "SEC-NEXT-COOKIE-001", "SEC-NEXT-CORS-001"}
    ),
    "Language: JavaScript": frozenset(
        {"SEC-NEXT-ENV-001", "SEC-NEXT-COOKIE-001", "SEC-NEXT-CORS-001"}
    ),
    "Language: Python": frozenset(
        {"SEC-SAST-001", "SEC-CONFIG-001", "SEC-CONFIG-002", "SEC-DEP-VULN-001"}
    ),
    "Language: TypeScript": frozenset(
        {"SEC-NEXT-ENV-001", "SEC-NEXT-COOKIE-001", "SEC-NEXT-CORS-001"}
    ),
    "Secrets": frozenset({"SEC-SECRET-001", "SEC-SECRET-GITLEAKS-001"}),
}

DIRECT_REQUIREMENT_DOMAINS = frozenset(
    {
        "AUTHENTICATION",
        "FILE-UPLOAD",
        "PAYMENT",
        "PERSONAL-DATA",
    }
)
