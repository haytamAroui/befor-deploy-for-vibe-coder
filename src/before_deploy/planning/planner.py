"""Deterministic construction of a traceable security analysis plan."""

from __future__ import annotations

from typing import Iterable

from before_deploy.models import (
    CapabilitySelection,
    CoverageExpectation,
    EvidenceSignal,
    ProjectProfile,
    SecurityAnalysisPlan,
)
from before_deploy.planning.catalog import ADAPTER_CONTROL_IDS, CATALOG_VERSION

PLAN_VERSION = "0.1.0"
PROFILE_VERSION = "0.1.0"


def build_security_analysis_plan(
    project_profile: ProjectProfile,
    evidence: Iterable[EvidenceSignal],
    runnable_controls: Iterable[object],
) -> SecurityAnalysisPlan:
    """Build a versioned plan from approved, already-compatible controls only.

    The plan is descriptive. It cannot add controls, execute adapters, create waivers, or alter policy.
    """
    ordered_evidence = tuple(sorted(evidence, key=lambda item: item.signal_id))
    evidence_ids = {item.signal_id for item in ordered_evidence}
    selections = tuple(
        _selection(control, project_profile, evidence_ids)
        for control in sorted(runnable_controls, key=lambda item: getattr(item, "control_id"))
    )
    control_selections = tuple(item for item in selections if item.kind == "CONTROL")
    adapter_selections = tuple(item for item in selections if item.kind == "ADAPTER")
    coverage_expectations = _coverage_expectations(project_profile, ordered_evidence)
    exclusions = tuple(
        sorted(
            {
                *project_profile.coverage_gaps,
                "Declarative skill packs are not loaded in this planning-foundation milestone.",
                "External adapters are selected only when explicitly configured by policy.",
            }
        )
    )
    return SecurityAnalysisPlan(
        plan_version=PLAN_VERSION,
        profile_version=PROFILE_VERSION,
        catalog_version=CATALOG_VERSION,
        evidence=ordered_evidence,
        control_selections=control_selections,
        adapter_selections=adapter_selections,
        skill_selections=(),
        coverage_expectations=coverage_expectations,
        exclusions=exclusions,
    )


def _selection(
    control: object,
    project_profile: ProjectProfile,
    evidence_ids: set[str],
) -> CapabilitySelection:
    control_id = getattr(control, "control_id")
    return CapabilitySelection(
        capability_id=control_id,
        capability_version=getattr(control, "control_version"),
        kind="ADAPTER" if control_id in ADAPTER_CONTROL_IDS else "CONTROL",
        rationale=_rationale(control_id, project_profile),
        evidence_ids=_selection_evidence_ids(control_id, project_profile, evidence_ids),
    )


def _rationale(control_id: str, project_profile: ProjectProfile) -> str:
    if control_id.startswith("SEC-NEXT-"):
        return "Next.js framework evidence selected this approved static control."
    if control_id == "SEC-API-001":
        return "FastAPI framework evidence selected this approved route-declaration control."
    if control_id in {"SEC-CONFIG-001", "SEC-CONFIG-002", "SEC-SAST-001", "SEC-DEP-VULN-001"}:
        return "Python language evidence selected this approved control."
    if control_id == "SEC-CICD-001":
        return "GitHub Actions workflow evidence selected this approved workflow control."
    if control_id == "SEC-DEP-001":
        managers = ", ".join(project_profile.package_managers) or "supported dependency evidence"
        return f"Package-manager evidence ({managers}) selected this approved manifest control."
    return "The selected policy configured this repository-wide approved capability."


def _selection_evidence_ids(
    control_id: str,
    project_profile: ProjectProfile,
    evidence_ids: set[str],
) -> tuple[str, ...]:
    candidates = ["REPOSITORY-INVENTORY"]
    if control_id.startswith("SEC-NEXT-"):
        candidates.append("REPOSITORY-FRAMEWORK-NEXT-JS")
    elif control_id == "SEC-API-001":
        candidates.append("REPOSITORY-FRAMEWORK-FASTAPI")
    elif control_id in {"SEC-CONFIG-001", "SEC-CONFIG-002", "SEC-SAST-001", "SEC-DEP-VULN-001"}:
        candidates.append("REPOSITORY-LANGUAGE-PYTHON")
    elif control_id == "SEC-CICD-001":
        candidates.append("REPOSITORY-CI-GITHUB-ACTIONS")
    elif control_id == "SEC-DEP-001":
        candidates.extend(
            f"REPOSITORY-PACKAGE-MANAGER-{_identifier(manager)}"
            for manager in project_profile.package_managers
        )
    return tuple(sorted(candidate for candidate in candidates if candidate in evidence_ids))


def _coverage_expectations(
    project_profile: ProjectProfile, evidence: tuple[EvidenceSignal, ...]
) -> tuple[CoverageExpectation, ...]:
    expectations: list[CoverageExpectation] = [
        CoverageExpectation(
            domain="Secrets",
            rationale="Every bounded repository should receive repository-wide secret coverage.",
            evidence_ids=("REPOSITORY-INVENTORY",),
        )
    ]
    for language in project_profile.languages:
        expectations.append(
            CoverageExpectation(
                domain=f"Language: {language}",
                rationale="Detected language requires explicit language-specific coverage visibility.",
                evidence_ids=(f"REPOSITORY-LANGUAGE-{_identifier(language)}",),
            )
        )
    for framework in project_profile.frameworks:
        expectations.append(
            CoverageExpectation(
                domain=f"Framework: {framework}",
                rationale="Detected framework requires explicit framework-specific coverage visibility.",
                evidence_ids=(f"REPOSITORY-FRAMEWORK-{_identifier(framework)}",),
            )
        )
    if project_profile.package_managers:
        expectations.append(
            CoverageExpectation(
                domain="Dependency manifests",
                rationale="Detected package-manager evidence requires dependency coverage visibility.",
                evidence_ids=tuple(
                    f"REPOSITORY-PACKAGE-MANAGER-{_identifier(manager)}"
                    for manager in project_profile.package_managers
                ),
            )
        )

    for item in evidence:
        if item.signal_id == "REPOSITORY-CI-GITHUB-ACTIONS":
            expectations.append(
                CoverageExpectation(
                    domain="CI/CD",
                    rationale="Detected GitHub Actions workflow requires workflow coverage visibility.",
                    evidence_ids=(item.signal_id,),
                )
            )
        elif item.signal_id == "REPOSITORY-API-OPENAPI":
            expectations.append(
                CoverageExpectation(
                    domain="API security",
                    rationale="OpenAPI evidence declares an API surface requiring coverage visibility.",
                    evidence_ids=(item.signal_id,),
                )
            )
        elif item.signal_id.startswith("REPOSITORY-CONTAINER-"):
            expectations.append(
                CoverageExpectation(
                    domain="Container",
                    rationale="Container evidence requires explicit container-security coverage visibility.",
                    evidence_ids=(item.signal_id,),
                )
            )
        elif item.signal_id == "REPOSITORY-IAC-TERRAFORM":
            expectations.append(
                CoverageExpectation(
                    domain="Infrastructure as code",
                    rationale="Terraform evidence requires explicit IaC-security coverage visibility.",
                    evidence_ids=(item.signal_id,),
                )
            )
        elif item.signal_id.startswith("REQUIREMENT-"):
            expectations.append(
                CoverageExpectation(
                    domain=f"Declared requirement: {item.title.removeprefix('Declared security domain: ')}",
                    rationale="Documentation declares this domain; implementation evidence requires review.",
                    evidence_ids=(item.signal_id,),
                )
            )
    return tuple(sorted(expectations, key=lambda item: item.domain))


def _identifier(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.upper()).strip("-")
