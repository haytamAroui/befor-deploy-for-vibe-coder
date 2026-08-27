"""Deterministic construction of a traceable plan from reviewed metadata catalogs."""

from __future__ import annotations

from collections.abc import Iterable

from before_deploy.capabilities import CapabilityRegistry
from before_deploy.capabilities.schema import CapabilityDefinition
from before_deploy.domains import SecurityDomainCatalog
from before_deploy.models import (
    CapabilitySelection,
    ControlContractSelection,
    CoverageExpectation,
    EvidenceSignal,
    ProjectProfile,
    ScanManifest,
    SecurityAnalysisPlan,
)

PLAN_VERSION = "0.4.0"
PROFILE_VERSION = "0.1.0"


def build_security_analysis_plan(
    project_profile: ProjectProfile,
    evidence: Iterable[EvidenceSignal],
    runnable_controls: Iterable[object],
    *,
    manifest: ScanManifest,
    registry: CapabilityRegistry,
    security_domain_catalog: SecurityDomainCatalog,
) -> SecurityAnalysisPlan:
    """Build a plan from compatible controls and reviewed metadata only.

    The planner cannot add a capability, discover a binary, alter policy, interpret requirements as
    implementation, or execute an adapter. A runnable implementation without exactly one approved
    capability definition is a fail-closed error.
    """
    ordered_evidence = tuple(sorted(evidence, key=lambda item: item.signal_id))
    evidence_ids = {item.signal_id for item in ordered_evidence}
    definitions = tuple(
        _definition_for_control(control, registry)
        for control in sorted(runnable_controls, key=lambda item: getattr(item, "control_id"))
    )
    selections = tuple(
        _selection(definition, manifest, registry, evidence_ids) for definition in definitions
    )
    control_contract_selections = tuple(
        sorted(
            (
                _control_contract_selection(definition, security_domain_catalog)
                for definition in definitions
            ),
            key=lambda item: item.control_id,
        )
    )
    control_selections = tuple(item for item in selections if item.kind == "CONTROL")
    adapter_selections = tuple(item for item in selections if item.kind == "ADAPTER")
    exclusions = _exclusions(project_profile, definitions)
    return SecurityAnalysisPlan(
        plan_version=PLAN_VERSION,
        profile_version=PROFILE_VERSION,
        catalog_version=registry.catalog_version,
        catalog_digest=registry.catalog_digest,
        policy_name=manifest.policy_name,
        policy_digest=manifest.policy_digest,
        evidence=ordered_evidence,
        control_selections=control_selections,
        adapter_selections=adapter_selections,
        skill_selections=(),
        control_contract_selections=control_contract_selections,
        coverage_expectations=_coverage_expectations(
            project_profile, ordered_evidence, security_domain_catalog
        ),
        exclusions=exclusions,
        security_domain_catalog_version=security_domain_catalog.catalog_version,
        security_domain_catalog_digest=security_domain_catalog.catalog_digest,
    )


def _definition_for_control(control: object, registry: CapabilityRegistry) -> CapabilityDefinition:
    implementation_id = getattr(control, "control_id")
    definition = registry.definition_for_implementation(implementation_id)
    if definition is None:
        raise ValueError(f"No approved capability is registered for control: {implementation_id}")
    return definition


def _control_contract_selection(
    definition: CapabilityDefinition, security_domain_catalog: SecurityDomainCatalog
) -> ControlContractSelection:
    """Record the reviewed non-executable contract for a policy-selected implementation."""
    contract = security_domain_catalog.control_for_implementation(definition.implementation_id)
    if contract is None:
        raise ValueError(
            f"No reviewed control contract is registered for implementation: {definition.implementation_id}"
        )
    if contract.capability_id != definition.capability_id:
        raise ValueError(
            f"Control contract capability does not match implementation: {definition.implementation_id}"
        )
    return ControlContractSelection(
        control_id=contract.control_id,
        control_version=contract.version,
        capability_id=contract.capability_id,
        implementation_id=contract.implementation_id,
        security_domain_ids=contract.security_domain_ids,
        detection_scope=contract.detection_scope,
        exclusions=contract.exclusions,
    )


def _selection(
    definition: CapabilityDefinition,
    manifest: ScanManifest,
    registry: CapabilityRegistry,
    evidence_ids: set[str],
) -> CapabilitySelection:
    return CapabilitySelection(
        capability_id=definition.capability_id,
        capability_version=definition.version,
        implementation_id=definition.implementation_id,
        kind=definition.kind,
        rationale=_rationale(definition),
        policy_name=manifest.policy_name,
        policy_digest=manifest.policy_digest,
        catalog_digest=registry.catalog_digest,
        evidence_ids=_selection_evidence_ids(definition, evidence_ids),
    )


def _rationale(definition: CapabilityDefinition) -> str:
    conditions: list[str] = []
    if definition.languages:
        conditions.append("language evidence: " + ", ".join(sorted(definition.languages)))
    if definition.frameworks:
        conditions.append("framework evidence: " + ", ".join(sorted(definition.frameworks)))
    if definition.requires_github_workflow:
        conditions.append("GitHub Actions workflow evidence")
    if not conditions:
        conditions.append("repository-wide approved applicability")
    return "Registry-selected capability based on " + "; ".join(conditions) + "."


def _selection_evidence_ids(
    definition: CapabilityDefinition, evidence_ids: set[str]
) -> tuple[str, ...]:
    candidates = ["REPOSITORY-INVENTORY"]
    candidates.extend(
        f"REPOSITORY-LANGUAGE-{_identifier(language)}" for language in definition.languages
    )
    candidates.extend(
        f"REPOSITORY-FRAMEWORK-{_identifier(framework)}" for framework in definition.frameworks
    )
    if definition.requires_github_workflow:
        candidates.append("REPOSITORY-CI-GITHUB-ACTIONS")
    candidates.extend(definition.required_project_signals)
    return tuple(sorted(candidate for candidate in candidates if candidate in evidence_ids))


def _coverage_expectations(
    project_profile: ProjectProfile,
    evidence: tuple[EvidenceSignal, ...],
    security_domain_catalog: SecurityDomainCatalog,
) -> tuple[CoverageExpectation, ...]:
    evidence_ids = frozenset(item.signal_id for item in evidence)
    expectations: list[CoverageExpectation] = [
        CoverageExpectation(
            domain=definition.title,
            domain_id=definition.domain_id,
            rationale="Versioned security-domain catalog applicability is satisfied by deterministic profile or evidence facts.",
            evidence_ids=_domain_evidence_ids(definition, project_profile, evidence_ids),
        )
        for definition in security_domain_catalog.domains_for_profile(project_profile, evidence_ids)
    ]

    catalog_titles = {item.domain for item in expectations}
    for language in project_profile.languages:
        _add_expectation(
            expectations,
            catalog_titles,
            CoverageExpectation(
                domain=f"Language: {language}",
                rationale="Detected language requires explicit language-specific coverage visibility.",
                evidence_ids=(f"REPOSITORY-LANGUAGE-{_identifier(language)}",),
            ),
        )
    for framework in project_profile.frameworks:
        _add_expectation(
            expectations,
            catalog_titles,
            CoverageExpectation(
                domain=f"Framework: {framework}",
                rationale="Detected framework requires explicit framework-specific coverage visibility.",
                evidence_ids=(f"REPOSITORY-FRAMEWORK-{_identifier(framework)}",),
            ),
        )
    if project_profile.package_managers:
        _add_expectation(
            expectations,
            catalog_titles,
            CoverageExpectation(
                domain="Dependency manifests",
                rationale="Detected package-manager evidence requires dependency coverage visibility.",
                evidence_ids=tuple(
                    f"REPOSITORY-PACKAGE-MANAGER-{_identifier(manager)}"
                    for manager in project_profile.package_managers
                ),
            ),
        )

    for item in evidence:
        if item.signal_id == "REPOSITORY-CI-GITHUB-ACTIONS":
            _add_expectation(
                expectations,
                catalog_titles,
                CoverageExpectation(
                    domain="CI/CD",
                    rationale="Detected GitHub Actions workflow requires workflow coverage visibility.",
                    evidence_ids=(item.signal_id,),
                ),
            )
        elif item.signal_id == "REPOSITORY-API-OPENAPI":
            _add_expectation(
                expectations,
                catalog_titles,
                CoverageExpectation(
                    domain="API security",
                    rationale="OpenAPI evidence declares an API surface requiring coverage visibility.",
                    evidence_ids=(item.signal_id,),
                ),
            )
        elif item.signal_id.startswith("REPOSITORY-CONTAINER-"):
            _add_expectation(
                expectations,
                catalog_titles,
                CoverageExpectation(
                    domain="Container",
                    rationale="Container evidence requires explicit container-security coverage visibility.",
                    evidence_ids=(item.signal_id,),
                ),
            )
        elif item.signal_id == "REPOSITORY-IAC-TERRAFORM":
            _add_expectation(
                expectations,
                catalog_titles,
                CoverageExpectation(
                    domain="Infrastructure as code",
                    rationale="Terraform evidence requires explicit IaC-security coverage visibility.",
                    evidence_ids=(item.signal_id,),
                ),
            )
        elif item.signal_id.startswith("REQUIREMENT-"):
            _add_expectation(
                expectations,
                catalog_titles,
                CoverageExpectation(
                    domain=f"Declared requirement: {item.title.removeprefix('Declared security domain: ')}",
                    rationale="Documentation declares this domain; implementation evidence requires review.",
                    evidence_ids=(item.signal_id,),
                ),
            )
    return tuple(sorted(expectations, key=lambda item: (item.domain, item.domain_id or "")))


def _domain_evidence_ids(definition, project_profile: ProjectProfile, evidence_ids: frozenset[str]) -> tuple[str, ...]:
    candidates: list[str] = []
    if definition.applies_when.repository_wide:
        candidates.append("REPOSITORY-INVENTORY")
    candidates.extend(
        f"REPOSITORY-LANGUAGE-{_identifier(language)}"
        for language in definition.applies_when.languages.intersection(project_profile.languages)
    )
    candidates.extend(
        f"REPOSITORY-FRAMEWORK-{_identifier(framework)}"
        for framework in definition.applies_when.frameworks.intersection(project_profile.frameworks)
    )
    candidates.extend(
        f"REPOSITORY-PACKAGE-MANAGER-{_identifier(manager)}"
        for manager in definition.applies_when.package_managers.intersection(project_profile.package_managers)
    )
    candidates.extend(definition.applies_when.evidence_signal_ids.intersection(evidence_ids))
    return tuple(sorted(candidate for candidate in candidates if candidate in evidence_ids))


def _add_expectation(
    expectations: list[CoverageExpectation], catalog_titles: set[str], expectation: CoverageExpectation
) -> None:
    if expectation.domain not in catalog_titles:
        expectations.append(expectation)
        catalog_titles.add(expectation.domain)


def _exclusions(
    project_profile: ProjectProfile, definitions: tuple[CapabilityDefinition, ...]
) -> tuple[str, ...]:
    exclusions = set(project_profile.coverage_gaps)
    for definition in definitions:
        exclusions.update(
            f"{definition.capability_id}: {exclusion}" for exclusion in definition.exclusions
        )
    exclusions.add("Security domains are informational metadata and cannot modify a policy decision.")
    exclusions.add("Declarative skill packs are not loaded in this registry milestone.")
    exclusions.add("External adapters are selected only when explicitly configured by policy.")
    return tuple(sorted(exclusions))


def _identifier(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.upper()).strip("-")
