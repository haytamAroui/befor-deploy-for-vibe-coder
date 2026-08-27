"""Deterministic coverage auditing over registered capabilities and a non-executable domain catalog."""

from __future__ import annotations

from collections.abc import Iterable

from before_deploy.capabilities import CapabilityRegistry
from before_deploy.domains import SecurityDomainCatalog
from before_deploy.models import (
    CoverageAssessment,
    CoverageAudit,
    CoverageStatus,
    ExecutionStatus,
    ProjectProfile,
    SecurityAnalysisPlan,
)

AUDIT_VERSION = "0.4.0"


def audit_security_coverage(
    plan: SecurityAnalysisPlan,
    project_profile: ProjectProfile,
    executions: Iterable[object],
    *,
    registry: CapabilityRegistry,
    security_domain_catalog: SecurityDomainCatalog,
) -> CoverageAudit:
    """Produce diagnostic coverage from reviewed catalogs and observed execution state.

    Coverage never changes policy evaluation. ``NOT_SELECTED`` means no compatible registered capability
    was selected. ``PARTIAL`` also records a selected and completed subset when another compatible mapped
    capability is absent from the active policy selection. ``ERROR`` preserves a selected execution
    failure instead of collapsing it into a clean or merely partial outcome.
    """
    statuses = {getattr(item, "control_id"): getattr(item, "status") for item in executions}
    selected = {
        selection.capability_id: selection
        for selection in (*plan.control_selections, *plan.adapter_selections)
    }
    assessments = tuple(
        _assess(expectation, selected, statuses, project_profile, registry, security_domain_catalog)
        for expectation in plan.coverage_expectations
    )
    return CoverageAudit(
        audit_version=AUDIT_VERSION,
        assessments=tuple(sorted(assessments, key=lambda item: (item.domain, item.domain_id or ""))),
        security_domain_catalog_version=security_domain_catalog.catalog_version,
        security_domain_catalog_digest=security_domain_catalog.catalog_digest,
    )


def _assess(
    expectation,
    selected,
    statuses,
    project_profile,
    registry,
    security_domain_catalog,
) -> CoverageAssessment:
    if expectation.domain.startswith("Declared requirement:"):
        return CoverageAssessment(
            domain=expectation.domain,
            status=CoverageStatus.DECLARED_REVIEW_REQUIRED,
            rationale=(
                "A bounded documentation signal declared this domain; no implementation conclusion or "
                "release decision is derived from the declaration."
            ),
            evidence_ids=expectation.evidence_ids,
            domain_id=expectation.domain_id,
        )

    candidates = _candidate_definitions(expectation, registry, security_domain_catalog)
    if not candidates:
        return CoverageAssessment(
            domain=expectation.domain,
            status=CoverageStatus.UNAVAILABLE,
            rationale="No approved capability in the versioned registry currently covers this domain.",
            evidence_ids=expectation.evidence_ids,
            domain_id=expectation.domain_id,
        )

    compatible_candidates = tuple(
        definition for definition in candidates if definition.applies_to(project_profile)
    )
    selected_definitions = tuple(
        definition for definition in compatible_candidates if definition.capability_id in selected
    )
    if not selected_definitions:
        if compatible_candidates:
            status = CoverageStatus.NOT_SELECTED
            rationale = "A compatible approved capability exists but the active policy did not select it."
        else:
            status = CoverageStatus.NOT_APPLICABLE
            rationale = "All mapped approved capabilities are explicitly incompatible with this repository."
        return CoverageAssessment(
            domain=expectation.domain,
            status=status,
            rationale=rationale,
            capability_ids=tuple(definition.capability_id for definition in candidates),
            evidence_ids=expectation.evidence_ids,
            domain_id=expectation.domain_id,
        )

    execution_statuses = [
        statuses.get(definition.implementation_id) for definition in selected_definitions
    ]
    if any(status == ExecutionStatus.ERROR for status in execution_statuses):
        status = CoverageStatus.ERROR
        rationale = "At least one selected mapped capability returned an execution error."
    elif all(status == ExecutionStatus.COMPLETED for status in execution_statuses):
        if len(selected_definitions) == len(compatible_candidates):
            status = CoverageStatus.COVERED
            rationale = "All compatible mapped capabilities completed; coverage remains scope-limited."
        else:
            status = CoverageStatus.PARTIAL
            rationale = (
                "At least one compatible mapped capability was absent from the active policy selection."
            )
    else:
        status = CoverageStatus.PARTIAL
        rationale = "One or more selected mapped capabilities did not complete."
    return CoverageAssessment(
        domain=expectation.domain,
        status=status,
        rationale=rationale,
        capability_ids=tuple(definition.capability_id for definition in selected_definitions),
        evidence_ids=expectation.evidence_ids,
        domain_id=expectation.domain_id,
    )


def _candidate_definitions(expectation, registry, security_domain_catalog):
    if expectation.domain_id is None:
        return registry.definitions_for_domain(expectation.domain)
    controls = security_domain_catalog.controls_for_domain(expectation.domain_id)
    return tuple(
        registry.capabilities[control.capability_id]
        for control in controls
        if control.capability_id in registry.capabilities
    )
