"""Deterministic coverage auditing over registered capabilities and observed executions."""

from __future__ import annotations

from collections.abc import Iterable

from before_deploy.capabilities import CapabilityRegistry
from before_deploy.models import (
    CoverageAssessment,
    CoverageAudit,
    CoverageStatus,
    ExecutionStatus,
    ProjectProfile,
    SecurityAnalysisPlan,
)

AUDIT_VERSION = "0.2.0"


def audit_security_coverage(
    plan: SecurityAnalysisPlan,
    project_profile: ProjectProfile,
    executions: Iterable[object],
    *,
    registry: CapabilityRegistry,
) -> CoverageAudit:
    """Produce diagnostic coverage from registered capability definitions and execution state.

    Coverage never changes policy evaluation. ``NOT_SELECTED`` means a compatible registered capability
    existed but was absent from the active policy selection; ``ERROR`` preserves a selected execution
    failure instead of collapsing it into a clean or merely partial outcome.
    """
    statuses = {getattr(item, "control_id"): getattr(item, "status") for item in executions}
    selected = {
        selection.capability_id: selection
        for selection in (*plan.control_selections, *plan.adapter_selections)
    }
    assessments = tuple(
        _assess(expectation, selected, statuses, project_profile, registry)
        for expectation in plan.coverage_expectations
    )
    return CoverageAudit(
        audit_version=AUDIT_VERSION,
        assessments=tuple(sorted(assessments, key=lambda item: item.domain)),
    )


def _assess(expectation, selected, statuses, project_profile, registry) -> CoverageAssessment:
    if expectation.domain.startswith("Declared requirement:"):
        return CoverageAssessment(
            domain=expectation.domain,
            status=CoverageStatus.DECLARED_REVIEW_REQUIRED,
            rationale=(
                "A bounded documentation signal declared this domain; no implementation conclusion or "
                "release decision is derived from the declaration."
            ),
            evidence_ids=expectation.evidence_ids,
        )

    candidates = registry.definitions_for_domain(expectation.domain)
    if not candidates:
        return CoverageAssessment(
            domain=expectation.domain,
            status=CoverageStatus.UNAVAILABLE,
            rationale="No approved capability in the versioned registry currently covers this domain.",
            evidence_ids=expectation.evidence_ids,
        )

    selected_definitions = tuple(
        definition for definition in candidates if definition.capability_id in selected
    )
    if not selected_definitions:
        if any(definition.applies_to(project_profile) for definition in candidates):
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
        )

    execution_statuses = [
        statuses.get(definition.implementation_id) for definition in selected_definitions
    ]
    if any(status == ExecutionStatus.ERROR for status in execution_statuses):
        status = CoverageStatus.ERROR
        rationale = "At least one selected mapped capability returned an execution error."
    elif all(status == ExecutionStatus.COMPLETED for status in execution_statuses):
        status = CoverageStatus.COVERED
        rationale = "All selected, mapped capabilities completed; coverage remains scope-limited."
    else:
        status = CoverageStatus.PARTIAL
        rationale = "One or more selected mapped capabilities did not complete."
    return CoverageAssessment(
        domain=expectation.domain,
        status=status,
        rationale=rationale,
        capability_ids=tuple(definition.capability_id for definition in selected_definitions),
        evidence_ids=expectation.evidence_ids,
    )
