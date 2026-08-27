"""Deterministic coverage auditing over planned capabilities and observed executions."""

from __future__ import annotations

from collections.abc import Iterable

from before_deploy.models import (
    CoverageAssessment,
    CoverageAudit,
    CoverageStatus,
    ExecutionStatus,
    SecurityAnalysisPlan,
)
from before_deploy.planning.catalog import DOMAIN_CAPABILITIES

AUDIT_VERSION = "0.1.0"


def audit_security_coverage(
    plan: SecurityAnalysisPlan, executions: Iterable[object]
) -> CoverageAudit:
    """Return coverage statuses from approved plan selections and control execution records.

    Coverage is diagnostic only. A covered status means an explicitly mapped, selected capability
    completed; it does not establish exhaustive security analysis or change policy evaluation.
    """
    statuses = {getattr(item, "control_id"): getattr(item, "status") for item in executions}
    selected = {
        selection.capability_id
        for selection in (*plan.control_selections, *plan.adapter_selections)
    }
    assessments = tuple(
        _assess(expectation, selected, statuses) for expectation in plan.coverage_expectations
    )
    return CoverageAudit(
        audit_version=AUDIT_VERSION,
        assessments=tuple(sorted(assessments, key=lambda item: item.domain)),
    )


def _assess(expectation, selected: set[str], statuses: dict[str, ExecutionStatus]) -> CoverageAssessment:
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

    capability_ids = tuple(sorted(DOMAIN_CAPABILITIES.get(expectation.domain, frozenset())))
    selected_ids = tuple(capability_id for capability_id in capability_ids if capability_id in selected)
    if not capability_ids:
        return CoverageAssessment(
            domain=expectation.domain,
            status=CoverageStatus.UNAVAILABLE,
            rationale="No approved capability in the versioned catalog currently covers this domain.",
            evidence_ids=expectation.evidence_ids,
        )
    if not selected_ids:
        non_applicable = all(
            statuses.get(capability_id) == ExecutionStatus.NOT_APPLICABLE
            for capability_id in capability_ids
            if capability_id in statuses
        )
        return CoverageAssessment(
            domain=expectation.domain,
            status=CoverageStatus.NOT_APPLICABLE if non_applicable else CoverageStatus.UNAVAILABLE,
            rationale=(
                "Approved capabilities were explicitly not applicable to this repository."
                if non_applicable
                else "Approved capabilities exist but were not selected by the configured policy."
            ),
            capability_ids=capability_ids,
            evidence_ids=expectation.evidence_ids,
        )

    completed_ids = tuple(
        capability_id
        for capability_id in selected_ids
        if statuses.get(capability_id) == ExecutionStatus.COMPLETED
    )
    if len(completed_ids) == len(selected_ids):
        status = CoverageStatus.COVERED
        rationale = "All selected, mapped capabilities completed; coverage remains scope-limited."
    else:
        status = CoverageStatus.PARTIAL
        rationale = "One or more selected, mapped capabilities did not complete."
    return CoverageAssessment(
        domain=expectation.domain,
        status=status,
        rationale=rationale,
        capability_ids=selected_ids,
        evidence_ids=expectation.evidence_ids,
    )
