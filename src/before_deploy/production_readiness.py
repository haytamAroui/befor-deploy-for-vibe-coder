"""Deterministic engineering-readiness evaluation for Before Deploy itself.

This module does not participate in application release authorization. It evaluates
whether the Before Deploy project has accumulated the evidence required by
``docs/PRODUCTION_READINESS_CRITERIA.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from json import dumps

PRODUCTION_READINESS_SCHEMA = "before-deploy-production-readiness-v1"
PRODUCTION_READINESS_AUTHORITY = "ENGINEERING_READINESS_DIAGNOSTIC"
PRODUCTION_READINESS_GATE_EFFECT = "NONE"


@dataclass(frozen=True)
class ProductionReadinessThresholds:
    min_repetitions: int = 5
    min_exploration_recall_lift: float = 0.20
    min_exploration_attributable_tp: int = 5
    min_prediction_stability: float = 0.70
    max_mean_exploratory_latency_ms: float = 300_000.0
    max_mean_exploratory_cost_microusd: float = 250_000.0
    min_real_world_repositories: int = 3
    min_real_world_known_defects: int = 6
    min_real_world_recall: float = 0.60


@dataclass(frozen=True)
class ProductionReadinessEvidence:
    # Repeated controlled benchmark.
    pilot_decision: str
    static_run_count: int
    exploratory_run_count: int
    exploration_required_recall_lift: float
    exploration_attributable_tp: int
    exploration_attributable_fp: int
    false_positive_trap_rate_delta: float
    static_sufficient_recall_delta: float
    exploratory_supported_claim_rate: float
    exploratory_citation_correct_rate: float
    # Gating measurement: mean pairwise Jaccard of normalized advisory claim-key sets.
    exploratory_prediction_claim_stability: float
    # Reported diagnostic only: mean pairwise Jaccard of exact advisory fingerprint sets. It has a
    # floor of 0 for free-text advisory output and cannot satisfy or waive the stability threshold.
    exploratory_exact_prediction_stability: float
    exploratory_mean_latency_ms: float
    exploratory_mean_cost_microusd: float

    # Operational hardening evidence.
    fault_scenarios_required: int
    fault_scenarios_passed: int
    bounded_retry_passed: bool
    malformed_output_safe: bool
    missing_credentials_safe: bool
    timeout_safe: bool
    cost_budget_enforced: bool
    advisory_authority_isolated: bool

    # Independent real-world benchmark.
    real_world_repository_count: int
    real_world_known_defects: int
    real_world_detected_defects: int
    real_world_exploration_attributable_tp: int
    real_world_exploration_attributable_fp: int
    real_world_static_false_positive_rate: float
    real_world_exploratory_false_positive_rate: float
    real_world_blinded: bool
    real_world_independent: bool

    # Full assurance and release engineering.
    assurance_workflow_passed: bool
    deterministic_ci_passed: bool
    clean_install_smoke_passed: bool
    retained_evidence_digest_count: int


@dataclass(frozen=True)
class ProductionReadinessAssessment:
    decision: str
    reason_codes: tuple[str, ...]
    real_world_recall: float
    exploratory_prediction_claim_stability: float
    exploratory_exact_prediction_stability: float
    schema_version: str = PRODUCTION_READINESS_SCHEMA
    authority: str = PRODUCTION_READINESS_AUTHORITY
    gate_effect: str = PRODUCTION_READINESS_GATE_EFFECT


def evaluate_production_readiness(
    evidence: ProductionReadinessEvidence,
    *,
    thresholds: ProductionReadinessThresholds = ProductionReadinessThresholds(),
) -> ProductionReadinessAssessment:
    """Return READY only when every frozen readiness criterion is satisfied."""
    _validate_evidence(evidence)
    _validate_thresholds(thresholds)
    reasons: list[str] = []

    if evidence.pilot_decision != "GO":
        reasons.append("REPEATED_PILOT_NOT_GO")
    if min(evidence.static_run_count, evidence.exploratory_run_count) < thresholds.min_repetitions:
        reasons.append("INSUFFICIENT_REPETITIONS")
    if evidence.exploration_required_recall_lift < thresholds.min_exploration_recall_lift:
        reasons.append("INSUFFICIENT_EXPLORATION_RECALL_LIFT")
    if evidence.exploration_attributable_tp < thresholds.min_exploration_attributable_tp:
        reasons.append("INSUFFICIENT_EXPLORATION_ATTRIBUTABLE_TP")
    if evidence.exploration_attributable_tp <= evidence.exploration_attributable_fp:
        reasons.append("EXPLORATION_TP_NOT_GREATER_THAN_FP")
    if evidence.false_positive_trap_rate_delta > 0:
        reasons.append("FALSE_POSITIVE_TRAP_REGRESSED")
    if evidence.static_sufficient_recall_delta < 0:
        reasons.append("STATIC_SUFFICIENT_RECALL_REGRESSED")
    if evidence.exploratory_supported_claim_rate != 1.0:
        reasons.append("EXPLORATORY_SUPPORTED_CLAIM_RATE_NOT_PERFECT")
    if evidence.exploratory_citation_correct_rate != 1.0:
        reasons.append("EXPLORATORY_CITATION_RATE_NOT_PERFECT")
    if evidence.exploratory_prediction_claim_stability < thresholds.min_prediction_stability:
        reasons.append("INSUFFICIENT_PREDICTION_STABILITY")
    if evidence.exploratory_mean_latency_ms > thresholds.max_mean_exploratory_latency_ms:
        reasons.append("EXPLORATORY_LATENCY_BUDGET_EXCEEDED")
    if evidence.exploratory_mean_cost_microusd > thresholds.max_mean_exploratory_cost_microusd:
        reasons.append("EXPLORATORY_COST_BUDGET_EXCEEDED")

    if evidence.fault_scenarios_required <= 0 or evidence.fault_scenarios_passed != evidence.fault_scenarios_required:
        reasons.append("OPERATIONAL_FAULT_COVERAGE_INCOMPLETE")
    operational_flags = (
        evidence.bounded_retry_passed,
        evidence.malformed_output_safe,
        evidence.missing_credentials_safe,
        evidence.timeout_safe,
        evidence.cost_budget_enforced,
        evidence.advisory_authority_isolated,
    )
    if not all(operational_flags):
        reasons.append("OPERATIONAL_SAFETY_REQUIREMENT_FAILED")

    real_world_recall = (
        evidence.real_world_detected_defects / evidence.real_world_known_defects
        if evidence.real_world_known_defects
        else 0.0
    )
    if evidence.real_world_repository_count < thresholds.min_real_world_repositories:
        reasons.append("INSUFFICIENT_REAL_WORLD_REPOSITORIES")
    if evidence.real_world_known_defects < thresholds.min_real_world_known_defects:
        reasons.append("INSUFFICIENT_REAL_WORLD_DEFECTS")
    if real_world_recall < thresholds.min_real_world_recall:
        reasons.append("INSUFFICIENT_REAL_WORLD_RECALL")
    if evidence.real_world_exploration_attributable_tp <= evidence.real_world_exploration_attributable_fp:
        reasons.append("REAL_WORLD_EXPLORATION_TP_NOT_GREATER_THAN_FP")
    if evidence.real_world_exploratory_false_positive_rate > evidence.real_world_static_false_positive_rate:
        reasons.append("REAL_WORLD_FALSE_POSITIVE_RATE_REGRESSED")
    if not evidence.real_world_blinded:
        reasons.append("REAL_WORLD_BENCHMARK_NOT_BLINDED")
    if not evidence.real_world_independent:
        reasons.append("REAL_WORLD_BENCHMARK_NOT_INDEPENDENT")

    if not evidence.assurance_workflow_passed:
        reasons.append("FULL_ASSURANCE_WORKFLOW_NOT_PROVEN")
    if not evidence.deterministic_ci_passed:
        reasons.append("DETERMINISTIC_CI_NOT_GREEN")
    if not evidence.clean_install_smoke_passed:
        reasons.append("CLEAN_INSTALL_SMOKE_NOT_GREEN")
    if evidence.retained_evidence_digest_count <= 0:
        reasons.append("READINESS_EVIDENCE_NOT_RETAINED")

    return ProductionReadinessAssessment(
        decision="READY" if not reasons else "NOT_READY",
        reason_codes=tuple(reasons),
        real_world_recall=real_world_recall,
        exploratory_prediction_claim_stability=evidence.exploratory_prediction_claim_stability,
        exploratory_exact_prediction_stability=evidence.exploratory_exact_prediction_stability,
    )


def render_production_readiness_json(result: ProductionReadinessAssessment) -> str:
    payload = {
        "schema_version": result.schema_version,
        "production_readiness": {
            "decision": result.decision,
            "reason_codes": list(result.reason_codes),
            "real_world_recall": result.real_world_recall,
            "exploratory_prediction_claim_stability": (
                result.exploratory_prediction_claim_stability
            ),
            "exploratory_exact_prediction_stability": (
                result.exploratory_exact_prediction_stability
            ),
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_production_readiness_markdown(result: ProductionReadinessAssessment) -> str:
    lines = [
        "# Before Deploy Production Readiness",
        "",
        f"- Decision: **{result.decision}**",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        f"- Real-world recall: **{result.real_world_recall:.4f}**",
        (
            "- Exploratory claim stability: "
            f"**{result.exploratory_prediction_claim_stability:.4f}** "
            "(exact fingerprint stability "
            f"{result.exploratory_exact_prediction_stability:.4f})"
        ),
        "",
        "## Reasons",
        "",
    ]
    if result.reason_codes:
        lines.extend(f"- `{reason}`" for reason in result.reason_codes)
    else:
        lines.append("- All frozen production-readiness criteria passed.")
    lines.extend(
        [
            "",
            "> This is an engineering maturity decision for Before Deploy itself. It does not grant AI findings release authority.",
        ]
    )
    return "\n".join(lines) + "\n"


def _validate_evidence(value: ProductionReadinessEvidence) -> None:
    integer_fields = (
        "static_run_count",
        "exploratory_run_count",
        "exploration_attributable_tp",
        "exploration_attributable_fp",
        "fault_scenarios_required",
        "fault_scenarios_passed",
        "real_world_repository_count",
        "real_world_known_defects",
        "real_world_detected_defects",
        "real_world_exploration_attributable_tp",
        "real_world_exploration_attributable_fp",
        "retained_evidence_digest_count",
    )
    for name in integer_fields:
        item = getattr(value, name)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ValueError(f"Production readiness {name} must be a non-negative integer")
    if value.fault_scenarios_passed > value.fault_scenarios_required:
        raise ValueError("Passed fault scenarios cannot exceed required fault scenarios")
    if value.real_world_detected_defects > value.real_world_known_defects:
        raise ValueError("Detected real-world defects cannot exceed known defects")
    rate_fields = (
        "exploratory_supported_claim_rate",
        "exploratory_citation_correct_rate",
        "exploratory_prediction_claim_stability",
        "exploratory_exact_prediction_stability",
        "real_world_static_false_positive_rate",
        "real_world_exploratory_false_positive_rate",
    )
    for name in rate_fields:
        item = getattr(value, name)
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not 0.0 <= float(item) <= 1.0:
            raise ValueError(f"Production readiness {name} must be between zero and one")
    for name in (
        "exploratory_mean_latency_ms",
        "exploratory_mean_cost_microusd",
    ):
        item = getattr(value, name)
        if isinstance(item, bool) or not isinstance(item, (int, float)) or float(item) < 0:
            raise ValueError(f"Production readiness {name} must be non-negative")


def _validate_thresholds(value: ProductionReadinessThresholds) -> None:
    if value.min_repetitions <= 0 or value.min_exploration_attributable_tp <= 0:
        raise ValueError("Production readiness count thresholds must be positive")
    if value.min_real_world_repositories <= 0 or value.min_real_world_known_defects <= 0:
        raise ValueError("Production readiness real-world thresholds must be positive")
    for item in (
        value.min_exploration_recall_lift,
        value.min_prediction_stability,
        value.min_real_world_recall,
    ):
        if not 0.0 <= item <= 1.0:
            raise ValueError("Production readiness rate thresholds must be between zero and one")
    if value.max_mean_exploratory_latency_ms <= 0 or value.max_mean_exploratory_cost_microusd <= 0:
        raise ValueError("Production readiness budget thresholds must be positive")
