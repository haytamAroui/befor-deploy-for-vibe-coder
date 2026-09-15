from before_deploy.production_readiness import (
    PRODUCTION_READINESS_GATE_EFFECT,
    ProductionReadinessEvidence,
    evaluate_production_readiness,
    render_production_readiness_json,
)


def _ready_evidence(**changes):
    values = {
        "pilot_decision": "GO",
        "static_run_count": 5,
        "exploratory_run_count": 5,
        "exploration_required_recall_lift": 0.25,
        "exploration_attributable_tp": 6,
        "exploration_attributable_fp": 1,
        "false_positive_trap_rate_delta": 0.0,
        "static_sufficient_recall_delta": 0.0,
        "exploratory_supported_claim_rate": 1.0,
        "exploratory_citation_correct_rate": 1.0,
        "exploratory_prediction_stability": 0.80,
        "exploratory_mean_latency_ms": 120_000.0,
        "exploratory_mean_cost_microusd": 50_000.0,
        "fault_scenarios_required": 7,
        "fault_scenarios_passed": 7,
        "bounded_retry_passed": True,
        "malformed_output_safe": True,
        "missing_credentials_safe": True,
        "timeout_safe": True,
        "cost_budget_enforced": True,
        "advisory_authority_isolated": True,
        "real_world_repository_count": 3,
        "real_world_known_defects": 10,
        "real_world_detected_defects": 7,
        "real_world_exploration_attributable_tp": 5,
        "real_world_exploration_attributable_fp": 1,
        "real_world_static_false_positive_rate": 0.10,
        "real_world_exploratory_false_positive_rate": 0.10,
        "real_world_blinded": True,
        "real_world_independent": True,
        "assurance_workflow_passed": True,
        "deterministic_ci_passed": True,
        "clean_install_smoke_passed": True,
        "retained_evidence_digest_count": 4,
    }
    values.update(changes)
    return ProductionReadinessEvidence(**values)


def test_ready_requires_all_frozen_criteria():
    result = evaluate_production_readiness(_ready_evidence())
    assert result.decision == "READY"
    assert result.reason_codes == ()
    assert result.real_world_recall == 0.7
    assert result.gate_effect == PRODUCTION_READINESS_GATE_EFFECT == "NONE"
    rendered = render_production_readiness_json(result)
    assert '"decision": "READY"' in rendered
    assert '"gate_effect": "NONE"' in rendered


def test_controlled_benchmark_thresholds_are_not_relaxed():
    result = evaluate_production_readiness(
        _ready_evidence(
            exploratory_run_count=4,
            exploration_required_recall_lift=0.19,
            exploration_attributable_tp=4,
            exploration_attributable_fp=4,
            false_positive_trap_rate_delta=0.01,
            static_sufficient_recall_delta=-0.01,
            exploratory_supported_claim_rate=0.99,
            exploratory_citation_correct_rate=0.99,
            exploratory_prediction_stability=0.69,
            exploratory_mean_latency_ms=300_001,
            exploratory_mean_cost_microusd=250_001,
        )
    )
    assert result.decision == "NOT_READY"
    assert set(result.reason_codes) >= {
        "INSUFFICIENT_REPETITIONS",
        "INSUFFICIENT_EXPLORATION_RECALL_LIFT",
        "INSUFFICIENT_EXPLORATION_ATTRIBUTABLE_TP",
        "EXPLORATION_TP_NOT_GREATER_THAN_FP",
        "FALSE_POSITIVE_TRAP_REGRESSED",
        "STATIC_SUFFICIENT_RECALL_REGRESSED",
        "EXPLORATORY_SUPPORTED_CLAIM_RATE_NOT_PERFECT",
        "EXPLORATORY_CITATION_RATE_NOT_PERFECT",
        "INSUFFICIENT_PREDICTION_STABILITY",
        "EXPLORATORY_LATENCY_BUDGET_EXCEEDED",
        "EXPLORATORY_COST_BUDGET_EXCEEDED",
    }


def test_real_world_and_operational_evidence_are_mandatory():
    result = evaluate_production_readiness(
        _ready_evidence(
            fault_scenarios_passed=6,
            bounded_retry_passed=False,
            real_world_repository_count=2,
            real_world_known_defects=5,
            real_world_detected_defects=2,
            real_world_exploration_attributable_tp=1,
            real_world_exploration_attributable_fp=1,
            real_world_static_false_positive_rate=0.05,
            real_world_exploratory_false_positive_rate=0.10,
            real_world_blinded=False,
            real_world_independent=False,
            assurance_workflow_passed=False,
            deterministic_ci_passed=False,
            clean_install_smoke_passed=False,
            retained_evidence_digest_count=0,
        )
    )
    assert result.decision == "NOT_READY"
    assert set(result.reason_codes) >= {
        "OPERATIONAL_FAULT_COVERAGE_INCOMPLETE",
        "OPERATIONAL_SAFETY_REQUIREMENT_FAILED",
        "INSUFFICIENT_REAL_WORLD_REPOSITORIES",
        "INSUFFICIENT_REAL_WORLD_DEFECTS",
        "INSUFFICIENT_REAL_WORLD_RECALL",
        "REAL_WORLD_EXPLORATION_TP_NOT_GREATER_THAN_FP",
        "REAL_WORLD_FALSE_POSITIVE_RATE_REGRESSED",
        "REAL_WORLD_BENCHMARK_NOT_BLINDED",
        "REAL_WORLD_BENCHMARK_NOT_INDEPENDENT",
        "FULL_ASSURANCE_WORKFLOW_NOT_PROVEN",
        "DETERMINISTIC_CI_NOT_GREEN",
        "CLEAN_INSTALL_SMOKE_NOT_GREEN",
        "READINESS_EVIDENCE_NOT_RETAINED",
    }
