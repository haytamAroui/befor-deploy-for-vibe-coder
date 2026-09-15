import json
from dataclasses import replace

import pytest

from before_deploy.assurance_comparison import (
    FULL_COMPARISON_AUTHORITY,
    VariantAssuranceSupplement,
    build_full_assurance_comparison,
    render_full_assurance_comparison_json,
    render_full_assurance_comparison_markdown,
)
from before_deploy.comparative_benchmark import ComparativeBenchmarkResult, VariantAggregate
from before_deploy.verification_obligations import (
    KIND_STATIC_CHECK,
    KIND_TEST,
    RESULT_FAIL,
    RESULT_PASS,
    VERIFICATION_AUTHORITY,
    VerificationObligationDraft,
    freeze_verification_obligation,
    propose_verification_obligation,
    record_verification_result,
    render_frozen_obligation_json,
    render_verification_result_json,
)


def _proposal():
    return propose_verification_obligation(
        VerificationObligationDraft(
            target_fingerprint="a" * 64,
            title="Verify the caller rejects an unsafe target",
            rationale="The finding depends on caller-side validation behavior.",
            kind=KIND_TEST,
            success_criterion="The verification passes only when unsafe targets are rejected.",
            evidence_ids=("caller:two",),
        ),
        available_evidence_ids=("initial:one", "caller:two"),
    )


def _frozen():
    return freeze_verification_obligation(
        _proposal(),
        frozen_by="reviewer@example",
        approval_reference="review/123#verification-1",
    )


def test_ai_proposal_is_stable_advisory_and_has_no_execution_command():
    first = _proposal()
    second = _proposal()

    assert first == second
    assert first.proposal_id.startswith("VOP-")
    assert first.authority == "AI_VERIFICATION_PROPOSAL_ADVISORY"
    assert first.gate_effect == "NONE"
    assert not hasattr(first, "command")
    assert not hasattr(first, "argv")


def test_proposal_rejects_evidence_outside_supplied_trace():
    with pytest.raises(ValueError, match="outside the supplied trace"):
        propose_verification_obligation(
            VerificationObligationDraft(
                target_fingerprint="a" * 64,
                title="Verify behavior",
                rationale="Need more evidence.",
                kind=KIND_STATIC_CHECK,
                success_criterion="The check reports no unsafe path.",
                evidence_ids=("hidden:three",),
            ),
            available_evidence_ids=("initial:one",),
        )


def test_human_freeze_is_explicit_immutable_boundary():
    frozen = _frozen()

    assert frozen.obligation_id.startswith("VOB-")
    assert frozen.proposal_id == _proposal().proposal_id
    assert frozen.authority == VERIFICATION_AUTHORITY
    assert frozen.gate_effect == "NONE"
    assert frozen.frozen_by == "reviewer@example"
    assert frozen.approval_reference == "review/123#verification-1"

    with pytest.raises(ValueError, match="frozen_by"):
        freeze_verification_obligation(
            _proposal(), frozen_by="", approval_reference="review/123"
        )


def test_result_requires_frozen_obligation_and_hashed_external_evidence():
    frozen = _frozen()
    result = record_verification_result(
        frozen,
        status=RESULT_PASS,
        summary="The bounded test suite rejected each unsafe target fixture.",
        executor="pytest:test_redirect_guard",
        evidence={"test-report": "4" * 64},
    )

    assert result.result_id.startswith("VR-")
    assert result.obligation_id == frozen.obligation_id
    assert result.status == RESULT_PASS
    assert result.authority == "DETERMINISTIC_VERIFICATION_EVIDENCE"
    assert result.gate_effect == "NONE"
    assert result.evidence == (("test-report", "4" * 64),)

    with pytest.raises(ValueError, match="human-frozen"):
        record_verification_result(
            replace(frozen, authority="AI_VERIFICATION_PROPOSAL_ADVISORY"),
            status=RESULT_FAIL,
            summary="Failure.",
            executor="pytest:test_redirect_guard",
            evidence={"test-report": "4" * 64},
        )


def test_obligation_and_result_renderers_preserve_gate_neutrality():
    frozen = _frozen()
    result = record_verification_result(
        frozen,
        status=RESULT_FAIL,
        summary="An unsafe target was accepted.",
        executor="pytest:test_redirect_guard",
        evidence={"test-report": "5" * 64},
    )

    obligation_payload = json.loads(render_frozen_obligation_json(frozen))["verification_obligation"]
    result_payload = json.loads(render_verification_result_json(result))["verification_result"]
    assert obligation_payload["gate_effect"] == "NONE"
    assert result_payload["gate_effect"] == "NONE"
    assert result_payload["evidence"] == [
        {"content_sha256": "5" * 64, "evidence_id": "test-report"}
    ]


def _variant(name, role, *, precision, recall, f1, explore_tp=0, explore_fp=0):
    return VariantAggregate(
        variant=name,
        variant_role=role,
        run_count=1,
        mean_true_positives=4.0,
        mean_false_positives=1.0,
        mean_false_negatives=2.0,
        mean_precision=precision,
        mean_recall=recall,
        mean_f1=f1,
        supported_claim_rate=1.0,
        citation_correct_rate=1.0,
        exploration_attributable_tp=explore_tp,
        exploration_attributable_fp=explore_fp,
        mean_context_bytes=1000.0,
        mean_tool_calls=0.0 if role == "STATIC" else 2.0,
        mean_latency_ms=100.0,
        mean_cost_microusd=25.0,
        mean_input_tokens=200.0,
        mean_output_tokens=50.0,
        prediction_stability=1.0,
        exact_prediction_stability=1.0,
    )


def _comparative():
    return ComparativeBenchmarkResult(
        name="full-pilot",
        corpus_path="corpus.json",
        runs=(),
        variants=(
            _variant("static", "STATIC", precision=0.8, recall=0.5, f1=0.6154),
            _variant(
                "find-callers",
                "EXPLORATORY",
                precision=0.85,
                recall=0.75,
                f1=0.7969,
                explore_tp=2,
                explore_fp=1,
            ),
        ),
    )


def test_full_comparison_joins_discovery_challenge_and_verification_metrics():
    result = build_full_assurance_comparison(
        _comparative(),
        (
            VariantAssuranceSupplement(variant="static"),
            VariantAssuranceSupplement(
                variant="find-callers",
                challenges_supported=3,
                challenges_insufficient=1,
                obligations_proposed=2,
                obligations_frozen=1,
                verification_pass=1,
            ),
        ),
    )

    exploratory = next(item for item in result.variants if item.variant == "find-callers")
    assert result.authority == FULL_COMPARISON_AUTHORITY
    assert result.gate_effect == "NONE"
    assert exploratory.mean_recall == 0.75
    assert exploratory.exploration_attributable_tp == 2
    assert exploratory.challenges_supported == 3
    assert exploratory.obligation_freeze_rate == 0.5
    assert exploratory.verification_pass_rate == 1.0


def test_full_comparison_rejects_missing_or_impossible_supplements():
    with pytest.raises(ValueError, match="supplement mismatch"):
        build_full_assurance_comparison(
            _comparative(), (VariantAssuranceSupplement(variant="static"),)
        )

    with pytest.raises(ValueError, match="cannot exceed proposals"):
        build_full_assurance_comparison(
            _comparative(),
            (
                VariantAssuranceSupplement(variant="static"),
                VariantAssuranceSupplement(
                    variant="find-callers", obligations_proposed=0, obligations_frozen=1
                ),
            ),
        )


def test_full_comparison_renderers_are_diagnostic_only():
    result = build_full_assurance_comparison(
        _comparative(),
        (
            VariantAssuranceSupplement(variant="static"),
            VariantAssuranceSupplement(variant="find-callers"),
        ),
    )
    payload = json.loads(render_full_assurance_comparison_json(result))["full_assurance_comparison"]
    assert payload["authority"] == "BENCHMARK_DIAGNOSTIC"
    assert payload["gate_effect"] == "NONE"

    markdown = render_full_assurance_comparison_markdown(result)
    assert "experimental diagnostics only" in markdown
    assert "find-callers" in markdown
