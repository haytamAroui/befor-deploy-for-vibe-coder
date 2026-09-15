from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, build_unified_review
from before_deploy.advisory_execution import (
    AdvisoryExecutionProvenance,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
)
from before_deploy.evidence_correlation import build_evidence_correlation
from before_deploy.evidence_corroboration import (
    CORROBORATION_STATUS_MULTI_EXECUTION_EXACT_CLAIM,
    CORROBORATION_STATUS_NONE,
    CORROBORATION_STATUS_REPEATED_EXACT_CLAIM,
    SIGNAL_DETERMINISTIC_COLOCATION,
    SIGNAL_EXACT_REPEAT,
    SIGNAL_MULTI_ATTESTED_MODEL,
    SIGNAL_MULTI_EXECUTION,
    SIGNAL_MULTI_NORMALIZED_OUTPUT,
    SIGNAL_MULTI_PROVIDER,
    build_evidence_corroboration,
    validate_evidence_corroboration,
)
from before_deploy.evidence_graph import build_evidence_graph
from before_deploy.models import (
    Confidence,
    Finding,
    GateOutcome,
    Location,
    PolicyDecision,
    ScanManifest,
    ScanResult,
    Severity,
)

NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _scan() -> ScanResult:
    deterministic = Finding(
        rule_id="SEC-TEST-001",
        rule_version="1.0.0",
        title="Deterministic issue",
        message="Deterministic evidence.",
        remediation="Fix it.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint="deterministic-fingerprint",
        location=Location(path="app.py", start_line=5, end_line=5),
    )
    return ScanResult(
        manifest=ScanManifest(
            scan_id="scan-1",
            repository_path="/private/repository",
            repository_digest="repo-digest",
            policy_digest="policy-digest",
            policy_name="strict",
            started_at=NOW,
            completed_at=NOW,
        ),
        executions=(),
        findings=(deterministic,),
        waivers=(),
        decision=PolicyDecision(
            outcome=GateOutcome.BLOCK,
            reason_codes=("BLOCKING_FINDINGS",),
            blocking_fingerprints=(deterministic.fingerprint,),
        ),
    )


def _finding() -> AdvisoryFinding:
    return AdvisoryFinding(
        finding_id="ADV-1",
        source="reviewer",
        title="Possible issue",
        message="Advisory claim.",
        category="security",
        severity="high",
        confidence="0.8",
        fingerprint="same-advisory-fingerprint",
        location=Location(path="app.py", start_line=5, end_line=5),
    )


def _executed_source(name: str, provider_id: str, model: str, digest_char: str) -> AdvisoryImport:
    raw = AdvisoryRawArtifact(
        sha256=digest_char * 64,
        size_bytes=100,
        media_type="application/json",
        schema="review-json-v1",
    )
    execution = AdvisoryExecutionProvenance(
        schema_version=1,
        provider_id=provider_id,
        implementation=f"{provider_id}-adapter",
        implementation_version="1",
        model=AdvisoryModelIdentity(status="ATTESTED", provider=provider_id, model=model),
        configuration=(),
        configuration_sha256=("c" if digest_char != "c" else "d") * 64,
        budgets=(),
        context_sha256=("e" if digest_char != "e" else "f") * 64,
        context_selected_files=1,
        context_selected_bytes=20,
        started_at=NOW,
        completed_at=NOW,
        duration_ms=5,
        raw_output=raw,
        normalized_output_sha256=("9" if digest_char != "9" else "8") * 64,
        result_status="COMPLETED",
    )
    return AdvisoryImport(
        input_name=name,
        source="reviewer",
        source_format="review-json-v1",
        findings=(_finding(),),
        raw_artifact=raw,
        execution=execution,
    )


def _build(sources: tuple[AdvisoryImport, ...]):
    review = build_unified_review(_scan(), sources)
    graph = build_evidence_graph(review.scan, review.advisory_sources)
    correlation = build_evidence_correlation(review, graph)
    corroboration = build_evidence_corroboration(graph, correlation)
    return review, graph, correlation, corroboration


def test_exact_claim_from_multiple_executions_records_provenance_diversity_without_authority():
    review, _, _, corroboration = _build(
        (
            _executed_source("one", "provider-a", "model-a", "a"),
            _executed_source("two", "provider-b", "model-b", "b"),
        )
    )

    assert review.scan.decision.outcome == GateOutcome.BLOCK
    assert len(corroboration.assessments) == 1
    item = corroboration.assessments[0]
    assert item.status == CORROBORATION_STATUS_MULTI_EXECUTION_EXACT_CLAIM
    assert item.occurrence_count == 2
    assert set(item.signals) == {
        SIGNAL_EXACT_REPEAT,
        SIGNAL_MULTI_NORMALIZED_OUTPUT,
        SIGNAL_MULTI_EXECUTION,
        SIGNAL_MULTI_PROVIDER,
        SIGNAL_MULTI_ATTESTED_MODEL,
        SIGNAL_DETERMINISTIC_COLOCATION,
    }
    assert item.provider_ids == ("provider-a", "provider-b")
    assert item.attested_model_identities == (
        "provider-a/model-a",
        "provider-b/model-b",
    )
    assert len(item.execution_node_ids) == 2
    assert len(item.deterministic_colocation_node_ids) == 1
    assert item.authority == "CORROBORATION_DIAGNOSTIC"
    assert item.gate_effect == "NONE"
    assert corroboration.authority == "CORROBORATION_DIAGNOSTIC"
    assert corroboration.gate_effect == "NONE"


def test_repeated_import_without_attested_executions_is_repetition_not_multi_execution():
    finding = _finding()
    _, _, _, corroboration = _build(
        (
            AdvisoryImport("one", "reviewer", "json", (finding,)),
            AdvisoryImport("two", "reviewer", "json", (finding,)),
        )
    )

    item = corroboration.assessments[0]
    assert item.status == CORROBORATION_STATUS_REPEATED_EXACT_CLAIM
    assert item.occurrence_count == 2
    assert SIGNAL_EXACT_REPEAT in item.signals
    assert SIGNAL_MULTI_NORMALIZED_OUTPUT in item.signals
    assert SIGNAL_MULTI_EXECUTION not in item.signals
    assert item.execution_node_ids == ()
    assert item.provider_ids == ()
    assert item.attested_model_identities == ()


def test_deterministic_colocation_alone_does_not_upgrade_corroboration_status():
    _, _, _, corroboration = _build((AdvisoryImport("one", "reviewer", "json", (_finding(),)),))

    item = corroboration.assessments[0]
    assert item.status == CORROBORATION_STATUS_NONE
    assert item.signals == (SIGNAL_DETERMINISTIC_COLOCATION,)
    assert len(item.deterministic_colocation_node_ids) == 1


def test_corroboration_digest_is_stable_for_identical_inputs():
    sources = (
        _executed_source("one", "provider-a", "model-a", "a"),
        _executed_source("two", "provider-b", "model-b", "b"),
    )
    first = _build(sources)[3]
    second = _build(sources)[3]

    assert first == second
    assert first.corroboration_sha256 == second.corroboration_sha256


def test_validation_rejects_authority_upgrade_and_binding_drift():
    _, graph, correlation, corroboration = _build(
        (
            _executed_source("one", "provider-a", "model-a", "a"),
            _executed_source("two", "provider-b", "model-b", "b"),
        )
    )

    with pytest.raises(ValueError, match="diagnostic and gate-neutral"):
        validate_evidence_corroboration(
            replace(corroboration, authority="RELEASE_AUTHORITY"),
            graph,
            correlation,
        )

    with pytest.raises(ValueError, match="different correlation result"):
        validate_evidence_corroboration(
            replace(corroboration, correlation_sha256="0" * 64),
            graph,
            correlation,
        )


def test_validation_rejects_claimed_status_not_derived_from_provenance():
    _, graph, correlation, corroboration = _build(
        (AdvisoryImport("one", "reviewer", "json", (_finding(),)),)
    )
    item = corroboration.assessments[0]
    tampered = replace(
        corroboration,
        assessments=(replace(item, status=CORROBORATION_STATUS_MULTI_EXECUTION_EXACT_CLAIM),),
    )

    with pytest.raises(ValueError, match="no longer matches graph provenance"):
        validate_evidence_corroboration(tampered, graph, correlation)
