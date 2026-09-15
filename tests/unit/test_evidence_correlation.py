from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, build_unified_review
from before_deploy.evidence_correlation import (
    CORRELATION_BASIS_LOCATION_OVERLAP,
    CORRELATION_RELATION,
    DEDUPLICATION_BASIS_EXACT_ADVISORY_FINGERPRINT,
    EvidenceCorrelationResult,
    build_evidence_correlation,
    validate_evidence_correlation,
)
from before_deploy.evidence_graph import build_evidence_graph
from before_deploy.models import (
    Confidence,
    Disposition,
    Finding,
    GateOutcome,
    Location,
    PolicyDecision,
    ScanManifest,
    ScanResult,
    Severity,
)

NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _scan(*, start_line: int = 10, end_line: int = 12) -> ScanResult:
    finding = Finding(
        rule_id="SEC-TEST-001",
        rule_version="1.0.0",
        title="Deterministic issue",
        message="Bounded deterministic evidence.",
        remediation="Fix it.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint="deterministic-fingerprint",
        location=Location(path="src/app.py", start_line=start_line, end_line=end_line),
        disposition=Disposition.BLOCK,
    )
    return ScanResult(
        manifest=ScanManifest(
            scan_id="scan-1",
            repository_path=".",
            repository_digest="repo-digest",
            policy_digest="policy-digest",
            policy_name="strict",
            started_at=NOW,
            completed_at=NOW,
        ),
        executions=(),
        findings=(finding,),
        waivers=(),
        decision=PolicyDecision(
            outcome=GateOutcome.BLOCK,
            reason_codes=("BLOCKING_FINDINGS",),
            blocking_fingerprints=(finding.fingerprint,),
        ),
    )


def _finding(
    *,
    fingerprint: str = "advisory-fingerprint",
    message: str = "Possible issue.",
    start_line: int = 11,
    end_line: int = 13,
) -> AdvisoryFinding:
    return AdvisoryFinding(
        finding_id=f"ADV-{fingerprint}",
        source="fake-reviewer",
        title="Possible issue",
        message=message,
        category="security",
        severity="high",
        confidence="0.8",
        fingerprint=fingerprint,
        location=Location(path="src/app.py", start_line=start_line, end_line=end_line),
    )


def _source(input_name: str, *findings: AdvisoryFinding) -> AdvisoryImport:
    return AdvisoryImport(
        input_name=input_name,
        source="fake-reviewer",
        source_format="fake-json-v1",
        findings=tuple(findings),
    )


def _build(scan: ScanResult, sources: tuple[AdvisoryImport, ...]):
    review = build_unified_review(scan, sources)
    graph = build_evidence_graph(scan, sources)
    return review, graph, build_evidence_correlation(review, graph)


def test_location_correlation_uses_stable_graph_ids_and_overlap_bounds():
    review, graph, result = _build(_scan(), (_source("one", _finding()),))

    assert review.scan.decision.outcome == GateOutcome.BLOCK
    assert len(result.correlations) == 1
    item = result.correlations[0]
    assert item.relation == CORRELATION_RELATION
    assert item.basis == CORRELATION_BASIS_LOCATION_OVERLAP
    assert item.path == "src/app.py"
    assert item.overlap_start_line == 11
    assert item.overlap_end_line == 12
    assert item.source_node_id.startswith("advisory_finding:")
    assert item.target_node_id.startswith("deterministic_finding:")
    assert item.source_node_id in {node.node_id for node in graph.nodes}
    assert item.target_node_id in {node.node_id for node in graph.nodes}
    assert item.authority == "CORRELATION_DIAGNOSTIC"
    assert item.gate_effect == "NONE"


def test_disjoint_ranges_do_not_correlate():
    _, _, result = _build(
        _scan(start_line=1, end_line=2),
        (_source("one", _finding(start_line=10, end_line=11)),),
    )

    assert result.correlations == ()


def test_exact_repeated_advisory_fingerprint_collapses_only_in_unique_view():
    repeated = _finding()
    sources = (_source("one", repeated), _source("two", repeated))
    review, _, result = _build(_scan(), sources)

    assert len(review.advisory_findings) == 2
    assert len(result.unique_advisory_node_ids) == 1
    assert len(result.duplicate_groups) == 1
    group = result.duplicate_groups[0]
    assert group.fingerprint == repeated.fingerprint
    assert group.occurrence_count == 2
    assert group.basis == DEDUPLICATION_BASIS_EXACT_ADVISORY_FINGERPRINT
    assert group.canonical_node_id == min(group.member_node_ids)
    assert group.gate_effect == "NONE"


def test_similar_claims_with_different_fingerprints_are_not_deduplicated():
    first = _finding(fingerprint="first", message="Possible authorization issue.")
    second = _finding(fingerprint="second", message="Potential access-control issue.")
    _, _, result = _build(_scan(), (_source("one", first, second),))

    assert len(result.unique_advisory_node_ids) == 2
    assert result.duplicate_groups == ()
    assert len(result.correlations) == 2


def test_correlation_digest_is_reproducible_and_graph_bound():
    review, graph, first = _build(_scan(), (_source("one", _finding()),))
    second = build_evidence_correlation(review, graph)

    assert first == second
    assert first.correlation_sha256 == second.correlation_sha256
    assert first.graph_sha256 == graph.graph_sha256

    tampered = replace(first, graph_sha256="0" * 64)
    with pytest.raises(ValueError, match="different graph"):
        validate_evidence_correlation(tampered, graph)


def test_correlation_authority_cannot_be_upgraded():
    _, graph, result = _build(_scan(), (_source("one", _finding()),))
    upgraded = EvidenceCorrelationResult(
        schema_version=result.schema_version,
        graph_sha256=result.graph_sha256,
        correlation_sha256=result.correlation_sha256,
        correlations=result.correlations,
        unique_advisory_node_ids=result.unique_advisory_node_ids,
        duplicate_groups=result.duplicate_groups,
        authority="RELEASE_AUTHORITY",
        gate_effect="BLOCK",
    )

    with pytest.raises(ValueError, match="gate-neutral"):
        validate_evidence_correlation(upgraded, graph)
