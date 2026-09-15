from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport
from before_deploy.advisory_execution import (
    AdvisoryExecutionBudget,
    AdvisoryExecutionParameter,
    AdvisoryExecutionProvenance,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
)
from before_deploy.evidence_graph import (
    AdvisoryExecutionNode,
    AdvisoryFindingNode,
    EvidenceGraph,
    PolicyDecisionNode,
    RawArtifactNode,
    build_evidence_graph,
    validate_evidence_graph,
)
from before_deploy.models import (
    Confidence,
    ControlExecution,
    Disposition,
    ExecutionStatus,
    Finding,
    GateOutcome,
    Location,
    PolicyDecision,
    ScanManifest,
    ScanResult,
    Severity,
)

NOW = datetime(2026, 9, 14, 22, 0, tzinfo=timezone.utc)


def _scan() -> ScanResult:
    finding = Finding(
        rule_id="SEC-TEST-001",
        rule_version="1.0.0",
        title="Deterministic issue",
        message="Bounded deterministic evidence.",
        remediation="Fix the issue.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint="deterministic-fingerprint",
        location=Location(path="app.py", start_line=3, end_line=3),
        evidence={"issue": "test"},
        disposition=Disposition.BLOCK,
    )
    execution = ControlExecution(
        control_id="SEC-TEST-001",
        control_version="1.0.0",
        status=ExecutionStatus.COMPLETED,
        started_at=NOW,
        completed_at=NOW,
        message="completed",
    )
    return ScanResult(
        manifest=ScanManifest(
            scan_id="scan-1",
            repository_path="/private/path-not-in-graph",
            repository_digest="repo-digest",
            policy_digest="policy-digest",
            policy_name="strict",
            started_at=NOW,
            completed_at=NOW,
            git_revision="a" * 40,
            scanned_file_count=1,
        ),
        executions=(execution,),
        findings=(finding,),
        waivers=(),
        decision=PolicyDecision(
            outcome=GateOutcome.BLOCK,
            reason_codes=("BLOCKING_FINDINGS",),
            blocking_fingerprints=(finding.fingerprint,),
        ),
    )


def _advisory() -> AdvisoryImport:
    raw = AdvisoryRawArtifact(
        sha256="b" * 64,
        size_bytes=321,
        media_type="application/json",
        schema="fake-json-v1",
    )
    execution = AdvisoryExecutionProvenance(
        schema_version=1,
        provider_id="fake",
        implementation="fake-adapter",
        implementation_version="1",
        model=AdvisoryModelIdentity(
            status="ATTESTED",
            provider="example",
            model="review-model",
        ),
        configuration=(AdvisoryExecutionParameter(name="mode", value="review"),),
        configuration_sha256="c" * 64,
        budgets=(AdvisoryExecutionBudget(name="timeout", limit=10, unit="seconds"),),
        context_sha256="d" * 64,
        context_selected_files=1,
        context_selected_bytes=20,
        started_at=NOW,
        completed_at=NOW,
        duration_ms=4,
        raw_output=raw,
        normalized_output_sha256="e" * 64,
        result_status="COMPLETED",
    )
    finding = AdvisoryFinding(
        finding_id="ADV-1",
        source="fake-reviewer",
        title="Possible bug",
        message="Advisory claim.",
        category="bug",
        severity="high",
        confidence="0.8",
        fingerprint="advisory-fingerprint",
        location=Location(path="app.py", start_line=3, end_line=3),
    )
    return AdvisoryImport(
        input_name="fake-provider",
        source="fake-reviewer",
        source_format="fake-json-v1",
        findings=(finding,),
        raw_artifact=raw,
        execution=execution,
    )


def test_graph_is_content_addressed_typed_and_reproducible():
    first = build_evidence_graph(_scan(), (_advisory(),))
    second = build_evidence_graph(_scan(), (_advisory(),))

    assert first.graph_sha256 == second.graph_sha256
    assert first.nodes == second.nodes
    assert first.edges == second.edges
    assert all(node.node_id.endswith(node.payload_sha256) for node in first.nodes)
    assert {node.node_type for node in first.nodes} >= {
        "REPOSITORY_SNAPSHOT",
        "POLICY_INPUT",
        "CONTROL_EXECUTION",
        "DETERMINISTIC_FINDING",
        "POLICY_DECISION",
        "ADVISORY_CONTEXT",
        "ADVISORY_EXECUTION",
        "RAW_ADVISORY_ARTIFACT",
        "NORMALIZED_ADVISORY_OUTPUT",
        "ADVISORY_FINDING",
    }


def test_only_policy_decision_node_has_release_authority():
    graph = build_evidence_graph(_scan(), (_advisory(),))

    release_nodes = [node for node in graph.nodes if node.authority == "RELEASE_AUTHORITY"]
    assert len(release_nodes) == 1
    assert isinstance(release_nodes[0], PolicyDecisionNode)
    assert all(
        node.gate_effect == "NONE"
        for node in graph.nodes
        if isinstance(node, (AdvisoryExecutionNode, AdvisoryFindingNode))
    )


def test_graph_records_explicit_raw_to_normalized_to_finding_lineage():
    graph = build_evidence_graph(_scan(), (_advisory(),))
    raw = next(node for node in graph.nodes if isinstance(node, RawArtifactNode))
    execution = next(node for node in graph.nodes if isinstance(node, AdvisoryExecutionNode))
    advisory = next(node for node in graph.nodes if isinstance(node, AdvisoryFindingNode))
    normalized = next(node for node in graph.nodes if node.node_type == "NORMALIZED_ADVISORY_OUTPUT")

    triples = {(edge.source_id, edge.relation, edge.target_id) for edge in graph.edges}
    assert (raw.node_id, "PRODUCED_BY", execution.node_id) in triples
    assert (normalized.node_id, "DERIVED_FROM", raw.node_id) in triples
    assert (advisory.node_id, "DERIVED_FROM", normalized.node_id) in triples


def test_location_overlap_is_not_promoted_to_graph_correlation():
    graph = build_evidence_graph(_scan(), (_advisory(),))

    assert all(edge.relation != "CORRELATES_WITH" for edge in graph.edges)
    deterministic = next(node for node in graph.nodes if node.node_type == "DETERMINISTIC_FINDING")
    advisory = next(node for node in graph.nodes if node.node_type == "ADVISORY_FINDING")
    assert not any(
        {edge.source_id, edge.target_id} == {deterministic.node_id, advisory.node_id}
        for edge in graph.edges
    )


def test_validation_rejects_node_payload_tampering():
    graph = build_evidence_graph(_scan(), (_advisory(),))
    advisory = next(node for node in graph.nodes if isinstance(node, AdvisoryFindingNode))
    tampered = replace(advisory, message="changed without changing node identity")
    nodes = tuple(tampered if node is advisory else node for node in graph.nodes)
    broken = EvidenceGraph(
        schema_version=graph.schema_version,
        graph_sha256=graph.graph_sha256,
        nodes=nodes,
        edges=graph.edges,
    )

    with pytest.raises(ValueError, match="payload digest mismatch"):
        validate_evidence_graph(broken)


def test_repository_local_path_is_not_copied_into_graph():
    graph = build_evidence_graph(_scan(), ())

    rendered = str(graph)
    assert "/private/path-not-in-graph" not in rendered
