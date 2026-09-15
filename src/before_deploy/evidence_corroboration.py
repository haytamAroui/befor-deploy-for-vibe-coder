"""Provenance-aware advisory corroboration over graph and correlation identities."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from typing import Any

from before_deploy.evidence_correlation import (
    EvidenceCorrelationResult,
    validate_evidence_correlation,
)
from before_deploy.evidence_graph import (
    AdvisoryExecutionNode,
    AdvisoryFindingNode,
    EvidenceGraph,
    NormalizedAdvisoryOutputNode,
    RawArtifactNode,
    validate_evidence_graph,
)
from before_deploy.models import to_primitive

EVIDENCE_CORROBORATION_SCHEMA_VERSION = 1
EVIDENCE_CORROBORATION_AUTHORITY = "CORROBORATION_DIAGNOSTIC"
EVIDENCE_CORROBORATION_GATE_EFFECT = "NONE"

CORROBORATION_STATUS_NONE = "NONE"
CORROBORATION_STATUS_REPEATED_EXACT_CLAIM = "REPEATED_EXACT_CLAIM"
CORROBORATION_STATUS_MULTI_EXECUTION_EXACT_CLAIM = "MULTI_EXECUTION_EXACT_CLAIM"
_ALLOWED_STATUSES = {
    CORROBORATION_STATUS_NONE,
    CORROBORATION_STATUS_REPEATED_EXACT_CLAIM,
    CORROBORATION_STATUS_MULTI_EXECUTION_EXACT_CLAIM,
}

SIGNAL_EXACT_REPEAT = "EXACT_REPEAT"
SIGNAL_MULTI_NORMALIZED_OUTPUT = "MULTI_NORMALIZED_OUTPUT"
SIGNAL_MULTI_EXECUTION = "MULTI_EXECUTION"
SIGNAL_MULTI_PROVIDER = "MULTI_PROVIDER"
SIGNAL_MULTI_ATTESTED_MODEL = "MULTI_ATTESTED_MODEL"
SIGNAL_DETERMINISTIC_COLOCATION = "DETERMINISTIC_COLOCATION"
_ALLOWED_SIGNALS = {
    SIGNAL_EXACT_REPEAT,
    SIGNAL_MULTI_NORMALIZED_OUTPUT,
    SIGNAL_MULTI_EXECUTION,
    SIGNAL_MULTI_PROVIDER,
    SIGNAL_MULTI_ATTESTED_MODEL,
    SIGNAL_DETERMINISTIC_COLOCATION,
}


@dataclass(frozen=True)
class AdvisoryCorroborationAssessment:
    """Diagnostic support facts for one canonical exact advisory claim."""

    assessment_id: str
    advisory_node_id: str
    status: str
    signals: tuple[str, ...]
    occurrence_count: int
    claim_member_node_ids: tuple[str, ...]
    normalized_output_node_ids: tuple[str, ...]
    execution_node_ids: tuple[str, ...]
    provider_ids: tuple[str, ...]
    attested_model_identities: tuple[str, ...]
    deterministic_colocation_node_ids: tuple[str, ...]
    authority: str = EVIDENCE_CORROBORATION_AUTHORITY
    gate_effect: str = EVIDENCE_CORROBORATION_GATE_EFFECT


@dataclass(frozen=True)
class EvidenceCorroborationResult:
    """Graph/correlation-bound corroboration result with no release authority."""

    schema_version: int
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    assessments: tuple[AdvisoryCorroborationAssessment, ...]
    authority: str = EVIDENCE_CORROBORATION_AUTHORITY
    gate_effect: str = EVIDENCE_CORROBORATION_GATE_EFFECT


def build_evidence_corroboration(
    graph: EvidenceGraph,
    correlation: EvidenceCorrelationResult,
) -> EvidenceCorroborationResult:
    """Describe exact-claim repetition and provenance diversity without authority promotion."""
    validate_evidence_graph(graph)
    validate_evidence_correlation(correlation, graph)

    assessments = tuple(
        _derive_assessment(node_id, graph, correlation)
        for node_id in correlation.unique_advisory_node_ids
    )
    result = EvidenceCorroborationResult(
        schema_version=EVIDENCE_CORROBORATION_SCHEMA_VERSION,
        graph_sha256=graph.graph_sha256,
        correlation_sha256=correlation.correlation_sha256,
        corroboration_sha256="",
        assessments=assessments,
    )
    result = EvidenceCorroborationResult(
        schema_version=result.schema_version,
        graph_sha256=result.graph_sha256,
        correlation_sha256=result.correlation_sha256,
        corroboration_sha256=_result_digest(result),
        assessments=result.assessments,
    )
    validate_evidence_corroboration(result, graph, correlation)
    return result


def validate_evidence_corroboration(
    result: EvidenceCorroborationResult,
    graph: EvidenceGraph,
    correlation: EvidenceCorrelationResult,
) -> None:
    """Validate provenance derivation, upstream bindings, and the non-authority contract."""
    validate_evidence_graph(graph)
    validate_evidence_correlation(correlation, graph)
    if result.schema_version != EVIDENCE_CORROBORATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence corroboration schema version")
    if result.graph_sha256 != graph.graph_sha256:
        raise ValueError("Evidence corroboration is bound to a different graph")
    if result.correlation_sha256 != correlation.correlation_sha256:
        raise ValueError("Evidence corroboration is bound to a different correlation result")
    if (
        result.authority != EVIDENCE_CORROBORATION_AUTHORITY
        or result.gate_effect != EVIDENCE_CORROBORATION_GATE_EFFECT
    ):
        raise ValueError("Evidence corroboration must remain diagnostic and gate-neutral")

    node_ids = tuple(item.advisory_node_id for item in result.assessments)
    if node_ids != tuple(sorted(node_ids)) or len(node_ids) != len(set(node_ids)):
        raise ValueError("Corroboration assessments must be unique and sorted by advisory node ID")
    if node_ids != correlation.unique_advisory_node_ids:
        raise ValueError("Corroboration must assess every canonical advisory claim exactly once")

    for item in result.assessments:
        if item.authority != EVIDENCE_CORROBORATION_AUTHORITY or item.gate_effect != "NONE":
            raise ValueError("Corroboration assessment must remain diagnostic and gate-neutral")
        if item.status not in _ALLOWED_STATUSES:
            raise ValueError(f"Unsupported corroboration status: {item.status}")
        if any(signal not in _ALLOWED_SIGNALS for signal in item.signals):
            raise ValueError("Unsupported corroboration signal")
        expected = _derive_assessment(item.advisory_node_id, graph, correlation)
        if item != expected:
            raise ValueError("Corroboration assessment no longer matches graph provenance")

    if result.corroboration_sha256 != _result_digest(result):
        raise ValueError("Evidence corroboration digest mismatch")


def evidence_corroboration_to_primitive(result: EvidenceCorroborationResult) -> dict[str, Any]:
    """Serialize corroboration facts without source content or confidence promotion."""
    return {
        "schema_version": result.schema_version,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "assessments": [to_primitive(item) for item in result.assessments],
    }


def _derive_assessment(
    advisory_node_id: str,
    graph: EvidenceGraph,
    correlation: EvidenceCorrelationResult,
) -> AdvisoryCorroborationAssessment:
    by_id = {node.node_id: node for node in graph.nodes}
    advisory = by_id.get(advisory_node_id)
    if not isinstance(advisory, AdvisoryFindingNode):
        raise ValueError("Corroboration assessment must target an advisory finding node")

    group = next(
        (item for item in correlation.duplicate_groups if item.canonical_node_id == advisory_node_id),
        None,
    )
    member_ids = group.member_node_ids if group is not None else (advisory_node_id,)
    occurrence_count = group.occurrence_count if group is not None else 1

    normalized_ids: set[str] = set()
    for edge in graph.edges:
        if edge.source_id in member_ids and edge.relation == "DERIVED_FROM":
            target = by_id.get(edge.target_id)
            if isinstance(target, NormalizedAdvisoryOutputNode):
                normalized_ids.add(target.node_id)

    execution_ids: set[str] = set()
    for normalized_id in normalized_ids:
        for edge in graph.edges:
            if edge.source_id != normalized_id:
                continue
            target = by_id.get(edge.target_id)
            if edge.relation == "PRODUCED_BY" and isinstance(target, AdvisoryExecutionNode):
                execution_ids.add(target.node_id)
            elif edge.relation == "DERIVED_FROM" and isinstance(target, RawArtifactNode):
                for raw_edge in graph.edges:
                    if raw_edge.source_id != target.node_id or raw_edge.relation != "PRODUCED_BY":
                        continue
                    producer = by_id.get(raw_edge.target_id)
                    if isinstance(producer, AdvisoryExecutionNode):
                        execution_ids.add(producer.node_id)

    executions = [by_id[node_id] for node_id in sorted(execution_ids)]
    provider_ids = tuple(
        sorted(
            {
                execution.provider_id
                for execution in executions
                if isinstance(execution, AdvisoryExecutionNode)
            }
        )
    )
    model_identities = tuple(
        sorted(
            {
                f"{execution.model_provider}/{execution.model_name}"
                for execution in executions
                if isinstance(execution, AdvisoryExecutionNode)
                and execution.model_status == "ATTESTED"
                and execution.model_provider is not None
                and execution.model_name is not None
            }
        )
    )
    deterministic_ids = tuple(
        sorted(
            {
                item.target_node_id
                for item in correlation.correlations
                if item.source_node_id == advisory_node_id
            }
        )
    )

    signals: list[str] = []
    if occurrence_count > 1:
        signals.append(SIGNAL_EXACT_REPEAT)
    if len(normalized_ids) > 1:
        signals.append(SIGNAL_MULTI_NORMALIZED_OUTPUT)
    if len(execution_ids) > 1:
        signals.append(SIGNAL_MULTI_EXECUTION)
    if len(provider_ids) > 1:
        signals.append(SIGNAL_MULTI_PROVIDER)
    if len(model_identities) > 1:
        signals.append(SIGNAL_MULTI_ATTESTED_MODEL)
    if deterministic_ids:
        signals.append(SIGNAL_DETERMINISTIC_COLOCATION)

    if len(execution_ids) > 1:
        status = CORROBORATION_STATUS_MULTI_EXECUTION_EXACT_CLAIM
    elif occurrence_count > 1:
        status = CORROBORATION_STATUS_REPEATED_EXACT_CLAIM
    else:
        status = CORROBORATION_STATUS_NONE

    semantic_payload = {
        "advisory_node_id": advisory_node_id,
        "status": status,
        "signals": tuple(sorted(signals)),
        "occurrence_count": occurrence_count,
        "claim_member_node_ids": tuple(sorted(member_ids)),
        "normalized_output_node_ids": tuple(sorted(normalized_ids)),
        "execution_node_ids": tuple(sorted(execution_ids)),
        "provider_ids": provider_ids,
        "attested_model_identities": model_identities,
        "deterministic_colocation_node_ids": deterministic_ids,
        "authority": EVIDENCE_CORROBORATION_AUTHORITY,
        "gate_effect": EVIDENCE_CORROBORATION_GATE_EFFECT,
    }
    return AdvisoryCorroborationAssessment(
        assessment_id=_diagnostic_id("corroboration", semantic_payload),
        **semantic_payload,
    )


def _diagnostic_id(kind: str, payload: Any) -> str:
    serialized = dumps(
        {"kind": kind, "payload": to_primitive(payload)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"{kind}:{sha256(serialized.encode('utf-8')).hexdigest()}"


def _result_digest(result: EvidenceCorroborationResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "assessments": [to_primitive(item) for item in result.assessments],
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()
