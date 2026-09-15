"""Typed, content-addressed evidence lineage for deterministic and advisory review."""

from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
from json import dumps
from typing import TYPE_CHECKING, Any

from before_deploy.models import Location, ScanResult, to_primitive

if TYPE_CHECKING:
    from before_deploy.advisory import AdvisoryImport

EVIDENCE_GRAPH_SCHEMA_VERSION = 1
EVIDENCE_GRAPH_AUTHORITY = "EVIDENCE_GRAPH"
EVIDENCE_GRAPH_GATE_EFFECT = "NONE"

RELATION_DERIVED_FROM = "DERIVED_FROM"
RELATION_OBSERVED_AT = "OBSERVED_AT"
RELATION_PRODUCED_BY = "PRODUCED_BY"
RELATION_SUPPORTS = "SUPPORTS"
RELATION_APPLIES_TO = "APPLIES_TO"
_ALLOWED_RELATIONS = {
    RELATION_DERIVED_FROM,
    RELATION_OBSERVED_AT,
    RELATION_PRODUCED_BY,
    RELATION_SUPPORTS,
    RELATION_APPLIES_TO,
}


@dataclass(frozen=True)
class EvidenceGraphNode:
    """Immutable content-addressed graph node base class."""

    node_id: str
    payload_sha256: str
    node_type: str
    authority: str


@dataclass(frozen=True)
class RepositorySnapshotNode(EvidenceGraphNode):
    repository_digest: str
    git_revision: str | None
    scanned_file_count: int
    excluded_file_count: int
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class PolicyInputNode(EvidenceGraphNode):
    policy_name: str
    policy_digest: str


@dataclass(frozen=True)
class ObservationNode(EvidenceGraphNode):
    signal_id: str
    signal_version: str
    kind: str
    title: str
    location: Location
    metadata: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ControlExecutionNode(EvidenceGraphNode):
    control_id: str
    control_version: str
    status: str
    applicable: bool
    started_at: str
    completed_at: str
    message: str | None
    metadata: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class DeterministicFindingNode(EvidenceGraphNode):
    fingerprint: str
    rule_id: str
    rule_version: str
    title: str
    message: str
    remediation: str
    severity: str
    confidence: str
    location: Location | None
    evidence: tuple[tuple[str, str], ...]
    disposition: str | None


@dataclass(frozen=True)
class WaiverNode(EvidenceGraphNode):
    waiver_id: str
    finding_fingerprint: str
    rule_id: str
    repository_digest: str
    approved_by: str
    justification: str
    compensating_controls: str
    expires_at: str


@dataclass(frozen=True)
class PolicyDecisionNode(EvidenceGraphNode):
    outcome: str
    reason_codes: tuple[str, ...]
    blocking_fingerprints: tuple[str, ...]
    waiver_required_fingerprints: tuple[str, ...]
    waived_fingerprints: tuple[str, ...]
    advisory_fingerprints: tuple[str, ...]
    error_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class AdvisoryContextNode(EvidenceGraphNode):
    context_sha256: str
    selected_file_count: int
    selected_bytes: int
    gate_effect: str


@dataclass(frozen=True)
class AdvisoryExecutionNode(EvidenceGraphNode):
    provider_id: str
    implementation: str
    implementation_version: str | None
    model_status: str
    model_provider: str | None
    model_name: str | None
    configuration_sha256: str
    budgets: tuple[tuple[str, int, str], ...]
    started_at: str
    completed_at: str
    duration_ms: int
    normalized_output_sha256: str
    result_status: str
    gate_effect: str


@dataclass(frozen=True)
class RawArtifactNode(EvidenceGraphNode):
    artifact_sha256: str
    size_bytes: int
    media_type: str
    schema: str | None


@dataclass(frozen=True)
class NormalizedAdvisoryOutputNode(EvidenceGraphNode):
    normalized_output_sha256: str
    input_name: str
    source: str
    source_format: str
    status: str
    finding_count: int


@dataclass(frozen=True)
class AdvisoryFindingNode(EvidenceGraphNode):
    fingerprint: str
    finding_id: str
    source: str
    title: str
    message: str
    category: str
    severity: str
    confidence: str | None
    location: Location | None
    gate_effect: str


@dataclass(frozen=True)
class EvidenceGraphEdge:
    """Directed typed lineage edge between two immutable graph nodes."""

    source_id: str
    relation: str
    target_id: str


@dataclass(frozen=True)
class EvidenceGraph:
    """Content-addressed graph container; the graph itself is not release authority."""

    schema_version: int
    graph_sha256: str
    nodes: tuple[EvidenceGraphNode, ...]
    edges: tuple[EvidenceGraphEdge, ...]
    authority: str = EVIDENCE_GRAPH_AUTHORITY
    gate_effect: str = EVIDENCE_GRAPH_GATE_EFFECT


def build_evidence_graph(
    scan: ScanResult,
    advisory_sources: tuple[AdvisoryImport, ...],
) -> EvidenceGraph:
    """Build Evidence Graph v1 using only explicit lineage available in current results."""
    nodes: list[EvidenceGraphNode] = []
    edges: list[EvidenceGraphEdge] = []

    repository = _node(
        RepositorySnapshotNode,
        "REPOSITORY_SNAPSHOT",
        "DETERMINISTIC_INPUT",
        repository_digest=scan.manifest.repository_digest,
        git_revision=scan.manifest.git_revision,
        scanned_file_count=scan.manifest.scanned_file_count,
        excluded_file_count=scan.manifest.excluded_file_count,
        limitations=tuple(scan.manifest.limitations),
    )
    policy = _node(
        PolicyInputNode,
        "POLICY_INPUT",
        "DETERMINISTIC_POLICY_INPUT",
        policy_name=scan.manifest.policy_name,
        policy_digest=scan.manifest.policy_digest,
    )
    nodes.extend((repository, policy))

    if scan.security_analysis_plan is not None:
        for signal in scan.security_analysis_plan.evidence:
            observation = _node(
                ObservationNode,
                "OBSERVATION",
                "DETERMINISTIC_EVIDENCE",
                signal_id=signal.signal_id,
                signal_version=signal.signal_version,
                kind=signal.kind.value,
                title=signal.title,
                location=signal.location,
                metadata=_pairs(signal.metadata),
            )
            nodes.append(observation)
            edges.append(_edge(observation, RELATION_OBSERVED_AT, repository))

    controls: dict[tuple[str, str], ControlExecutionNode] = {}
    for execution in scan.executions:
        control = _node(
            ControlExecutionNode,
            "CONTROL_EXECUTION",
            "DETERMINISTIC_EXECUTION",
            control_id=execution.control_id,
            control_version=execution.control_version,
            status=execution.status.value,
            applicable=execution.applicable,
            started_at=_timestamp(execution.started_at),
            completed_at=_timestamp(execution.completed_at),
            message=execution.message,
            metadata=_pairs(execution.metadata),
        )
        nodes.append(control)
        controls[(execution.control_id, execution.control_version)] = control
        edges.append(_edge(control, RELATION_DERIVED_FROM, repository))

    findings: dict[str, DeterministicFindingNode] = {}
    for finding in scan.findings:
        finding_node = _node(
            DeterministicFindingNode,
            "DETERMINISTIC_FINDING",
            "DETERMINISTIC_FINDING",
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            title=finding.title,
            message=finding.message,
            remediation=finding.remediation,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            location=finding.location,
            evidence=_pairs(finding.evidence),
            disposition=finding.disposition.value if finding.disposition is not None else None,
        )
        nodes.append(finding_node)
        findings[finding.fingerprint] = finding_node
        edges.append(_edge(finding_node, RELATION_OBSERVED_AT, repository))
        producer = controls.get((finding.rule_id, finding.rule_version))
        if producer is not None:
            edges.append(_edge(finding_node, RELATION_PRODUCED_BY, producer))

    waiver_nodes: list[WaiverNode] = []
    for waiver in scan.waivers:
        waiver_node = _node(
            WaiverNode,
            "WAIVER",
            "DETERMINISTIC_WAIVER",
            waiver_id=waiver.waiver_id,
            finding_fingerprint=waiver.finding_fingerprint,
            rule_id=waiver.rule_id,
            repository_digest=waiver.repository_digest,
            approved_by=waiver.approved_by,
            justification=waiver.justification,
            compensating_controls=waiver.compensating_controls,
            expires_at=_timestamp(waiver.expires_at),
        )
        nodes.append(waiver_node)
        waiver_nodes.append(waiver_node)
        finding_node = findings.get(waiver.finding_fingerprint)
        if finding_node is not None:
            edges.append(_edge(waiver_node, RELATION_APPLIES_TO, finding_node))

    decision = scan.decision
    decision_node = _node(
        PolicyDecisionNode,
        "POLICY_DECISION",
        "RELEASE_AUTHORITY",
        outcome=decision.outcome.value,
        reason_codes=tuple(decision.reason_codes),
        blocking_fingerprints=tuple(decision.blocking_fingerprints),
        waiver_required_fingerprints=tuple(decision.waiver_required_fingerprints),
        waived_fingerprints=tuple(decision.waived_fingerprints),
        advisory_fingerprints=tuple(decision.advisory_fingerprints),
        error_control_ids=tuple(decision.error_control_ids),
    )
    nodes.append(decision_node)
    edges.append(_edge(decision_node, RELATION_DERIVED_FROM, policy))
    for control in controls.values():
        edges.append(_edge(decision_node, RELATION_DERIVED_FROM, control))
    for finding_node in findings.values():
        edges.append(_edge(decision_node, RELATION_DERIVED_FROM, finding_node))
    for waiver_node in waiver_nodes:
        edges.append(_edge(decision_node, RELATION_DERIVED_FROM, waiver_node))

    for source in advisory_sources:
        execution_node: AdvisoryExecutionNode | None = None
        if source.execution is not None:
            execution = source.execution
            context_node = _node(
                AdvisoryContextNode,
                "ADVISORY_CONTEXT",
                "ADVISORY_CONTEXT",
                context_sha256=execution.context_sha256,
                selected_file_count=execution.context_selected_files,
                selected_bytes=execution.context_selected_bytes,
                gate_effect="NONE",
            )
            nodes.append(context_node)
            execution_node = _node(
                AdvisoryExecutionNode,
                "ADVISORY_EXECUTION",
                execution.authority,
                provider_id=execution.provider_id,
                implementation=execution.implementation,
                implementation_version=execution.implementation_version,
                model_status=execution.model.status,
                model_provider=execution.model.provider,
                model_name=execution.model.model,
                configuration_sha256=execution.configuration_sha256,
                budgets=tuple((item.name, item.limit, item.unit) for item in execution.budgets),
                started_at=_timestamp(execution.started_at),
                completed_at=_timestamp(execution.completed_at),
                duration_ms=execution.duration_ms,
                normalized_output_sha256=execution.normalized_output_sha256,
                result_status=execution.result_status,
                gate_effect=execution.gate_effect,
            )
            nodes.append(execution_node)
            edges.append(_edge(execution_node, RELATION_DERIVED_FROM, context_node))

        raw_node: RawArtifactNode | None = None
        if source.raw_artifact is not None:
            artifact = source.raw_artifact
            raw_node = _node(
                RawArtifactNode,
                "RAW_ADVISORY_ARTIFACT",
                "ADVISORY_ARTIFACT",
                artifact_sha256=artifact.sha256,
                size_bytes=artifact.size_bytes,
                media_type=artifact.media_type,
                schema=artifact.schema,
            )
            nodes.append(raw_node)
            if execution_node is not None:
                edges.append(_edge(raw_node, RELATION_PRODUCED_BY, execution_node))

        normalized_sha = (
            source.execution.normalized_output_sha256
            if source.execution is not None
            else _normalized_source_sha256(source)
        )
        normalized_node = _node(
            NormalizedAdvisoryOutputNode,
            "NORMALIZED_ADVISORY_OUTPUT",
            "ADVISORY_ARTIFACT",
            normalized_output_sha256=normalized_sha,
            input_name=source.input_name,
            source=source.source,
            source_format=source.source_format,
            status=source.status,
            finding_count=len(source.findings),
        )
        nodes.append(normalized_node)
        if raw_node is not None:
            edges.append(_edge(normalized_node, RELATION_DERIVED_FROM, raw_node))
        elif execution_node is not None:
            edges.append(_edge(normalized_node, RELATION_PRODUCED_BY, execution_node))

        for finding in source.findings:
            advisory_node = _node(
                AdvisoryFindingNode,
                "ADVISORY_FINDING",
                finding.authority,
                fingerprint=finding.fingerprint,
                finding_id=finding.finding_id,
                source=finding.source,
                title=finding.title,
                message=finding.message,
                category=finding.category,
                severity=finding.severity,
                confidence=finding.confidence,
                location=finding.location,
                gate_effect=finding.gate_effect,
            )
            nodes.append(advisory_node)
            edges.append(_edge(advisory_node, RELATION_DERIVED_FROM, normalized_node))

    unique_nodes = {node.node_id: node for node in nodes}
    graph = EvidenceGraph(
        schema_version=EVIDENCE_GRAPH_SCHEMA_VERSION,
        graph_sha256="",
        nodes=tuple(sorted(unique_nodes.values(), key=lambda item: item.node_id)),
        edges=tuple(sorted(set(edges), key=lambda item: (item.source_id, item.relation, item.target_id))),
    )
    graph = EvidenceGraph(
        schema_version=graph.schema_version,
        graph_sha256=_graph_digest(graph),
        nodes=graph.nodes,
        edges=graph.edges,
    )
    validate_evidence_graph(graph)
    return graph


def validate_evidence_graph(graph: EvidenceGraph) -> None:
    """Reject graph tampering, dangling edges, duplicate nodes, or authority drift."""
    if graph.schema_version != EVIDENCE_GRAPH_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence graph schema version")
    if graph.authority != EVIDENCE_GRAPH_AUTHORITY or graph.gate_effect != EVIDENCE_GRAPH_GATE_EFFECT:
        raise ValueError("Evidence graph container must remain gate-neutral")

    node_ids = [node.node_id for node in graph.nodes]
    if node_ids != sorted(node_ids) or len(node_ids) != len(set(node_ids)):
        raise ValueError("Evidence graph nodes must be unique and sorted")
    known = set(node_ids)
    for node in graph.nodes:
        expected_digest = _node_digest(node.node_type, node.authority, _semantic_payload(node))
        if node.payload_sha256 != expected_digest:
            raise ValueError(f"Evidence graph node payload digest mismatch for {node.node_id}")
        if node.node_id != f"{node.node_type.lower()}:{expected_digest}":
            raise ValueError("Evidence graph node ID is not content-addressed")
        _validate_node_authority(node)

    sorted_edges = tuple(sorted(graph.edges, key=lambda item: (item.source_id, item.relation, item.target_id)))
    if graph.edges != sorted_edges or len(graph.edges) != len(set(graph.edges)):
        raise ValueError("Evidence graph edges must be unique and sorted")
    for edge in graph.edges:
        if edge.relation not in _ALLOWED_RELATIONS:
            raise ValueError(f"Unsupported evidence graph relation: {edge.relation}")
        if edge.source_id not in known or edge.target_id not in known:
            raise ValueError("Evidence graph edge references an unknown node")
        if edge.source_id == edge.target_id:
            raise ValueError("Evidence graph self-edges are not allowed")

    if graph.graph_sha256 != _graph_digest(graph):
        raise ValueError("Evidence graph digest mismatch")


def evidence_graph_to_primitive(graph: EvidenceGraph) -> dict[str, Any]:
    """Serialize the validated graph for stable machine consumption."""
    validate_evidence_graph(graph)
    return {
        "schema_version": graph.schema_version,
        "graph_sha256": graph.graph_sha256,
        "authority": graph.authority,
        "gate_effect": graph.gate_effect,
        "nodes": [to_primitive(node) for node in graph.nodes],
        "edges": [to_primitive(edge) for edge in graph.edges],
    }


def render_evidence_graph_json(graph: EvidenceGraph) -> str:
    return dumps(evidence_graph_to_primitive(graph), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_evidence_graph_markdown(graph: EvidenceGraph) -> str:
    validate_evidence_graph(graph)
    counts: dict[str, int] = {}
    for node in graph.nodes:
        counts[node.node_type] = counts.get(node.node_type, 0) + 1
    lines = [
        "# Before Deploy Evidence Graph",
        "",
        f"- Schema: **{graph.schema_version}**",
        f"- Graph SHA-256: `{graph.graph_sha256}`",
        f"- Nodes: **{len(graph.nodes)}**",
        f"- Edges: **{len(graph.edges)}**",
        f"- Authority: `{graph.authority}`",
        f"- Gate effect: `{graph.gate_effect}`",
        "",
        "## Node inventory",
        "",
    ]
    for node_type, count in sorted(counts.items()):
        lines.append(f"- `{node_type}`: **{count}**")
    lines.extend(
        [
            "",
            "## Authority boundary",
            "",
            "The graph records lineage; it does not make a release decision.",
            "Only `POLICY_DECISION` nodes may carry `RELEASE_AUTHORITY`.",
            "Advisory findings, contexts, executions, and artifacts remain non-authoritative.",
            "",
            "## Edges",
            "",
        ]
    )
    if not graph.edges:
        lines.append("No edges were recorded.")
    else:
        by_id = {node.node_id: node for node in graph.nodes}
        for edge in graph.edges:
            source = by_id[edge.source_id]
            target = by_id[edge.target_id]
            lines.append(
                f"- `{source.node_type}` `{source.node_id}` **{edge.relation}** "
                f"`{target.node_type}` `{target.node_id}`"
            )
    return "\n".join(lines) + "\n"


def _node(cls, node_type: str, authority: str, **payload):
    digest = _node_digest(node_type, authority, payload)
    return cls(
        node_id=f"{node_type.lower()}:{digest}",
        payload_sha256=digest,
        node_type=node_type,
        authority=authority,
        **payload,
    )


def _edge(source: EvidenceGraphNode, relation: str, target: EvidenceGraphNode) -> EvidenceGraphEdge:
    return EvidenceGraphEdge(source_id=source.node_id, relation=relation, target_id=target.node_id)


def _node_digest(node_type: str, authority: str, payload: Any) -> str:
    serialized = dumps(
        {"node_type": node_type, "authority": authority, "payload": to_primitive(payload)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


def _semantic_payload(node: EvidenceGraphNode) -> dict[str, Any]:
    excluded = {"node_id", "payload_sha256", "node_type", "authority"}
    return {
        field.name: getattr(node, field.name)
        for field in fields(node)
        if field.name not in excluded
    }


def _graph_digest(graph: EvidenceGraph) -> str:
    payload = {
        "schema_version": graph.schema_version,
        "authority": graph.authority,
        "gate_effect": graph.gate_effect,
        "nodes": [to_primitive(node) for node in graph.nodes],
        "edges": [to_primitive(edge) for edge in graph.edges],
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def _pairs(mapping) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(key), str(value)) for key, value in mapping.items()))


def _timestamp(value) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _normalized_source_sha256(source: AdvisoryImport) -> str:
    payload = {
        "input_name": source.input_name,
        "source": source.source,
        "source_format": source.source_format,
        "status": source.status,
        "message": source.message,
        "scope_status": source.scope_status,
        "scope_message": source.scope_message,
        "findings": to_primitive(source.findings),
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def _validate_node_authority(node: EvidenceGraphNode) -> None:
    if isinstance(node, PolicyDecisionNode):
        if node.authority != "RELEASE_AUTHORITY":
            raise ValueError("PolicyDecision graph node must carry release authority")
        return
    if node.authority == "RELEASE_AUTHORITY":
        raise ValueError("Only PolicyDecision graph nodes may carry release authority")
    if isinstance(node, AdvisoryContextNode) and node.gate_effect != "NONE":
        raise ValueError("Advisory context graph node must remain gate-neutral")
    if isinstance(node, AdvisoryExecutionNode) and node.gate_effect != "NONE":
        raise ValueError("Advisory execution graph node must remain gate-neutral")
    if isinstance(node, AdvisoryFindingNode) and node.gate_effect != "NONE":
        raise ValueError("Advisory finding graph node must remain gate-neutral")
