"""Deterministic inspection of one persisted finding and its recorded evidence lineage."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from typing import Any

from before_deploy.evidence_artifact import ReviewEvidenceArtifact
from before_deploy.evidence_correlation import (
    AdvisoryDeduplicationGroup,
    EvidenceCorrelationEdge,
)
from before_deploy.evidence_corroboration import AdvisoryCorroborationAssessment
from before_deploy.evidence_graph import (
    AdvisoryFindingNode,
    DeterministicFindingNode,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    PolicyDecisionNode,
    PolicyInputNode,
    WaiverNode,
)
from before_deploy.models import Location, to_primitive

EVIDENCE_INSPECTION_SCHEMA_VERSION = 1
EVIDENCE_INSPECTION_AUTHORITY = "INSPECTION_DIAGNOSTIC"
EVIDENCE_INSPECTION_GATE_EFFECT = "NONE"

ROLE_SELECTED = "SELECTED"
ROLE_EXACT_CLAIM_MEMBER = "EXACT_CLAIM_MEMBER"
ROLE_CORRELATED_FINDING = "CORRELATED_FINDING"
ROLE_LINEAGE = "LINEAGE"
ROLE_WAIVER = "WAIVER"
ROLE_POLICY_DECISION = "POLICY_DECISION"
ROLE_POLICY_INPUT = "POLICY_INPUT"


@dataclass(frozen=True)
class InspectionNodeRecord:
    """One graph node included in an inspection trace."""

    node: EvidenceGraphNode
    roles: tuple[str, ...]
    depth: int


@dataclass(frozen=True)
class InspectionPolicyRelationship:
    """How one deterministic finding appears in the persisted policy decision."""

    decision_node_id: str
    deterministic_node_id: str
    fingerprint: str
    policy_role: str
    outcome: str


@dataclass(frozen=True)
class EvidenceInspectionResult:
    """Validated, graph-bound, non-authoritative inspection of one finding."""

    schema_version: int
    source_review_sha256: str
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    inspection_sha256: str
    selected_node_id: str
    nodes: tuple[InspectionNodeRecord, ...]
    edges: tuple[EvidenceGraphEdge, ...]
    correlations: tuple[EvidenceCorrelationEdge, ...]
    duplicate_groups: tuple[AdvisoryDeduplicationGroup, ...]
    corroboration_assessments: tuple[AdvisoryCorroborationAssessment, ...]
    policy_relationships: tuple[InspectionPolicyRelationship, ...]
    authority: str = EVIDENCE_INSPECTION_AUTHORITY
    gate_effect: str = EVIDENCE_INSPECTION_GATE_EFFECT


def build_evidence_inspection(
    artifact: ReviewEvidenceArtifact,
    selector: str,
) -> EvidenceInspectionResult:
    """Resolve one finding and expose only its validated recorded lineage and context."""
    selected = resolve_inspection_selector(artifact, selector)
    graph = artifact.graph
    by_id = {node.node_id: node for node in graph.nodes}

    roles: dict[str, set[str]] = {selected.node_id: {ROLE_SELECTED}}
    depths: dict[str, int] = {selected.node_id: 0}

    def include(node_id: str, role: str, depth: int) -> None:
        if node_id not in by_id:
            raise ValueError(f"Inspection references unknown graph node {node_id!r}")
        roles.setdefault(node_id, set()).add(role)
        depths[node_id] = min(depths.get(node_id, depth), depth)

    selected_advisory_ids = _claim_member_ids(selected, artifact)
    for node_id in selected_advisory_ids:
        if node_id != selected.node_id:
            include(node_id, ROLE_EXACT_CLAIM_MEMBER, 0)

    correlations = _relevant_correlations(selected, selected_advisory_ids, artifact)
    deterministic_ids: set[str] = set()
    advisory_ids: set[str] = set(selected_advisory_ids)
    if isinstance(selected, DeterministicFindingNode):
        deterministic_ids.add(selected.node_id)
    else:
        advisory_ids.add(selected.node_id)

    for item in correlations:
        advisory_ids.add(item.source_node_id)
        deterministic_ids.add(item.target_node_id)
        counterpart = (
            item.target_node_id
            if isinstance(selected, AdvisoryFindingNode)
            else item.source_node_id
        )
        include(counterpart, ROLE_CORRELATED_FINDING, 1)
        counterpart_node = by_id[counterpart]
        if isinstance(counterpart_node, AdvisoryFindingNode):
            for member_id in _claim_member_ids(counterpart_node, artifact):
                advisory_ids.add(member_id)
                if member_id != counterpart:
                    include(member_id, ROLE_EXACT_CLAIM_MEMBER, 1)

    provenance_starts = set(advisory_ids) | set(deterministic_ids)
    _include_upstream_lineage(graph.edges, by_id, provenance_starts, roles, depths)

    waiver_ids: set[str] = set()
    for edge in graph.edges:
        if edge.relation != "APPLIES_TO" or edge.target_id not in deterministic_ids:
            continue
        source = by_id[edge.source_id]
        if isinstance(source, WaiverNode):
            waiver_ids.add(source.node_id)
            include(source.node_id, ROLE_WAIVER, 1)

    policy_ids: set[str] = set()
    policy_targets = deterministic_ids | waiver_ids
    for edge in graph.edges:
        if edge.relation != "DERIVED_FROM" or edge.target_id not in policy_targets:
            continue
        source = by_id[edge.source_id]
        if isinstance(source, PolicyDecisionNode):
            policy_ids.add(source.node_id)
            include(source.node_id, ROLE_POLICY_DECISION, 1)

    for policy_id in policy_ids:
        for edge in graph.edges:
            if edge.source_id != policy_id or edge.relation != "DERIVED_FROM":
                continue
            target = by_id[edge.target_id]
            if isinstance(target, PolicyInputNode):
                include(target.node_id, ROLE_POLICY_INPUT, 2)

    included_ids = set(roles)
    edges = tuple(
        edge
        for edge in graph.edges
        if edge.source_id in included_ids and edge.target_id in included_ids
    )

    duplicate_groups = tuple(
        group
        for group in artifact.correlation.duplicate_groups
        if group.canonical_node_id in advisory_ids
        or any(node_id in advisory_ids for node_id in group.member_node_ids)
    )
    canonical_advisory_ids = {
        group.canonical_node_id for group in duplicate_groups
    } | {
        node_id
        for node_id in advisory_ids
        if node_id in artifact.correlation.unique_advisory_node_ids
    }
    corroboration_assessments = tuple(
        item
        for item in artifact.corroboration.assessments
        if item.advisory_node_id in canonical_advisory_ids
    )

    policy_relationships = tuple(
        sorted(
            (
                _policy_relationship(policy, deterministic)
                for policy_id in policy_ids
                for deterministic_id in deterministic_ids
                if isinstance((policy := by_id[policy_id]), PolicyDecisionNode)
                and isinstance((deterministic := by_id[deterministic_id]), DeterministicFindingNode)
            ),
            key=lambda item: (item.decision_node_id, item.deterministic_node_id),
        )
    )

    records = tuple(
        InspectionNodeRecord(
            node=by_id[node_id],
            roles=tuple(sorted(roles[node_id])),
            depth=depths[node_id],
        )
        for node_id in sorted(included_ids, key=lambda value: (depths[value], value))
    )
    provisional = EvidenceInspectionResult(
        schema_version=EVIDENCE_INSPECTION_SCHEMA_VERSION,
        source_review_sha256=artifact.source_review_sha256,
        graph_sha256=graph.graph_sha256,
        correlation_sha256=artifact.correlation.correlation_sha256,
        corroboration_sha256=artifact.corroboration.corroboration_sha256,
        inspection_sha256="",
        selected_node_id=selected.node_id,
        nodes=records,
        edges=edges,
        correlations=correlations,
        duplicate_groups=duplicate_groups,
        corroboration_assessments=corroboration_assessments,
        policy_relationships=policy_relationships,
    )
    result = EvidenceInspectionResult(
        **{
            **provisional.__dict__,
            "inspection_sha256": _inspection_digest(provisional),
        }
    )
    validate_evidence_inspection(result, artifact)
    return result


def resolve_inspection_selector(
    artifact: ReviewEvidenceArtifact,
    selector: str,
) -> EvidenceGraphNode:
    """Resolve exact node ID, exact finding fingerprint, or advisory finding ID."""
    if not selector:
        raise ValueError("Inspection selector must not be empty")
    findings = tuple(
        node
        for node in artifact.graph.nodes
        if isinstance(node, (DeterministicFindingNode, AdvisoryFindingNode))
    )
    by_id = {node.node_id: node for node in findings}
    if selector in by_id:
        return by_id[selector]

    candidates: dict[str, EvidenceGraphNode] = {}
    for node in findings:
        if node.fingerprint == selector:
            candidates[node.node_id] = node
        if isinstance(node, AdvisoryFindingNode) and node.finding_id == selector:
            candidates[node.node_id] = node
    if not candidates:
        raise ValueError(
            "Inspection selector did not match a finding node ID, fingerprint, or advisory finding ID"
        )
    if len(candidates) > 1:
        joined = ", ".join(sorted(candidates))
        raise ValueError(f"Inspection selector is ambiguous; matching node IDs: {joined}")
    return next(iter(candidates.values()))


def validate_evidence_inspection(
    result: EvidenceInspectionResult,
    artifact: ReviewEvidenceArtifact,
) -> None:
    """Validate upstream bindings, selected identity, and inspection gate neutrality."""
    if result.schema_version != EVIDENCE_INSPECTION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence inspection schema version")
    if result.authority != EVIDENCE_INSPECTION_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Evidence inspection must remain diagnostic and gate-neutral")
    if result.source_review_sha256 != artifact.source_review_sha256:
        raise ValueError("Evidence inspection is bound to a different review artifact")
    if result.graph_sha256 != artifact.graph.graph_sha256:
        raise ValueError("Evidence inspection is bound to a different evidence graph")
    if result.correlation_sha256 != artifact.correlation.correlation_sha256:
        raise ValueError("Evidence inspection is bound to a different correlation result")
    if result.corroboration_sha256 != artifact.corroboration.corroboration_sha256:
        raise ValueError("Evidence inspection is bound to a different corroboration result")

    node_ids = [record.node.node_id for record in result.nodes]
    if result.selected_node_id not in node_ids:
        raise ValueError("Evidence inspection does not contain its selected node")
    selected = next(record.node for record in result.nodes if record.node.node_id == result.selected_node_id)
    if not isinstance(selected, (DeterministicFindingNode, AdvisoryFindingNode)):
        raise ValueError("Evidence inspection selected node must be a finding")
    if any(record.depth < 0 for record in result.nodes):
        raise ValueError("Evidence inspection node depth cannot be negative")
    if any(not record.roles for record in result.nodes):
        raise ValueError("Every evidence inspection node must have at least one role")
    known = set(node_ids)
    if any(edge.source_id not in known or edge.target_id not in known for edge in result.edges):
        raise ValueError("Evidence inspection edge escapes the inspected node set")
    if any(item.gate_effect != "NONE" for item in result.correlations):
        raise ValueError("Inspection correlation context must remain gate-neutral")
    if any(item.gate_effect != "NONE" for item in result.corroboration_assessments):
        raise ValueError("Inspection corroboration context must remain gate-neutral")
    if result.inspection_sha256 != _inspection_digest(result):
        raise ValueError("Evidence inspection digest mismatch")


def evidence_inspection_to_primitive(result: EvidenceInspectionResult) -> dict[str, Any]:
    """Serialize an inspection without copying unrelated review-artifact fields."""
    selected = next(record.node for record in result.nodes if record.node.node_id == result.selected_node_id)
    return {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "inspection_sha256": result.inspection_sha256,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "authority_contract": {
            "inspection_authority": "diagnostic_only",
            "release_authority": "persisted_policy_decision_only",
            "correlation_semantics": "location_overlap_only",
            "corroboration_semantics": "exact_claim_provenance_only",
            "advisory_authority_promotion": "forbidden",
        },
        "selected_node_id": result.selected_node_id,
        "selected_node": to_primitive(selected),
        "nodes": [
            {
                "depth": record.depth,
                "roles": list(record.roles),
                "node": to_primitive(record.node),
            }
            for record in result.nodes
        ],
        "edges": [to_primitive(edge) for edge in result.edges],
        "correlations": [to_primitive(item) for item in result.correlations],
        "duplicate_groups": [to_primitive(item) for item in result.duplicate_groups],
        "corroboration_assessments": [
            to_primitive(item) for item in result.corroboration_assessments
        ],
        "policy_relationships": [to_primitive(item) for item in result.policy_relationships],
    }


def render_evidence_inspection_json(result: EvidenceInspectionResult) -> str:
    return dumps(
        evidence_inspection_to_primitive(result),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_evidence_inspection_markdown(result: EvidenceInspectionResult) -> str:
    selected_record = next(
        record for record in result.nodes if record.node.node_id == result.selected_node_id
    )
    selected = selected_record.node
    lines = [
        "# Before Deploy Evidence Inspection",
        "",
        f"- Selected node: `{selected.node_id}`",
        f"- Node type: `{selected.node_type}`",
        f"- Authority: `{selected.authority}`",
        f"- Inspection authority: `{result.authority}`",
        f"- Inspection gate effect: `{result.gate_effect}`",
        f"- Review artifact SHA-256: `{result.source_review_sha256}`",
        f"- Evidence graph SHA-256: `{result.graph_sha256}`",
        f"- Correlation SHA-256: `{result.correlation_sha256}`",
        f"- Corroboration SHA-256: `{result.corroboration_sha256}`",
        f"- Inspection SHA-256: `{result.inspection_sha256}`",
        "",
        "## Selected finding",
        "",
    ]
    lines.extend(_finding_markdown(selected))
    lines.extend(
        [
            "",
            "## Authority boundary",
            "",
            "Inspection is a deterministic read of persisted evidence. It does not rerun providers or policy.",
            "Only persisted `POLICY_DECISION` nodes carry release authority.",
            "Advisory correlation and corroboration remain diagnostic and cannot promote advisory authority.",
            "",
            "## Correlation context",
            "",
        ]
    )
    if result.correlations:
        for item in result.correlations:
            lines.append(
                f"- `{item.source_node_id}` **{item.relation}** `{item.target_node_id}` "
                f"at `{item.path}:{item.overlap_start_line}-{item.overlap_end_line}` "
                f"(basis `{item.basis}`)"
            )
        lines.append("- Location overlap is context only; it does not assert semantic equivalence.")
    else:
        lines.append("No graph-backed deterministic/advisory location correlation was recorded.")

    lines.extend(["", "## Corroboration context", ""])
    if result.corroboration_assessments:
        for item in result.corroboration_assessments:
            signals = ", ".join(f"`{value}`" for value in item.signals) or "none"
            lines.append(
                f"- `{item.advisory_node_id}`: status `{item.status}`, "
                f"occurrences **{item.occurrence_count}**, signals {signals}"
            )
            if item.provider_ids:
                lines.append("  - Providers: " + ", ".join(f"`{v}`" for v in item.provider_ids))
            if item.attested_model_identities:
                lines.append(
                    "  - Attested models: "
                    + ", ".join(f"`{v}`" for v in item.attested_model_identities)
                )
    else:
        lines.append("No advisory corroboration assessment applies to this inspection.")

    lines.extend(["", "## Policy context", ""])
    if result.policy_relationships:
        for item in result.policy_relationships:
            lines.append(
                f"- Deterministic finding `{item.deterministic_node_id}` is `{item.policy_role}` "
                f"in policy decision `{item.decision_node_id}` with outcome `{item.outcome}`."
            )
        if isinstance(selected, AdvisoryFindingNode):
            lines.append(
                "- The selected advisory finding itself is not a policy input; any policy context above belongs to correlated deterministic findings."
            )
    else:
        lines.append("No deterministic policy relationship applies to this inspection.")

    lines.extend(["", "## Traceable lineage", ""])
    for record in result.nodes:
        role_text = ", ".join(record.roles)
        lines.append(
            f"- depth **{record.depth}** — `{record.node.node_type}` `{record.node.node_id}` "
            f"— roles `{role_text}` — authority `{record.node.authority}`"
        )
    lines.extend(["", "## Recorded edges", ""])
    if result.edges:
        for edge in result.edges:
            lines.append(f"- `{edge.source_id}` **{edge.relation}** `{edge.target_id}`")
    else:
        lines.append("No graph edges are part of this inspection trace.")
    return "\n".join(lines).rstrip() + "\n"


def render_evidence_inspection_terminal(result: EvidenceInspectionResult) -> str:
    selected = next(record.node for record in result.nodes if record.node.node_id == result.selected_node_id)
    lines = [
        f"Before Deploy inspect: {selected.node_type}",
        f"Node: {selected.node_id}",
        f"Authority: {selected.authority}; inspection={result.authority}, gate_effect={result.gate_effect}",
    ]
    fingerprint = getattr(selected, "fingerprint", None)
    if fingerprint:
        lines.append(f"Fingerprint: {fingerprint}")
    location = getattr(selected, "location", None)
    if location is not None:
        lines.append(f"Location: {_location_text(location)}")
    lines.append(
        f"Trace: nodes={len(result.nodes)}, edges={len(result.edges)}, correlations={len(result.correlations)}"
    )
    if result.corroboration_assessments:
        statuses = ", ".join(sorted({item.status for item in result.corroboration_assessments}))
        lines.append(f"Corroboration: {statuses}")
    if result.policy_relationships:
        relationships = ", ".join(
            sorted({f"{item.policy_role}@{item.outcome}" for item in result.policy_relationships})
        )
        lines.append(f"Policy context: {relationships}")
    lines.append(f"Inspection SHA-256: {result.inspection_sha256}")
    return "\n".join(lines) + "\n"


def _claim_member_ids(
    node: EvidenceGraphNode,
    artifact: ReviewEvidenceArtifact,
) -> set[str]:
    if not isinstance(node, AdvisoryFindingNode):
        return set()
    for group in artifact.correlation.duplicate_groups:
        if node.node_id == group.canonical_node_id or node.node_id in group.member_node_ids:
            return set(group.member_node_ids) | {group.canonical_node_id}
    return {node.node_id}


def _relevant_correlations(
    selected: EvidenceGraphNode,
    selected_advisory_ids: set[str],
    artifact: ReviewEvidenceArtifact,
) -> tuple[EvidenceCorrelationEdge, ...]:
    if isinstance(selected, AdvisoryFindingNode):
        canonical_ids = set(selected_advisory_ids)
        for group in artifact.correlation.duplicate_groups:
            if selected.node_id == group.canonical_node_id or selected.node_id in group.member_node_ids:
                canonical_ids.add(group.canonical_node_id)
        return tuple(
            item for item in artifact.correlation.correlations if item.source_node_id in canonical_ids
        )
    return tuple(
        item
        for item in artifact.correlation.correlations
        if item.target_node_id == selected.node_id
    )


def _include_upstream_lineage(
    edges: tuple[EvidenceGraphEdge, ...],
    by_id: dict[str, EvidenceGraphNode],
    starts: set[str],
    roles: dict[str, set[str]],
    depths: dict[str, int],
) -> None:
    queue = [(node_id, depths.get(node_id, 1)) for node_id in sorted(starts)]
    visited: set[str] = set()
    while queue:
        node_id, depth = queue.pop(0)
        if node_id in visited:
            continue
        visited.add(node_id)
        for edge in edges:
            if edge.source_id != node_id:
                continue
            target = by_id[edge.target_id]
            if isinstance(target, PolicyDecisionNode):
                continue
            roles.setdefault(target.node_id, set()).add(ROLE_LINEAGE)
            target_depth = depth + 1
            depths[target.node_id] = min(depths.get(target.node_id, target_depth), target_depth)
            queue.append((target.node_id, target_depth))


def _policy_relationship(
    decision: PolicyDecisionNode,
    finding: DeterministicFindingNode,
) -> InspectionPolicyRelationship:
    fingerprint = finding.fingerprint
    if fingerprint in decision.blocking_fingerprints:
        role = "BLOCKING"
    elif fingerprint in decision.waiver_required_fingerprints:
        role = "WAIVER_REQUIRED"
    elif fingerprint in decision.waived_fingerprints:
        role = "WAIVED"
    elif fingerprint in decision.advisory_fingerprints:
        role = "ADVISORY"
    else:
        role = "EVALUATED"
    return InspectionPolicyRelationship(
        decision_node_id=decision.node_id,
        deterministic_node_id=finding.node_id,
        fingerprint=fingerprint,
        policy_role=role,
        outcome=decision.outcome,
    )


def _finding_markdown(node: EvidenceGraphNode) -> list[str]:
    if isinstance(node, DeterministicFindingNode):
        lines = [
            f"- Title: {node.title}",
            f"- Fingerprint: `{node.fingerprint}`",
            f"- Rule: `{node.rule_id}@{node.rule_version}`",
            f"- Severity: `{node.severity}`",
            f"- Confidence: `{node.confidence}`",
        ]
        if node.location is not None:
            lines.append(f"- Location: `{_location_text(node.location)}`")
        lines.extend(["", node.message, "", f"Remediation: {node.remediation}"])
        return lines
    if isinstance(node, AdvisoryFindingNode):
        lines = [
            f"- Title: {node.title}",
            f"- Finding ID: `{node.finding_id}`",
            f"- Fingerprint: `{node.fingerprint}`",
            f"- Source: `{node.source}`",
            f"- Category: `{node.category}`",
            f"- Severity: `{node.severity}`",
            f"- Provider confidence: `{node.confidence or 'UNREPORTED'}`",
            f"- Gate effect: `{node.gate_effect}`",
        ]
        if node.location is not None:
            lines.append(f"- Location: `{_location_text(node.location)}`")
        lines.extend(["", "Advisory message (untrusted content):", "", node.message])
        return lines
    return [f"- Node type: `{node.node_type}`"]


def _location_text(location: Location) -> str:
    if location.start_line is None:
        return location.path
    if location.end_line is None or location.end_line == location.start_line:
        return f"{location.path}:{location.start_line}"
    return f"{location.path}:{location.start_line}-{location.end_line}"


def _inspection_digest(result: EvidenceInspectionResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "selected_node_id": result.selected_node_id,
        "nodes": [
            {
                "node": to_primitive(record.node),
                "roles": list(record.roles),
                "depth": record.depth,
            }
            for record in result.nodes
        ],
        "edges": [to_primitive(edge) for edge in result.edges],
        "correlations": [to_primitive(item) for item in result.correlations],
        "duplicate_groups": [to_primitive(item) for item in result.duplicate_groups],
        "corroboration_assessments": [
            to_primitive(item) for item in result.corroboration_assessments
        ],
        "policy_relationships": [to_primitive(item) for item in result.policy_relationships],
        "authority": result.authority,
        "gate_effect": result.gate_effect,
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()
