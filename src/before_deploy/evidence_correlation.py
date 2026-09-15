"""Deterministic correlation and exact deduplication over Evidence Graph identities."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from typing import Any

from before_deploy.advisory import UnifiedReviewResult
from before_deploy.evidence_graph import (
    AdvisoryFindingNode,
    DeterministicFindingNode,
    EvidenceGraph,
    EvidenceGraphNode,
    validate_evidence_graph,
)
from before_deploy.models import Location, to_primitive

EVIDENCE_CORRELATION_SCHEMA_VERSION = 1
EVIDENCE_CORRELATION_AUTHORITY = "CORRELATION_DIAGNOSTIC"
EVIDENCE_CORRELATION_GATE_EFFECT = "NONE"
CORRELATION_RELATION = "CORRELATES_WITH"
CORRELATION_BASIS_LOCATION_OVERLAP = "LOCATION_OVERLAP"
DEDUPLICATION_BASIS_EXACT_ADVISORY_FINGERPRINT = "EXACT_ADVISORY_FINGERPRINT"


@dataclass(frozen=True)
class EvidenceCorrelationEdge:
    """A diagnostic relation between stable graph finding identities."""

    correlation_id: str
    source_node_id: str
    relation: str
    target_node_id: str
    basis: str
    path: str
    overlap_start_line: int
    overlap_end_line: int
    authority: str = EVIDENCE_CORRELATION_AUTHORITY
    gate_effect: str = EVIDENCE_CORRELATION_GATE_EFFECT


@dataclass(frozen=True)
class AdvisoryDeduplicationGroup:
    """Exact repeated advisory claims collapsed only in the diagnostic unique view."""

    group_id: str
    fingerprint: str
    canonical_node_id: str
    member_node_ids: tuple[str, ...]
    occurrence_count: int
    basis: str = DEDUPLICATION_BASIS_EXACT_ADVISORY_FINGERPRINT
    authority: str = EVIDENCE_CORRELATION_AUTHORITY
    gate_effect: str = EVIDENCE_CORRELATION_GATE_EFFECT


@dataclass(frozen=True)
class EvidenceCorrelationResult:
    """Graph-bound correlation/deduplication result with no release authority."""

    schema_version: int
    graph_sha256: str
    correlation_sha256: str
    correlations: tuple[EvidenceCorrelationEdge, ...]
    unique_advisory_node_ids: tuple[str, ...]
    duplicate_groups: tuple[AdvisoryDeduplicationGroup, ...]
    authority: str = EVIDENCE_CORRELATION_AUTHORITY
    gate_effect: str = EVIDENCE_CORRELATION_GATE_EFFECT


def build_evidence_correlation(
    review: UnifiedReviewResult,
    graph: EvidenceGraph,
) -> EvidenceCorrelationResult:
    """Correlate by explicit location overlap and deduplicate only exact advisory fingerprints."""
    validate_evidence_graph(graph)

    deterministic_by_fingerprint: dict[str, tuple[DeterministicFindingNode, ...]] = {}
    advisory_by_fingerprint: dict[str, tuple[AdvisoryFindingNode, ...]] = {}
    for node in graph.nodes:
        if isinstance(node, DeterministicFindingNode):
            deterministic_by_fingerprint[node.fingerprint] = _append_sorted(
                deterministic_by_fingerprint.get(node.fingerprint, ()), node
            )
        elif isinstance(node, AdvisoryFindingNode):
            advisory_by_fingerprint[node.fingerprint] = _append_sorted(
                advisory_by_fingerprint.get(node.fingerprint, ()), node
            )

    occurrence_counts: dict[str, int] = {}
    for finding in review.advisory_findings:
        occurrence_counts[finding.fingerprint] = occurrence_counts.get(finding.fingerprint, 0) + 1

    canonical_by_fingerprint: dict[str, AdvisoryFindingNode] = {}
    duplicate_groups: list[AdvisoryDeduplicationGroup] = []
    for fingerprint, count in sorted(occurrence_counts.items()):
        candidates = advisory_by_fingerprint.get(fingerprint, ())
        if not candidates:
            raise ValueError(
                f"Evidence correlation could not resolve advisory fingerprint {fingerprint!r} in graph"
            )
        canonical = min(candidates, key=lambda item: item.node_id)
        canonical_by_fingerprint[fingerprint] = canonical
        member_ids = tuple(sorted(node.node_id for node in candidates))
        if count > 1 or len(member_ids) > 1:
            duplicate_groups.append(
                AdvisoryDeduplicationGroup(
                    group_id=_diagnostic_id(
                        "deduplication",
                        {
                            "fingerprint": fingerprint,
                            "canonical_node_id": canonical.node_id,
                            "member_node_ids": member_ids,
                            "occurrence_count": count,
                            "basis": DEDUPLICATION_BASIS_EXACT_ADVISORY_FINGERPRINT,
                        },
                    ),
                    fingerprint=fingerprint,
                    canonical_node_id=canonical.node_id,
                    member_node_ids=member_ids,
                    occurrence_count=count,
                )
            )

    correlation_keys: set[tuple[str, str]] = set()
    correlations: list[EvidenceCorrelationEdge] = []
    for item in review.correlations:
        advisory = canonical_by_fingerprint.get(item.advisory_fingerprint)
        if advisory is None or advisory.location is None:
            continue
        for deterministic_fingerprint in item.deterministic_fingerprints:
            deterministic_candidates = deterministic_by_fingerprint.get(deterministic_fingerprint, ())
            for deterministic in deterministic_candidates:
                overlap = _overlap(advisory.location, deterministic.location)
                if overlap is None:
                    continue
                key = (advisory.node_id, deterministic.node_id)
                if key in correlation_keys:
                    continue
                correlation_keys.add(key)
                path, start_line, end_line = overlap
                correlations.append(
                    EvidenceCorrelationEdge(
                        correlation_id=_diagnostic_id(
                            "correlation",
                            {
                                "source_node_id": advisory.node_id,
                                "relation": CORRELATION_RELATION,
                                "target_node_id": deterministic.node_id,
                                "basis": CORRELATION_BASIS_LOCATION_OVERLAP,
                                "path": path,
                                "overlap_start_line": start_line,
                                "overlap_end_line": end_line,
                            },
                        ),
                        source_node_id=advisory.node_id,
                        relation=CORRELATION_RELATION,
                        target_node_id=deterministic.node_id,
                        basis=CORRELATION_BASIS_LOCATION_OVERLAP,
                        path=path,
                        overlap_start_line=start_line,
                        overlap_end_line=end_line,
                    )
                )

    result = EvidenceCorrelationResult(
        schema_version=EVIDENCE_CORRELATION_SCHEMA_VERSION,
        graph_sha256=graph.graph_sha256,
        correlation_sha256="",
        correlations=tuple(sorted(correlations, key=lambda item: item.correlation_id)),
        unique_advisory_node_ids=tuple(
            sorted(node.node_id for node in canonical_by_fingerprint.values())
        ),
        duplicate_groups=tuple(sorted(duplicate_groups, key=lambda item: item.group_id)),
    )
    result = EvidenceCorrelationResult(
        schema_version=result.schema_version,
        graph_sha256=result.graph_sha256,
        correlation_sha256=_result_digest(result),
        correlations=result.correlations,
        unique_advisory_node_ids=result.unique_advisory_node_ids,
        duplicate_groups=result.duplicate_groups,
    )
    validate_evidence_correlation(result, graph)
    return result


def validate_evidence_correlation(result: EvidenceCorrelationResult, graph: EvidenceGraph) -> None:
    """Validate graph binding, endpoint types, exact-dedup semantics, and gate neutrality."""
    validate_evidence_graph(graph)
    if result.schema_version != EVIDENCE_CORRELATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence correlation schema version")
    if result.graph_sha256 != graph.graph_sha256:
        raise ValueError("Evidence correlation is bound to a different graph")
    if (
        result.authority != EVIDENCE_CORRELATION_AUTHORITY
        or result.gate_effect != EVIDENCE_CORRELATION_GATE_EFFECT
    ):
        raise ValueError("Evidence correlation must remain diagnostic and gate-neutral")

    by_id = {node.node_id: node for node in graph.nodes}
    if result.correlations != tuple(sorted(result.correlations, key=lambda item: item.correlation_id)):
        raise ValueError("Evidence correlations must be deterministically sorted")
    if len({item.correlation_id for item in result.correlations}) != len(result.correlations):
        raise ValueError("Evidence correlation IDs must be unique")

    for item in result.correlations:
        if item.authority != EVIDENCE_CORRELATION_AUTHORITY or item.gate_effect != "NONE":
            raise ValueError("Correlation edge must remain gate-neutral")
        if item.relation != CORRELATION_RELATION or item.basis != CORRELATION_BASIS_LOCATION_OVERLAP:
            raise ValueError("Unsupported evidence correlation relation or basis")
        source = by_id.get(item.source_node_id)
        target = by_id.get(item.target_node_id)
        if not isinstance(source, AdvisoryFindingNode) or not isinstance(
            target, DeterministicFindingNode
        ):
            raise ValueError("CORRELATES_WITH must connect advisory to deterministic findings")
        overlap = _overlap(source.location, target.location)
        if overlap != (item.path, item.overlap_start_line, item.overlap_end_line):
            raise ValueError("Evidence correlation overlap no longer matches graph locations")
        expected_id = _diagnostic_id(
            "correlation",
            {
                "source_node_id": item.source_node_id,
                "relation": item.relation,
                "target_node_id": item.target_node_id,
                "basis": item.basis,
                "path": item.path,
                "overlap_start_line": item.overlap_start_line,
                "overlap_end_line": item.overlap_end_line,
            },
        )
        if item.correlation_id != expected_id:
            raise ValueError("Evidence correlation ID does not match its canonical payload")

    if result.unique_advisory_node_ids != tuple(sorted(set(result.unique_advisory_node_ids))):
        raise ValueError("Unique advisory node IDs must be sorted and unique")
    for node_id in result.unique_advisory_node_ids:
        if not isinstance(by_id.get(node_id), AdvisoryFindingNode):
            raise ValueError("Unique advisory view references a non-advisory graph node")

    for group in result.duplicate_groups:
        if group.authority != EVIDENCE_CORRELATION_AUTHORITY or group.gate_effect != "NONE":
            raise ValueError("Advisory deduplication group must remain gate-neutral")
        if group.basis != DEDUPLICATION_BASIS_EXACT_ADVISORY_FINGERPRINT:
            raise ValueError("Unsupported advisory deduplication basis")
        if group.occurrence_count <= 1 and len(group.member_node_ids) <= 1:
            raise ValueError("Deduplication group does not contain a duplicate")
        if group.canonical_node_id != min(group.member_node_ids):
            raise ValueError("Deduplication canonical node must be lexicographically stable")
        members = [by_id.get(node_id) for node_id in group.member_node_ids]
        if not members or any(not isinstance(node, AdvisoryFindingNode) for node in members):
            raise ValueError("Deduplication group references a non-advisory node")
        if any(node.fingerprint != group.fingerprint for node in members if node is not None):
            raise ValueError("Deduplication may collapse only exact advisory fingerprints")
        expected_id = _diagnostic_id(
            "deduplication",
            {
                "fingerprint": group.fingerprint,
                "canonical_node_id": group.canonical_node_id,
                "member_node_ids": group.member_node_ids,
                "occurrence_count": group.occurrence_count,
                "basis": group.basis,
            },
        )
        if group.group_id != expected_id:
            raise ValueError("Deduplication group ID does not match its canonical payload")

    if result.correlation_sha256 != _result_digest(result):
        raise ValueError("Evidence correlation digest mismatch")


def evidence_correlation_to_primitive(result: EvidenceCorrelationResult) -> dict[str, Any]:
    """Serialize a validated correlation result without adding raw provider content."""
    return {
        "schema_version": result.schema_version,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "correlations": [to_primitive(item) for item in result.correlations],
        "unique_advisory_node_ids": list(result.unique_advisory_node_ids),
        "duplicate_groups": [to_primitive(item) for item in result.duplicate_groups],
    }


def _append_sorted(items: tuple[EvidenceGraphNode, ...], node: EvidenceGraphNode):
    return tuple(sorted((*items, node), key=lambda item: item.node_id))


def _overlap(
    left: Location | None,
    right: Location | None,
) -> tuple[str, int, int] | None:
    if left is None or right is None or left.path != right.path:
        return None
    if left.start_line is None or right.start_line is None:
        return None
    left_end = left.end_line or left.start_line
    right_end = right.end_line or right.start_line
    start = max(left.start_line, right.start_line)
    end = min(left_end, right_end)
    if start > end:
        return None
    return left.path, start, end


def _diagnostic_id(kind: str, payload: Any) -> str:
    serialized = dumps(
        {"kind": kind, "payload": to_primitive(payload)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"{kind}:{sha256(serialized.encode('utf-8')).hexdigest()}"


def _result_digest(result: EvidenceCorrelationResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "graph_sha256": result.graph_sha256,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "correlations": [to_primitive(item) for item in result.correlations],
        "unique_advisory_node_ids": list(result.unique_advisory_node_ids),
        "duplicate_groups": [to_primitive(item) for item in result.duplicate_groups],
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()
