"""Load persisted review evidence back into the typed diagnostic models."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, loads
from pathlib import Path
from typing import Any, Mapping

from before_deploy.evidence_correlation import (
    AdvisoryDeduplicationGroup,
    EvidenceCorrelationEdge,
    EvidenceCorrelationResult,
    validate_evidence_correlation,
)
from before_deploy.evidence_corroboration import (
    AdvisoryCorroborationAssessment,
    EvidenceCorroborationResult,
    validate_evidence_corroboration,
)
from before_deploy.evidence_graph import (
    AdvisoryContextNode,
    AdvisoryExecutionNode,
    AdvisoryFindingNode,
    ControlExecutionNode,
    DeterministicFindingNode,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    NormalizedAdvisoryOutputNode,
    ObservationNode,
    PolicyDecisionNode,
    PolicyInputNode,
    RawArtifactNode,
    RepositorySnapshotNode,
    WaiverNode,
    validate_evidence_graph,
)
from before_deploy.models import Location

REVIEW_ARTIFACT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ReviewEvidenceArtifact:
    """Validated evidence sections from one persisted review.json artifact."""

    source_review_sha256: str
    graph: EvidenceGraph
    correlation: EvidenceCorrelationResult
    corroboration: EvidenceCorroborationResult


def load_review_evidence(path: Path) -> ReviewEvidenceArtifact:
    """Load and fully validate persisted graph/correlation/corroboration evidence."""
    raw = path.read_bytes()
    try:
        payload = loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, JSONDecodeError) as error:
        raise ValueError("Review artifact is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Review artifact root must be a JSON object")
    if payload.get("schema_version") != REVIEW_ARTIFACT_SCHEMA_VERSION:
        raise ValueError("Unsupported review artifact schema version")

    try:
        graph = _graph_from_primitive(_mapping(payload, "evidence_graph"))
        correlation = _correlation_from_primitive(
            _mapping(payload, "evidence_correlation"),
            graph,
        )
        corroboration = _corroboration_from_primitive(
            _mapping(payload, "evidence_corroboration"),
            graph,
            correlation,
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith("Review evidence"):
            raise
        raise ValueError(f"Review evidence artifact failed validation: {error}") from error

    return ReviewEvidenceArtifact(
        source_review_sha256=sha256(raw).hexdigest(),
        graph=graph,
        correlation=correlation,
        corroboration=corroboration,
    )


def _graph_from_primitive(raw: Mapping[str, Any]) -> EvidenceGraph:
    nodes_raw = _list(raw, "nodes")
    edges_raw = _list(raw, "edges")
    graph = EvidenceGraph(
        schema_version=raw["schema_version"],
        graph_sha256=raw["graph_sha256"],
        nodes=tuple(_node_from_primitive(_as_mapping(item, "graph node")) for item in nodes_raw),
        edges=tuple(
            EvidenceGraphEdge(
                source_id=item["source_id"],
                relation=item["relation"],
                target_id=item["target_id"],
            )
            for item in (_as_mapping(value, "graph edge") for value in edges_raw)
        ),
        authority=raw.get("authority", ""),
        gate_effect=raw.get("gate_effect", ""),
    )
    validate_evidence_graph(graph)
    return graph


def _node_from_primitive(raw: Mapping[str, Any]) -> EvidenceGraphNode:
    base = {
        "node_id": raw["node_id"],
        "payload_sha256": raw["payload_sha256"],
        "node_type": raw["node_type"],
        "authority": raw["authority"],
    }
    node_type = raw["node_type"]
    if node_type == "REPOSITORY_SNAPSHOT":
        return RepositorySnapshotNode(
            **base,
            repository_digest=raw["repository_digest"],
            git_revision=raw.get("git_revision"),
            scanned_file_count=raw["scanned_file_count"],
            excluded_file_count=raw["excluded_file_count"],
            limitations=_strings(raw.get("limitations", []), "limitations"),
        )
    if node_type == "POLICY_INPUT":
        return PolicyInputNode(
            **base,
            policy_name=raw["policy_name"],
            policy_digest=raw["policy_digest"],
        )
    if node_type == "OBSERVATION":
        return ObservationNode(
            **base,
            signal_id=raw["signal_id"],
            signal_version=raw["signal_version"],
            kind=raw["kind"],
            title=raw["title"],
            location=_location(raw["location"]),
            metadata=_pairs(raw.get("metadata", []), "metadata"),
        )
    if node_type == "CONTROL_EXECUTION":
        return ControlExecutionNode(
            **base,
            control_id=raw["control_id"],
            control_version=raw["control_version"],
            status=raw["status"],
            applicable=raw["applicable"],
            started_at=raw["started_at"],
            completed_at=raw["completed_at"],
            message=raw.get("message"),
            metadata=_pairs(raw.get("metadata", []), "metadata"),
        )
    if node_type == "DETERMINISTIC_FINDING":
        return DeterministicFindingNode(
            **base,
            fingerprint=raw["fingerprint"],
            rule_id=raw["rule_id"],
            rule_version=raw["rule_version"],
            title=raw["title"],
            message=raw["message"],
            remediation=raw["remediation"],
            severity=raw["severity"],
            confidence=raw["confidence"],
            location=_optional_location(raw.get("location")),
            evidence=_pairs(raw.get("evidence", []), "evidence"),
            disposition=raw.get("disposition"),
        )
    if node_type == "WAIVER":
        return WaiverNode(
            **base,
            waiver_id=raw["waiver_id"],
            finding_fingerprint=raw["finding_fingerprint"],
            rule_id=raw["rule_id"],
            repository_digest=raw["repository_digest"],
            approved_by=raw["approved_by"],
            justification=raw["justification"],
            compensating_controls=raw["compensating_controls"],
            expires_at=raw["expires_at"],
        )
    if node_type == "POLICY_DECISION":
        return PolicyDecisionNode(
            **base,
            outcome=raw["outcome"],
            reason_codes=_strings(raw.get("reason_codes", []), "reason_codes"),
            blocking_fingerprints=_strings(
                raw.get("blocking_fingerprints", []), "blocking_fingerprints"
            ),
            waiver_required_fingerprints=_strings(
                raw.get("waiver_required_fingerprints", []),
                "waiver_required_fingerprints",
            ),
            waived_fingerprints=_strings(raw.get("waived_fingerprints", []), "waived_fingerprints"),
            advisory_fingerprints=_strings(
                raw.get("advisory_fingerprints", []), "advisory_fingerprints"
            ),
            error_control_ids=_strings(raw.get("error_control_ids", []), "error_control_ids"),
        )
    if node_type == "ADVISORY_CONTEXT":
        return AdvisoryContextNode(
            **base,
            context_sha256=raw["context_sha256"],
            selected_file_count=raw["selected_file_count"],
            selected_bytes=raw["selected_bytes"],
            gate_effect=raw["gate_effect"],
        )
    if node_type == "ADVISORY_EXECUTION":
        return AdvisoryExecutionNode(
            **base,
            provider_id=raw["provider_id"],
            implementation=raw["implementation"],
            implementation_version=raw.get("implementation_version"),
            model_status=raw["model_status"],
            model_provider=raw.get("model_provider"),
            model_name=raw.get("model_name"),
            configuration_sha256=raw["configuration_sha256"],
            budgets=_triples(raw.get("budgets", []), "budgets"),
            started_at=raw["started_at"],
            completed_at=raw["completed_at"],
            duration_ms=raw["duration_ms"],
            normalized_output_sha256=raw["normalized_output_sha256"],
            result_status=raw["result_status"],
            gate_effect=raw["gate_effect"],
        )
    if node_type == "RAW_ADVISORY_ARTIFACT":
        return RawArtifactNode(
            **base,
            artifact_sha256=raw["artifact_sha256"],
            size_bytes=raw["size_bytes"],
            media_type=raw["media_type"],
            schema=raw.get("schema"),
        )
    if node_type == "NORMALIZED_ADVISORY_OUTPUT":
        return NormalizedAdvisoryOutputNode(
            **base,
            normalized_output_sha256=raw["normalized_output_sha256"],
            input_name=raw["input_name"],
            source=raw["source"],
            source_format=raw["source_format"],
            status=raw["status"],
            finding_count=raw["finding_count"],
        )
    if node_type == "ADVISORY_FINDING":
        return AdvisoryFindingNode(
            **base,
            fingerprint=raw["fingerprint"],
            finding_id=raw["finding_id"],
            source=raw["source"],
            title=raw["title"],
            message=raw["message"],
            category=raw["category"],
            severity=raw["severity"],
            confidence=raw.get("confidence"),
            location=_optional_location(raw.get("location")),
            gate_effect=raw["gate_effect"],
        )
    raise ValueError(f"Review evidence contains unsupported graph node type: {node_type!r}")


def _correlation_from_primitive(
    raw: Mapping[str, Any],
    graph: EvidenceGraph,
) -> EvidenceCorrelationResult:
    correlations = tuple(
        EvidenceCorrelationEdge(
            correlation_id=item["correlation_id"],
            source_node_id=item["source_node_id"],
            relation=item["relation"],
            target_node_id=item["target_node_id"],
            basis=item["basis"],
            path=item["path"],
            overlap_start_line=item["overlap_start_line"],
            overlap_end_line=item["overlap_end_line"],
            authority=item.get("authority", ""),
            gate_effect=item.get("gate_effect", ""),
        )
        for item in (
            _as_mapping(value, "correlation") for value in _list(raw, "correlations")
        )
    )
    duplicate_groups = tuple(
        AdvisoryDeduplicationGroup(
            group_id=item["group_id"],
            fingerprint=item["fingerprint"],
            canonical_node_id=item["canonical_node_id"],
            member_node_ids=_strings(item.get("member_node_ids", []), "member_node_ids"),
            occurrence_count=item["occurrence_count"],
            basis=item.get("basis", ""),
            authority=item.get("authority", ""),
            gate_effect=item.get("gate_effect", ""),
        )
        for item in (
            _as_mapping(value, "deduplication group")
            for value in _list(raw, "duplicate_groups")
        )
    )
    result = EvidenceCorrelationResult(
        schema_version=raw["schema_version"],
        graph_sha256=raw["graph_sha256"],
        correlation_sha256=raw["correlation_sha256"],
        correlations=correlations,
        unique_advisory_node_ids=_strings(
            raw.get("unique_advisory_node_ids", []), "unique_advisory_node_ids"
        ),
        duplicate_groups=duplicate_groups,
        authority=raw.get("authority", ""),
        gate_effect=raw.get("gate_effect", ""),
    )
    validate_evidence_correlation(result, graph)
    return result


def _corroboration_from_primitive(
    raw: Mapping[str, Any],
    graph: EvidenceGraph,
    correlation: EvidenceCorrelationResult,
) -> EvidenceCorroborationResult:
    assessments = tuple(
        AdvisoryCorroborationAssessment(
            assessment_id=item["assessment_id"],
            advisory_node_id=item["advisory_node_id"],
            status=item["status"],
            signals=_strings(item.get("signals", []), "signals"),
            occurrence_count=item["occurrence_count"],
            claim_member_node_ids=_strings(
                item.get("claim_member_node_ids", []), "claim_member_node_ids"
            ),
            normalized_output_node_ids=_strings(
                item.get("normalized_output_node_ids", []), "normalized_output_node_ids"
            ),
            execution_node_ids=_strings(
                item.get("execution_node_ids", []), "execution_node_ids"
            ),
            provider_ids=_strings(item.get("provider_ids", []), "provider_ids"),
            attested_model_identities=_strings(
                item.get("attested_model_identities", []), "attested_model_identities"
            ),
            deterministic_colocation_node_ids=_strings(
                item.get("deterministic_colocation_node_ids", []),
                "deterministic_colocation_node_ids",
            ),
            authority=item.get("authority", ""),
            gate_effect=item.get("gate_effect", ""),
        )
        for item in (
            _as_mapping(value, "corroboration assessment")
            for value in _list(raw, "assessments")
        )
    )
    result = EvidenceCorroborationResult(
        schema_version=raw["schema_version"],
        graph_sha256=raw["graph_sha256"],
        correlation_sha256=raw["correlation_sha256"],
        corroboration_sha256=raw["corroboration_sha256"],
        assessments=assessments,
        authority=raw.get("authority", ""),
        gate_effect=raw.get("gate_effect", ""),
    )
    validate_evidence_corroboration(result, graph, correlation)
    return result


def _mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    if key not in payload:
        raise ValueError(f"Review evidence artifact is missing {key!r}")
    return _as_mapping(payload[key], key)


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Review evidence {label} must be a JSON object")
    return value


def _list(payload: Mapping[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ValueError(f"Review evidence field {key!r} must be a JSON array")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Review evidence {label} must be an array of strings")
    return tuple(value)


def _pairs(value: Any, label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise ValueError(f"Review evidence {label} must be an array")
    result: list[tuple[str, str]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            raise ValueError(f"Review evidence {label} contains an invalid key/value pair")
        result.append((item[0], item[1]))
    return tuple(result)


def _triples(value: Any, label: str) -> tuple[tuple[str, int, str], ...]:
    if not isinstance(value, list):
        raise ValueError(f"Review evidence {label} must be an array")
    result: list[tuple[str, int, str]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 3
            or not isinstance(item[0], str)
            or not isinstance(item[1], int)
            or not isinstance(item[2], str)
        ):
            raise ValueError(f"Review evidence {label} contains an invalid budget tuple")
        result.append((item[0], item[1], item[2]))
    return tuple(result)


def _optional_location(value: Any) -> Location | None:
    if value is None:
        return None
    return _location(value)


def _location(value: Any) -> Location:
    raw = _as_mapping(value, "location")
    path = raw.get("path")
    start = raw.get("start_line")
    end = raw.get("end_line")
    if not isinstance(path, str):
        raise ValueError("Review evidence location path must be a string")
    if start is not None and not isinstance(start, int):
        raise ValueError("Review evidence location start_line must be an integer or null")
    if end is not None and not isinstance(end, int):
        raise ValueError("Review evidence location end_line must be an integer or null")
    return Location(path=path, start_line=start, end_line=end)
