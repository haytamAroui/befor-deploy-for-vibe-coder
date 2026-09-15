"""Deterministic provenance graph and gate-neutral assurance-case summaries."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from typing import Mapping, Sequence

from before_deploy.advisory import ADVISORY_GATE_EFFECT, AdvisoryFinding
from before_deploy.evidence_challenge import (
    VERDICT_CONTRADICTED,
    VERDICT_INSUFFICIENT,
    VERDICT_SUPPORTED,
    VERDICT_UNRESOLVED,
    EvidenceChallengeAssessment,
)

ASSURANCE_CASE_SCHEMA = "before-deploy-assurance-case-v1"
ASSURANCE_CASE_AUTHORITY = "ASSURANCE_CASE_ADVISORY"
ASSURANCE_CASE_GATE_EFFECT = "NONE"

ORIGIN_INITIAL = "INITIAL"
ORIGIN_EXPANDED = "EXPANDED"
_ALLOWED_ORIGINS = {ORIGIN_INITIAL, ORIGIN_EXPANDED}

POSTURE_UNCHALLENGED = "UNCHALLENGED"
POSTURE_CHALLENGE_SUPPORTED = "CHALLENGE_SUPPORTED"
POSTURE_EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
POSTURE_CLAIM_CONTRADICTED = "CLAIM_CONTRADICTED"
POSTURE_UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class AssuranceEvidence:
    evidence_id: str
    content_sha256: str
    origin: str
    producer: str | None = None


@dataclass(frozen=True)
class InvestigationStepDraft:
    action: str
    input_evidence_ids: tuple[str, ...]
    output_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationStep:
    step_id: str
    action: str
    input_evidence_ids: tuple[str, ...]
    output_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class AssuranceNode:
    node_id: str
    kind: str
    reference: str
    content_sha256: str | None = None
    origin: str | None = None


@dataclass(frozen=True)
class AssuranceEdge:
    edge_id: str
    source_node_id: str
    relation: str
    target_node_id: str


@dataclass(frozen=True)
class AssuranceCase:
    case_id: str
    finding_id: str
    finding_fingerprint: str
    posture: str
    nodes: tuple[AssuranceNode, ...]
    edges: tuple[AssuranceEdge, ...]
    investigation_steps: tuple[InvestigationStep, ...]
    challenge_id: str | None = None
    challenge_verdict: str | None = None
    schema_version: str = ASSURANCE_CASE_SCHEMA
    authority: str = ASSURANCE_CASE_AUTHORITY
    gate_effect: str = ASSURANCE_CASE_GATE_EFFECT


def build_assurance_case(
    *,
    finding: AdvisoryFinding,
    evidence: Sequence[AssuranceEvidence],
    investigation_steps: Sequence[InvestigationStepDraft] = (),
    challenge: EvidenceChallengeAssessment | None = None,
) -> AssuranceCase:
    """Build a stable graph from already-bounded finding, investigation and challenge records."""
    if finding.gate_effect != ADVISORY_GATE_EFFECT:
        raise ValueError("Assurance Case accepts gate-neutral advisory findings only")
    if not finding.finding_id.strip() or not finding.fingerprint.strip():
        raise ValueError("Assurance Case finding identity must be non-empty")

    normalized_evidence = _normalize_evidence(evidence)
    evidence_by_id = {item.evidence_id: item for item in normalized_evidence}
    steps = tuple(_normalize_step(item, evidence_by_id) for item in investigation_steps)

    if challenge is not None:
        _validate_challenge(finding, challenge, evidence_by_id)

    nodes: list[AssuranceNode] = [
        AssuranceNode(
            node_id=_node_id("FINDING", finding.fingerprint),
            kind="FINDING",
            reference=finding.fingerprint,
        )
    ]
    finding_node = nodes[0].node_id
    for item in normalized_evidence:
        nodes.append(
            AssuranceNode(
                node_id=_node_id("EVIDENCE", item.evidence_id),
                kind="EVIDENCE",
                reference=item.evidence_id,
                content_sha256=item.content_sha256,
                origin=item.origin,
            )
        )
    for step in steps:
        nodes.append(
            AssuranceNode(
                node_id=_node_id("INVESTIGATION", step.step_id),
                kind="INVESTIGATION",
                reference=step.step_id,
            )
        )

    edges: list[AssuranceEdge] = []
    for item in normalized_evidence:
        edges.append(
            _edge(
                finding_node,
                "HAS_EVIDENCE",
                _node_id("EVIDENCE", item.evidence_id),
            )
        )
    for step in steps:
        step_node = _node_id("INVESTIGATION", step.step_id)
        for evidence_id in step.input_evidence_ids:
            edges.append(_edge(step_node, "READS", _node_id("EVIDENCE", evidence_id)))
        for evidence_id in step.output_evidence_ids:
            edges.append(_edge(step_node, "PRODUCES", _node_id("EVIDENCE", evidence_id)))

    challenge_id: str | None = None
    challenge_verdict: str | None = None
    if challenge is not None:
        challenge_id = challenge.challenge_id
        challenge_verdict = challenge.verdict
        challenge_node = _node_id("CHALLENGE", challenge.challenge_id)
        nodes.append(
            AssuranceNode(
                node_id=challenge_node,
                kind="CHALLENGE",
                reference=challenge.challenge_id,
            )
        )
        edges.append(_edge(challenge_node, "CHALLENGES", finding_node))
        for cited in challenge.evidence:
            edges.append(
                _edge(challenge_node, "CITES", _node_id("EVIDENCE", cited.evidence_id))
            )
        for objection in challenge.objections:
            objection_node = _node_id("OBJECTION", objection.objection_id)
            nodes.append(
                AssuranceNode(
                    node_id=objection_node,
                    kind="OBJECTION",
                    reference=objection.objection_id,
                )
            )
            edges.append(_edge(objection_node, "PART_OF", challenge_node))
            for evidence_id in objection.evidence_ids:
                edges.append(
                    _edge(objection_node, "CITES", _node_id("EVIDENCE", evidence_id))
                )

    nodes_tuple = tuple(sorted(nodes, key=lambda item: item.node_id))
    edges_tuple = tuple(sorted(_dedupe_edges(edges), key=lambda item: item.edge_id))
    posture = _posture(challenge)
    payload = {
        "finding_fingerprint": finding.fingerprint,
        "posture": posture,
        "nodes": [_node_payload(item) for item in nodes_tuple],
        "edges": [_edge_payload(item) for item in edges_tuple],
        "investigation_steps": [_step_payload(item) for item in steps],
        "challenge_id": challenge_id,
        "challenge_verdict": challenge_verdict,
    }
    return AssuranceCase(
        case_id=f"AC-{_digest(payload)[:16]}",
        finding_id=finding.finding_id,
        finding_fingerprint=finding.fingerprint,
        posture=posture,
        nodes=nodes_tuple,
        edges=edges_tuple,
        investigation_steps=steps,
        challenge_id=challenge_id,
        challenge_verdict=challenge_verdict,
    )


def render_assurance_case_json(result: AssuranceCase) -> str:
    payload = {
        "schema_version": result.schema_version,
        "assurance_case": {
            "case_id": result.case_id,
            "finding_id": result.finding_id,
            "finding_fingerprint": result.finding_fingerprint,
            "posture": result.posture,
            "challenge_id": result.challenge_id,
            "challenge_verdict": result.challenge_verdict,
            "authority": result.authority,
            "gate_effect": result.gate_effect,
            "nodes": [_node_payload(item) for item in result.nodes],
            "edges": [_edge_payload(item) for item in result.edges],
            "investigation_steps": [_step_payload(item) for item in result.investigation_steps],
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_assurance_case_markdown(result: AssuranceCase) -> str:
    lines = [
        "# Assurance Case",
        "",
        f"- Case: `{result.case_id}`",
        f"- Finding: `{result.finding_id}` / `{result.finding_fingerprint}`",
        f"- Posture: **{result.posture}**",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        "- Release authority: **none**; this graph is diagnostic provenance only.",
        "",
        "## Trace",
        "",
        f"- Nodes: **{len(result.nodes)}**",
        f"- Edges: **{len(result.edges)}**",
        f"- Investigation steps: **{len(result.investigation_steps)}**",
    ]
    if result.challenge_id is not None:
        lines.append(
            f"- Challenge: `{result.challenge_id}` → **{result.challenge_verdict}**"
        )
    return "\n".join(lines) + "\n"


def _normalize_evidence(values: Sequence[AssuranceEvidence]) -> tuple[AssuranceEvidence, ...]:
    if isinstance(values, (str, bytes)) or not values:
        raise ValueError("Assurance Case requires evidence")
    result: list[AssuranceEvidence] = []
    seen: set[str] = set()
    for item in values:
        evidence_id = _text(item.evidence_id, "evidence id", 500)
        if evidence_id in seen:
            raise ValueError("Duplicate Assurance Case evidence id")
        seen.add(evidence_id)
        digest = _sha256_text(item.content_sha256)
        origin = _text(item.origin, "evidence origin", 100).upper()
        if origin not in _ALLOWED_ORIGINS:
            raise ValueError(f"Unsupported Assurance Case evidence origin: {origin}")
        producer = _optional_text(item.producer, "evidence producer", 500)
        result.append(
            AssuranceEvidence(
                evidence_id=evidence_id,
                content_sha256=digest,
                origin=origin,
                producer=producer,
            )
        )
    return tuple(sorted(result, key=lambda item: item.evidence_id))


def _normalize_step(
    draft: InvestigationStepDraft,
    available: Mapping[str, AssuranceEvidence],
) -> InvestigationStep:
    action = _text(draft.action, "investigation action", 500)
    inputs = _ids(draft.input_evidence_ids, available, "investigation input")
    outputs = _ids(draft.output_evidence_ids, available, "investigation output")
    if not outputs:
        raise ValueError("Investigation step requires at least one output evidence id")
    payload = {"action": action, "inputs": list(inputs), "outputs": list(outputs)}
    return InvestigationStep(
        step_id=f"INV-{_digest(payload)[:16]}",
        action=action,
        input_evidence_ids=inputs,
        output_evidence_ids=outputs,
    )


def _validate_challenge(
    finding: AdvisoryFinding,
    challenge: EvidenceChallengeAssessment,
    available: Mapping[str, AssuranceEvidence],
) -> None:
    if challenge.gate_effect != ASSURANCE_CASE_GATE_EFFECT:
        raise ValueError("Assurance Case challenge must remain gate-neutral")
    if challenge.finding_fingerprint != finding.fingerprint:
        raise ValueError("Assurance Case challenge targets another finding")
    for cited in challenge.evidence:
        item = available.get(cited.evidence_id)
        if item is None:
            raise ValueError("Assurance Case challenge cites evidence outside the graph")
        if item.content_sha256 != cited.content_sha256:
            raise ValueError("Assurance Case challenge evidence hash mismatch")


def _posture(challenge: EvidenceChallengeAssessment | None) -> str:
    if challenge is None:
        return POSTURE_UNCHALLENGED
    return {
        VERDICT_SUPPORTED: POSTURE_CHALLENGE_SUPPORTED,
        VERDICT_INSUFFICIENT: POSTURE_EVIDENCE_INSUFFICIENT,
        VERDICT_CONTRADICTED: POSTURE_CLAIM_CONTRADICTED,
        VERDICT_UNRESOLVED: POSTURE_UNRESOLVED,
    }[challenge.verdict]


def _ids(
    values: Sequence[str],
    available: Mapping[str, AssuranceEvidence],
    label: str,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{label} ids must be a sequence")
    ids = tuple(sorted({_text(item, f"{label} id", 500) for item in values}))
    if set(ids) - set(available):
        raise ValueError(f"{label} references evidence outside the graph")
    return ids


def _node_id(kind: str, reference: str) -> str:
    return f"N-{_digest({'kind': kind, 'reference': reference})[:16]}"


def _edge(source: str, relation: str, target: str) -> AssuranceEdge:
    payload = {"source": source, "relation": relation, "target": target}
    return AssuranceEdge(
        edge_id=f"E-{_digest(payload)[:16]}",
        source_node_id=source,
        relation=relation,
        target_node_id=target,
    )


def _dedupe_edges(values: Sequence[AssuranceEdge]) -> tuple[AssuranceEdge, ...]:
    return tuple({item.edge_id: item for item in values}.values())


def _node_payload(item: AssuranceNode) -> dict[str, object]:
    return {
        "node_id": item.node_id,
        "kind": item.kind,
        "reference": item.reference,
        "content_sha256": item.content_sha256,
        "origin": item.origin,
    }


def _edge_payload(item: AssuranceEdge) -> dict[str, str]:
    return {
        "edge_id": item.edge_id,
        "source_node_id": item.source_node_id,
        "relation": item.relation,
        "target_node_id": item.target_node_id,
    }


def _step_payload(item: InvestigationStep) -> dict[str, object]:
    return {
        "step_id": item.step_id,
        "action": item.action,
        "input_evidence_ids": list(item.input_evidence_ids),
        "output_evidence_ids": list(item.output_evidence_ids),
    }


def _sha256_text(value: str) -> str:
    text = _text(value, "content sha256", 64).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("Assurance Case content_sha256 must be 64 lowercase hex characters")
    return text


def _optional_text(value: str | None, label: str, limit: int) -> str | None:
    if value is None:
        return None
    return _text(value, label, limit)


def _text(value: str, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    text = value.strip()
    if len(text) > limit:
        raise ValueError(f"{label} exceeds maximum length")
    return text


def _digest(payload: object) -> str:
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()
