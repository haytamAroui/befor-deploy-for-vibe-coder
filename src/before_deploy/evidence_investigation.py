"""Bounded advisory investigation over a validated evidence inspection trace."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path
from typing import Any, Mapping

from before_deploy.evidence_inspect import (
    EvidenceInspectionResult,
    evidence_inspection_to_primitive,
)
from before_deploy.models import to_primitive

EVIDENCE_INVESTIGATION_SCHEMA_VERSION = 1
EVIDENCE_INVESTIGATION_REQUEST_AUTHORITY = "INVESTIGATION_CONTEXT"
EVIDENCE_INVESTIGATION_AUTHORITY = "INVESTIGATION_ADVISORY"
EVIDENCE_INVESTIGATION_GATE_EFFECT = "NONE"
EVIDENCE_INVESTIGATION_SOURCE_FORMAT = "before-deploy-investigation-v1"
EVIDENCE_INVESTIGATION_IDENTITY_STATUS = "DECLARED_UNATTESTED"
DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES = 500_000
MAX_INVESTIGATION_ITEMS_PER_KIND = 64
MAX_INVESTIGATION_ITEMS_TOTAL = 128
MAX_INVESTIGATION_TEXT_CHARS = 8_000
MAX_INVESTIGATION_IDENTITY_CHARS = 200


@dataclass(frozen=True)
class EvidenceInvestigationRequest:
    """Deterministic, content-bound context packet for an external investigator."""

    schema_version: int
    source_review_sha256: str
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    inspection_sha256: str
    request_sha256: str
    selected_node_id: str
    allowed_evidence_node_ids: tuple[str, ...]
    inspection: EvidenceInspectionResult
    authority: str = EVIDENCE_INVESTIGATION_REQUEST_AUTHORITY
    gate_effect: str = EVIDENCE_INVESTIGATION_GATE_EFFECT


@dataclass(frozen=True)
class InvestigationHypothesis:
    """One advisory hypothesis grounded only in nodes from the inspection trace."""

    hypothesis_id: str
    statement: str
    rationale: str | None
    evidence_node_ids: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationObservation:
    """One investigator-authored advisory observation with explicit evidence references."""

    observation_id: str
    statement: str
    rationale: str | None
    evidence_node_ids: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationQuestion:
    """One open investigation question grounded in the bounded inspection context."""

    question_id: str
    question: str
    rationale: str | None
    evidence_node_ids: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceInvestigationResult:
    """Normalized external investigation response with no release authority."""

    schema_version: int
    source_review_sha256: str
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    inspection_sha256: str
    request_sha256: str
    investigation_sha256: str
    selected_node_id: str
    source_provider: str
    declared_model: str | None
    identity_status: str
    source_format: str
    raw_input_sha256: str
    raw_input_size_bytes: int
    normalized_output_sha256: str
    hypotheses: tuple[InvestigationHypothesis, ...]
    observations: tuple[InvestigationObservation, ...]
    questions: tuple[InvestigationQuestion, ...]
    authority: str = EVIDENCE_INVESTIGATION_AUTHORITY
    gate_effect: str = EVIDENCE_INVESTIGATION_GATE_EFFECT


def build_evidence_investigation_request(
    inspection: EvidenceInspectionResult,
) -> EvidenceInvestigationRequest:
    """Create a deterministic context packet from one validated inspection result."""
    allowed_ids = tuple(sorted(record.node.node_id for record in inspection.nodes))
    provisional = EvidenceInvestigationRequest(
        schema_version=EVIDENCE_INVESTIGATION_SCHEMA_VERSION,
        source_review_sha256=inspection.source_review_sha256,
        graph_sha256=inspection.graph_sha256,
        correlation_sha256=inspection.correlation_sha256,
        corroboration_sha256=inspection.corroboration_sha256,
        inspection_sha256=inspection.inspection_sha256,
        request_sha256="",
        selected_node_id=inspection.selected_node_id,
        allowed_evidence_node_ids=allowed_ids,
        inspection=inspection,
    )
    result = EvidenceInvestigationRequest(
        **{
            **provisional.__dict__,
            "request_sha256": _request_digest(provisional),
        }
    )
    validate_evidence_investigation_request(result)
    return result


def validate_evidence_investigation_request(request: EvidenceInvestigationRequest) -> None:
    """Validate inspection binding and the non-authority request contract."""
    if request.schema_version != EVIDENCE_INVESTIGATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence investigation request schema version")
    if (
        request.authority != EVIDENCE_INVESTIGATION_REQUEST_AUTHORITY
        or request.gate_effect != EVIDENCE_INVESTIGATION_GATE_EFFECT
    ):
        raise ValueError("Evidence investigation request must remain gate-neutral")
    inspection = request.inspection
    if request.source_review_sha256 != inspection.source_review_sha256:
        raise ValueError("Investigation request is bound to a different review artifact")
    if request.graph_sha256 != inspection.graph_sha256:
        raise ValueError("Investigation request is bound to a different evidence graph")
    if request.correlation_sha256 != inspection.correlation_sha256:
        raise ValueError("Investigation request is bound to a different correlation result")
    if request.corroboration_sha256 != inspection.corroboration_sha256:
        raise ValueError("Investigation request is bound to a different corroboration result")
    if request.inspection_sha256 != inspection.inspection_sha256:
        raise ValueError("Investigation request is bound to a different inspection")
    if request.selected_node_id != inspection.selected_node_id:
        raise ValueError("Investigation request selected node does not match inspection")
    expected_ids = tuple(sorted(record.node.node_id for record in inspection.nodes))
    if request.allowed_evidence_node_ids != expected_ids:
        raise ValueError("Investigation request evidence allow-list does not match inspection")
    if request.request_sha256 != _request_digest(request):
        raise ValueError("Evidence investigation request digest mismatch")


def load_evidence_investigation_response(
    path: Path,
    request: EvidenceInvestigationRequest,
    *,
    max_bytes: int = DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES,
) -> EvidenceInvestigationResult:
    """Load a strict investigation response bound to one deterministic request."""
    validate_evidence_investigation_request(request)
    if max_bytes <= 0:
        raise ValueError("Investigation response byte limit must be positive")
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(
            f"Investigation response exceeds byte limit: {len(raw)} > {max_bytes}"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Investigation response must be UTF-8 JSON") from error
    try:
        payload = loads(text)
    except JSONDecodeError as error:
        raise ValueError("Investigation response must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Investigation response root must be an object")

    _require_keys(
        payload,
        allowed={
            "schema_version",
            "inspection_sha256",
            "request_sha256",
            "source",
            "hypotheses",
            "observations",
            "questions",
        },
        required={
            "schema_version",
            "inspection_sha256",
            "request_sha256",
            "source",
            "hypotheses",
            "observations",
            "questions",
        },
        label="investigation response",
    )
    if payload["schema_version"] != EVIDENCE_INVESTIGATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence investigation response schema version")
    if payload["inspection_sha256"] != request.inspection_sha256:
        raise ValueError("Investigation response is bound to a different inspection")
    if payload["request_sha256"] != request.request_sha256:
        raise ValueError("Investigation response is bound to a different request")

    provider, model = _parse_declared_source(payload["source"])
    hypotheses = _parse_hypotheses(payload["hypotheses"], request)
    observations = _parse_observations(payload["observations"], request)
    questions = _parse_questions(payload["questions"], request)
    total_items = len(hypotheses) + len(observations) + len(questions)
    if total_items == 0:
        raise ValueError("Investigation response must contain at least one structured item")
    if total_items > MAX_INVESTIGATION_ITEMS_TOTAL:
        raise ValueError(
            f"Investigation response contains too many items: {total_items} > {MAX_INVESTIGATION_ITEMS_TOTAL}"
        )

    normalized_payload = {
        "source_provider": provider,
        "declared_model": model,
        "identity_status": EVIDENCE_INVESTIGATION_IDENTITY_STATUS,
        "source_format": EVIDENCE_INVESTIGATION_SOURCE_FORMAT,
        "hypotheses": [to_primitive(item) for item in hypotheses],
        "observations": [to_primitive(item) for item in observations],
        "questions": [to_primitive(item) for item in questions],
    }
    normalized_sha = _canonical_sha256(normalized_payload)
    provisional = EvidenceInvestigationResult(
        schema_version=EVIDENCE_INVESTIGATION_SCHEMA_VERSION,
        source_review_sha256=request.source_review_sha256,
        graph_sha256=request.graph_sha256,
        correlation_sha256=request.correlation_sha256,
        corroboration_sha256=request.corroboration_sha256,
        inspection_sha256=request.inspection_sha256,
        request_sha256=request.request_sha256,
        investigation_sha256="",
        selected_node_id=request.selected_node_id,
        source_provider=provider,
        declared_model=model,
        identity_status=EVIDENCE_INVESTIGATION_IDENTITY_STATUS,
        source_format=EVIDENCE_INVESTIGATION_SOURCE_FORMAT,
        raw_input_sha256=sha256(raw).hexdigest(),
        raw_input_size_bytes=len(raw),
        normalized_output_sha256=normalized_sha,
        hypotheses=hypotheses,
        observations=observations,
        questions=questions,
    )
    result = EvidenceInvestigationResult(
        **{
            **provisional.__dict__,
            "investigation_sha256": _investigation_digest(provisional),
        }
    )
    validate_evidence_investigation(result, request)
    return result


def validate_evidence_investigation(
    result: EvidenceInvestigationResult,
    request: EvidenceInvestigationRequest,
) -> None:
    """Reject authority upgrades, lineage drift, forged IDs, and out-of-context evidence."""
    validate_evidence_investigation_request(request)
    if result.schema_version != EVIDENCE_INVESTIGATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence investigation schema version")
    if result.authority != EVIDENCE_INVESTIGATION_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Evidence investigation must remain advisory and gate-neutral")
    bindings = (
        (result.source_review_sha256, request.source_review_sha256, "review artifact"),
        (result.graph_sha256, request.graph_sha256, "evidence graph"),
        (result.correlation_sha256, request.correlation_sha256, "correlation result"),
        (result.corroboration_sha256, request.corroboration_sha256, "corroboration result"),
        (result.inspection_sha256, request.inspection_sha256, "inspection"),
        (result.request_sha256, request.request_sha256, "request"),
        (result.selected_node_id, request.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Evidence investigation is bound to a different {label}")
    if result.identity_status != EVIDENCE_INVESTIGATION_IDENTITY_STATUS:
        raise ValueError("Investigator identity must remain declared and unattested")
    if result.source_format != EVIDENCE_INVESTIGATION_SOURCE_FORMAT:
        raise ValueError("Unsupported evidence investigation source format")
    _bounded_text(result.source_provider, "source provider", MAX_INVESTIGATION_IDENTITY_CHARS)
    if result.declared_model is not None:
        _bounded_text(result.declared_model, "declared model", MAX_INVESTIGATION_IDENTITY_CHARS)
    if result.raw_input_size_bytes <= 0:
        raise ValueError("Investigation raw input size must be positive")
    if not _is_sha256(result.raw_input_sha256):
        raise ValueError("Investigation raw input digest must be SHA-256")

    allowed = set(request.allowed_evidence_node_ids)
    for item in result.hypotheses:
        _validate_hypothesis(item, allowed)
    for item in result.observations:
        _validate_observation(item, allowed)
    for item in result.questions:
        _validate_question(item, allowed)
    total_items = len(result.hypotheses) + len(result.observations) + len(result.questions)
    if total_items == 0 or total_items > MAX_INVESTIGATION_ITEMS_TOTAL:
        raise ValueError("Investigation result item count is outside the supported bounds")

    normalized_payload = {
        "source_provider": result.source_provider,
        "declared_model": result.declared_model,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "hypotheses": [to_primitive(item) for item in result.hypotheses],
        "observations": [to_primitive(item) for item in result.observations],
        "questions": [to_primitive(item) for item in result.questions],
    }
    if result.normalized_output_sha256 != _canonical_sha256(normalized_payload):
        raise ValueError("Investigation normalized output digest mismatch")
    if result.investigation_sha256 != _investigation_digest(result):
        raise ValueError("Evidence investigation digest mismatch")


def evidence_investigation_request_to_primitive(
    request: EvidenceInvestigationRequest,
) -> dict[str, Any]:
    """Serialize the bounded context packet that an investigator may receive."""
    validate_evidence_investigation_request(request)
    return {
        "schema_version": request.schema_version,
        "source_review_sha256": request.source_review_sha256,
        "graph_sha256": request.graph_sha256,
        "correlation_sha256": request.correlation_sha256,
        "corroboration_sha256": request.corroboration_sha256,
        "inspection_sha256": request.inspection_sha256,
        "request_sha256": request.request_sha256,
        "selected_node_id": request.selected_node_id,
        "allowed_evidence_node_ids": list(request.allowed_evidence_node_ids),
        "authority": request.authority,
        "gate_effect": request.gate_effect,
        "authority_contract": {
            "request_authority": "context_only",
            "investigation_authority": "advisory_only",
            "release_authority": "persisted_policy_decision_only",
            "evidence_references": "inspection_node_ids_only",
            "policy_mutation": "forbidden",
            "confidence_promotion": "forbidden",
        },
        "response_contract": {
            "schema_version": EVIDENCE_INVESTIGATION_SCHEMA_VERSION,
            "source_format": EVIDENCE_INVESTIGATION_SOURCE_FORMAT,
            "required_top_level_fields": [
                "schema_version",
                "inspection_sha256",
                "request_sha256",
                "source",
                "hypotheses",
                "observations",
                "questions",
            ],
            "source_fields": ["provider", "model"],
            "hypothesis_fields": ["statement", "rationale", "evidence_node_ids"],
            "observation_fields": ["statement", "rationale", "evidence_node_ids"],
            "question_fields": ["question", "rationale", "evidence_node_ids"],
            "provider_item_ids": "not_accepted_content_addressed_by_before_deploy",
        },
        "inspection_context": evidence_inspection_to_primitive(request.inspection),
    }


def evidence_investigation_to_primitive(result: EvidenceInvestigationResult) -> dict[str, Any]:
    """Serialize advisory investigation output without creating release semantics."""
    return {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "inspection_sha256": result.inspection_sha256,
        "request_sha256": result.request_sha256,
        "investigation_sha256": result.investigation_sha256,
        "selected_node_id": result.selected_node_id,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "authority_contract": {
            "investigation_authority": "advisory_only",
            "release_authority": "persisted_policy_decision_only",
            "evidence_references": "inspection_node_ids_only",
            "investigator_identity": "declared_unattested",
            "policy_mutation": "forbidden",
            "finding_authority_promotion": "forbidden",
            "confidence_promotion": "forbidden",
        },
        "source": {
            "provider": result.source_provider,
            "declared_model": result.declared_model,
            "identity_status": result.identity_status,
            "source_format": result.source_format,
        },
        "raw_input": {
            "sha256": result.raw_input_sha256,
            "size_bytes": result.raw_input_size_bytes,
        },
        "normalized_output_sha256": result.normalized_output_sha256,
        "hypotheses": [to_primitive(item) for item in result.hypotheses],
        "observations": [to_primitive(item) for item in result.observations],
        "questions": [to_primitive(item) for item in result.questions],
    }


def render_evidence_investigation_request_json(request: EvidenceInvestigationRequest) -> str:
    return dumps(
        evidence_investigation_request_to_primitive(request),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_evidence_investigation_json(result: EvidenceInvestigationResult) -> str:
    return dumps(
        evidence_investigation_to_primitive(result),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_evidence_investigation_request_markdown(
    request: EvidenceInvestigationRequest,
) -> str:
    lines = [
        "# Before Deploy Investigation Request",
        "",
        f"- Selected node: `{request.selected_node_id}`",
        f"- Review artifact SHA-256: `{request.source_review_sha256}`",
        f"- Inspection SHA-256: `{request.inspection_sha256}`",
        f"- Request SHA-256: `{request.request_sha256}`",
        f"- Evidence nodes available: **{len(request.allowed_evidence_node_ids)}**",
        f"- Authority: `{request.authority}`",
        f"- Gate effect: `{request.gate_effect}`",
        "",
        "## Investigation boundary",
        "",
        "This packet is advisory context only. It cannot change `PolicyDecision`, finding authority, severity, or provider confidence.",
        "Every hypothesis, observation, and question in a response must reference one or more node IDs from this packet.",
        "Provider/model identity in a response is treated as declared and unattested.",
        "",
        "## Allowed evidence node IDs",
        "",
    ]
    for record in request.inspection.nodes:
        roles = ", ".join(record.roles)
        lines.append(
            f"- `{record.node.node_id}` — `{record.node.node_type}` — roles `{roles}` — depth `{record.depth}`"
        )
    lines.extend(
        [
            "",
            "## Response schema",
            "",
            f"Use schema version `{EVIDENCE_INVESTIGATION_SCHEMA_VERSION}` and echo both the inspection and request SHA-256 values exactly.",
            "Only `source`, `hypotheses`, `observations`, and `questions` are accepted as investigator-authored content.",
            "Before Deploy assigns item IDs after normalization; provider-supplied IDs are rejected.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_evidence_investigation_markdown(result: EvidenceInvestigationResult) -> str:
    model = result.declared_model or "UNATTESTED"
    lines = [
        "# Before Deploy Evidence Investigation",
        "",
        f"- Selected node: `{result.selected_node_id}`",
        f"- Provider declaration: `{result.source_provider}`",
        f"- Declared model: `{model}`",
        f"- Identity status: `{result.identity_status}`",
        f"- Inspection SHA-256: `{result.inspection_sha256}`",
        f"- Request SHA-256: `{result.request_sha256}`",
        f"- Investigation SHA-256: `{result.investigation_sha256}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "## Authority boundary",
        "",
        "Investigation content is advisory and untrusted. It does not mutate the persisted Evidence Graph or `PolicyDecision`.",
        "Evidence references are limited to node IDs already present in the validated inspection trace.",
        "No investigation statement changes severity, confidence, corroboration status, or release authority.",
        "",
        "## Hypotheses",
        "",
    ]
    _append_items_markdown(lines, result.hypotheses, "hypothesis_id", "statement")
    lines.extend(["", "## Advisory observations", ""])
    _append_items_markdown(lines, result.observations, "observation_id", "statement")
    lines.extend(["", "## Open questions", ""])
    _append_items_markdown(lines, result.questions, "question_id", "question")
    return "\n".join(lines).rstrip() + "\n"


def render_evidence_investigation_request_terminal(
    request: EvidenceInvestigationRequest,
) -> str:
    return (
        "Before Deploy investigation request\n"
        f"Selected node: {request.selected_node_id}\n"
        f"Inspection SHA-256: {request.inspection_sha256}\n"
        f"Request SHA-256: {request.request_sha256}\n"
        f"Bounded evidence nodes: {len(request.allowed_evidence_node_ids)}\n"
        f"Authority: {request.authority}, gate_effect={request.gate_effect}\n"
    )


def render_evidence_investigation_terminal(result: EvidenceInvestigationResult) -> str:
    return (
        "Before Deploy investigation: ADVISORY\n"
        f"Selected node: {result.selected_node_id}\n"
        f"Provider: {result.source_provider} (identity={result.identity_status})\n"
        f"Items: hypotheses={len(result.hypotheses)}, observations={len(result.observations)}, questions={len(result.questions)}\n"
        f"Investigation SHA-256: {result.investigation_sha256}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def _parse_declared_source(value: Any) -> tuple[str, str | None]:
    if not isinstance(value, dict):
        raise ValueError("Investigation source must be an object")
    _require_keys(
        value,
        allowed={"provider", "model"},
        required={"provider"},
        label="investigation source",
    )
    provider = _bounded_text(
        value["provider"],
        "source provider",
        MAX_INVESTIGATION_IDENTITY_CHARS,
    )
    model_value = value.get("model")
    model = (
        _bounded_text(model_value, "declared model", MAX_INVESTIGATION_IDENTITY_CHARS)
        if model_value is not None
        else None
    )
    return provider, model


def _parse_hypotheses(
    value: Any,
    request: EvidenceInvestigationRequest,
) -> tuple[InvestigationHypothesis, ...]:
    items = _list_of_objects(value, "hypotheses")
    parsed: dict[str, InvestigationHypothesis] = {}
    for payload in items:
        _require_keys(
            payload,
            allowed={"statement", "rationale", "evidence_node_ids"},
            required={"statement", "evidence_node_ids"},
            label="hypothesis",
        )
        statement = _bounded_text(payload["statement"], "hypothesis statement")
        rationale = _optional_text(payload.get("rationale"), "hypothesis rationale")
        evidence_ids = _evidence_ids(payload["evidence_node_ids"], request, "hypothesis")
        semantic = {
            "statement": statement,
            "rationale": rationale,
            "evidence_node_ids": evidence_ids,
        }
        item_id = _diagnostic_id("investigation-hypothesis", semantic)
        parsed[item_id] = InvestigationHypothesis(
            hypothesis_id=item_id,
            statement=statement,
            rationale=rationale,
            evidence_node_ids=evidence_ids,
        )
    return tuple(parsed[key] for key in sorted(parsed))


def _parse_observations(
    value: Any,
    request: EvidenceInvestigationRequest,
) -> tuple[InvestigationObservation, ...]:
    items = _list_of_objects(value, "observations")
    parsed: dict[str, InvestigationObservation] = {}
    for payload in items:
        _require_keys(
            payload,
            allowed={"statement", "rationale", "evidence_node_ids"},
            required={"statement", "evidence_node_ids"},
            label="observation",
        )
        statement = _bounded_text(payload["statement"], "observation statement")
        rationale = _optional_text(payload.get("rationale"), "observation rationale")
        evidence_ids = _evidence_ids(payload["evidence_node_ids"], request, "observation")
        semantic = {
            "statement": statement,
            "rationale": rationale,
            "evidence_node_ids": evidence_ids,
        }
        item_id = _diagnostic_id("investigation-observation", semantic)
        parsed[item_id] = InvestigationObservation(
            observation_id=item_id,
            statement=statement,
            rationale=rationale,
            evidence_node_ids=evidence_ids,
        )
    return tuple(parsed[key] for key in sorted(parsed))


def _parse_questions(
    value: Any,
    request: EvidenceInvestigationRequest,
) -> tuple[InvestigationQuestion, ...]:
    items = _list_of_objects(value, "questions")
    parsed: dict[str, InvestigationQuestion] = {}
    for payload in items:
        _require_keys(
            payload,
            allowed={"question", "rationale", "evidence_node_ids"},
            required={"question", "evidence_node_ids"},
            label="question",
        )
        question = _bounded_text(payload["question"], "investigation question")
        rationale = _optional_text(payload.get("rationale"), "question rationale")
        evidence_ids = _evidence_ids(payload["evidence_node_ids"], request, "question")
        semantic = {
            "question": question,
            "rationale": rationale,
            "evidence_node_ids": evidence_ids,
        }
        item_id = _diagnostic_id("investigation-question", semantic)
        parsed[item_id] = InvestigationQuestion(
            question_id=item_id,
            question=question,
            rationale=rationale,
            evidence_node_ids=evidence_ids,
        )
    return tuple(parsed[key] for key in sorted(parsed))


def _validate_hypothesis(item: InvestigationHypothesis, allowed: set[str]) -> None:
    semantic = {
        "statement": _bounded_text(item.statement, "hypothesis statement"),
        "rationale": _optional_text(item.rationale, "hypothesis rationale"),
        "evidence_node_ids": _validate_evidence_id_tuple(item.evidence_node_ids, allowed, "hypothesis"),
    }
    if item.hypothesis_id != _diagnostic_id("investigation-hypothesis", semantic):
        raise ValueError("Investigation hypothesis ID does not match canonical payload")


def _validate_observation(item: InvestigationObservation, allowed: set[str]) -> None:
    semantic = {
        "statement": _bounded_text(item.statement, "observation statement"),
        "rationale": _optional_text(item.rationale, "observation rationale"),
        "evidence_node_ids": _validate_evidence_id_tuple(item.evidence_node_ids, allowed, "observation"),
    }
    if item.observation_id != _diagnostic_id("investigation-observation", semantic):
        raise ValueError("Investigation observation ID does not match canonical payload")


def _validate_question(item: InvestigationQuestion, allowed: set[str]) -> None:
    semantic = {
        "question": _bounded_text(item.question, "investigation question"),
        "rationale": _optional_text(item.rationale, "question rationale"),
        "evidence_node_ids": _validate_evidence_id_tuple(item.evidence_node_ids, allowed, "question"),
    }
    if item.question_id != _diagnostic_id("investigation-question", semantic):
        raise ValueError("Investigation question ID does not match canonical payload")


def _list_of_objects(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"Investigation {label} must be an array")
    if len(value) > MAX_INVESTIGATION_ITEMS_PER_KIND:
        raise ValueError(
            f"Investigation {label} exceeds item limit: {len(value)} > {MAX_INVESTIGATION_ITEMS_PER_KIND}"
        )
    if any(not isinstance(item, dict) for item in value):
        raise ValueError(f"Investigation {label} entries must be objects")
    return value


def _evidence_ids(
    value: Any,
    request: EvidenceInvestigationRequest,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"Investigation {label} must reference at least one evidence node")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"Investigation {label} evidence node IDs must be non-empty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"Investigation {label} evidence node IDs must be unique")
    result = tuple(sorted(value))
    return _validate_evidence_id_tuple(
        result,
        set(request.allowed_evidence_node_ids),
        label,
    )


def _validate_evidence_id_tuple(
    value: tuple[str, ...],
    allowed: set[str],
    label: str,
) -> tuple[str, ...]:
    if not value or value != tuple(sorted(set(value))):
        raise ValueError(f"Investigation {label} evidence node IDs must be sorted and unique")
    unknown = [node_id for node_id in value if node_id not in allowed]
    if unknown:
        raise ValueError(
            "Investigation evidence reference escapes bounded inspection context: "
            + ", ".join(unknown)
        )
    return value


def _require_keys(
    payload: Mapping[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    keys = set(payload)
    unknown = sorted(keys - allowed)
    missing = sorted(required - keys)
    if unknown:
        raise ValueError(f"Unsupported {label} field(s): {', '.join(unknown)}")
    if missing:
        raise ValueError(f"Missing {label} field(s): {', '.join(missing)}")


def _bounded_text(
    value: Any,
    label: str,
    max_chars: int = MAX_INVESTIGATION_TEXT_CHARS,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Investigation {label} must be a string")
    result = value.strip()
    if not result:
        raise ValueError(f"Investigation {label} must not be empty")
    if len(result) > max_chars:
        raise ValueError(f"Investigation {label} exceeds character limit")
    return result


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label)


def _append_items_markdown(lines: list[str], items: tuple[Any, ...], id_attr: str, text_attr: str) -> None:
    if not items:
        lines.append("No items recorded.")
        return
    for item in items:
        item_id = getattr(item, id_attr)
        text = getattr(item, text_attr)
        lines.append(f"- `{item_id}` — {text}")
        if item.rationale:
            lines.append(f"  - Rationale: {item.rationale}")
        lines.append(
            "  - Evidence: " + ", ".join(f"`{node_id}`" for node_id in item.evidence_node_ids)
        )


def _request_digest(request: EvidenceInvestigationRequest) -> str:
    payload = {
        "schema_version": request.schema_version,
        "source_review_sha256": request.source_review_sha256,
        "graph_sha256": request.graph_sha256,
        "correlation_sha256": request.correlation_sha256,
        "corroboration_sha256": request.corroboration_sha256,
        "inspection_sha256": request.inspection_sha256,
        "selected_node_id": request.selected_node_id,
        "allowed_evidence_node_ids": list(request.allowed_evidence_node_ids),
        "authority": request.authority,
        "gate_effect": request.gate_effect,
        "inspection_context": evidence_inspection_to_primitive(request.inspection),
    }
    return _canonical_sha256(payload)


def _investigation_digest(result: EvidenceInvestigationResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "inspection_sha256": result.inspection_sha256,
        "request_sha256": result.request_sha256,
        "selected_node_id": result.selected_node_id,
        "source_provider": result.source_provider,
        "declared_model": result.declared_model,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "raw_input_sha256": result.raw_input_sha256,
        "raw_input_size_bytes": result.raw_input_size_bytes,
        "normalized_output_sha256": result.normalized_output_sha256,
        "hypotheses": [to_primitive(item) for item in result.hypotheses],
        "observations": [to_primitive(item) for item in result.observations],
        "questions": [to_primitive(item) for item in result.questions],
        "authority": result.authority,
        "gate_effect": result.gate_effect,
    }
    return _canonical_sha256(payload)


def _diagnostic_id(kind: str, payload: Any) -> str:
    return f"{kind}:{_canonical_sha256({'kind': kind, 'payload': to_primitive(payload)})}"


def _canonical_sha256(payload: Any) -> str:
    serialized = dumps(
        to_primitive(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
