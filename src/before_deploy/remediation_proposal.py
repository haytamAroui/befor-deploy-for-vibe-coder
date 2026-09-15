"""Evidence-cited, non-executable remediation proposals over validated explanation lineage."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path, PurePosixPath
from typing import Any

from before_deploy.evidence_explanation import (
    EvidenceExplanationRequest,
    EvidenceExplanationResult,
    evidence_explanation_to_primitive,
    validate_evidence_explanation,
    validate_evidence_explanation_request,
)
from before_deploy.evidence_investigation import EvidenceInvestigationRequest
from before_deploy.models import to_primitive

REMEDIATION_PROPOSAL_SCHEMA_VERSION = 1
REMEDIATION_PROPOSAL_REQUEST_AUTHORITY = "REMEDIATION_CONTEXT"
REMEDIATION_PROPOSAL_AUTHORITY = "REMEDIATION_PROPOSAL_ADVISORY"
REMEDIATION_PROPOSAL_GATE_EFFECT = "NONE"
REMEDIATION_PROPOSAL_SOURCE_FORMAT = "before-deploy-remediation-proposal-v1"
REMEDIATION_PROPOSAL_IDENTITY_STATUS = "DECLARED_UNATTESTED"
REMEDIATION_PROPOSAL_EXECUTION_STATUS = "NON_EXECUTABLE"
REMEDIATION_PROPOSAL_APPROVAL_STATUS = "NOT_APPROVED"
DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES = 500_000
MAX_REMEDIATION_CHANGES = 64
MAX_REMEDIATION_VERIFICATION_GOALS = 64
MAX_REMEDIATION_RISKS = 32
MAX_REMEDIATION_ITEMS_TOTAL = 128
MAX_REMEDIATION_TEXT_CHARS = 8_000
MAX_REMEDIATION_PATH_CHARS = 500
MAX_REMEDIATION_IDENTITY_CHARS = 200
VERIFICATION_KINDS = ("TEST", "STATIC_SCAN", "RUNTIME_CHECK", "MANUAL_REVIEW", "OTHER")


@dataclass(frozen=True)
class RemediationCitation:
    """Bounded references to existing evidence, investigation, or explanation material."""

    evidence_node_ids: tuple[str, ...]
    investigation_item_ids: tuple[str, ...]
    explanation_statement_ids: tuple[str, ...]


@dataclass(frozen=True)
class RemediationObjective:
    objective_id: str
    text: str
    citations: RemediationCitation


@dataclass(frozen=True)
class RemediationChange:
    change_id: str
    target_path: str
    intent: str
    rationale: str | None
    citations: RemediationCitation


@dataclass(frozen=True)
class RemediationVerificationGoal:
    verification_goal_id: str
    kind: str
    statement: str
    citations: RemediationCitation


@dataclass(frozen=True)
class RemediationRisk:
    risk_id: str
    statement: str
    citations: RemediationCitation


@dataclass(frozen=True)
class RemediationProposalRequest:
    """Content-bound context packet for a non-executable remediation proposal."""

    schema_version: int
    source_review_sha256: str
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    inspection_sha256: str
    investigation_request_sha256: str
    investigation_sha256: str | None
    explanation_request_sha256: str
    explanation_sha256: str
    request_sha256: str
    selected_node_id: str
    allowed_evidence_node_ids: tuple[str, ...]
    allowed_investigation_item_ids: tuple[str, ...]
    allowed_explanation_statement_ids: tuple[str, ...]
    explanation_request: EvidenceExplanationRequest
    explanation: EvidenceExplanationResult
    authority: str = REMEDIATION_PROPOSAL_REQUEST_AUTHORITY
    gate_effect: str = REMEDIATION_PROPOSAL_GATE_EFFECT


@dataclass(frozen=True)
class RemediationProposalResult:
    """Normalized remediation proposal with no execution or release authority."""

    schema_version: int
    source_review_sha256: str
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    inspection_sha256: str
    investigation_request_sha256: str
    investigation_sha256: str | None
    explanation_request_sha256: str
    explanation_sha256: str
    request_sha256: str
    proposal_sha256: str
    selected_node_id: str
    source_provider: str
    declared_model: str | None
    identity_status: str
    source_format: str
    raw_input_sha256: str
    raw_input_size_bytes: int
    normalized_output_sha256: str
    execution_status: str
    approval_status: str
    objective: RemediationObjective
    changes: tuple[RemediationChange, ...]
    verification_goals: tuple[RemediationVerificationGoal, ...]
    risks: tuple[RemediationRisk, ...]
    authority: str = REMEDIATION_PROPOSAL_AUTHORITY
    gate_effect: str = REMEDIATION_PROPOSAL_GATE_EFFECT


def build_remediation_proposal_request(
    explanation_request: EvidenceExplanationRequest,
    explanation: EvidenceExplanationResult,
    investigation_request: EvidenceInvestigationRequest,
) -> RemediationProposalRequest:
    """Build a bounded remediation context from one validated explanation artifact."""
    validate_evidence_explanation_request(explanation_request, investigation_request)
    validate_evidence_explanation(explanation, explanation_request, investigation_request)

    allowed_explanation = _explanation_statement_ids(explanation)
    provisional = RemediationProposalRequest(
        schema_version=REMEDIATION_PROPOSAL_SCHEMA_VERSION,
        source_review_sha256=explanation.source_review_sha256,
        graph_sha256=explanation.graph_sha256,
        correlation_sha256=explanation.correlation_sha256,
        corroboration_sha256=explanation.corroboration_sha256,
        inspection_sha256=explanation.inspection_sha256,
        investigation_request_sha256=explanation.investigation_request_sha256,
        investigation_sha256=explanation.investigation_sha256,
        explanation_request_sha256=explanation.request_sha256,
        explanation_sha256=explanation.explanation_sha256,
        request_sha256="",
        selected_node_id=explanation.selected_node_id,
        allowed_evidence_node_ids=explanation_request.allowed_evidence_node_ids,
        allowed_investigation_item_ids=explanation_request.allowed_investigation_item_ids,
        allowed_explanation_statement_ids=allowed_explanation,
        explanation_request=explanation_request,
        explanation=explanation,
    )
    result = RemediationProposalRequest(
        **{**provisional.__dict__, "request_sha256": _request_digest(provisional)}
    )
    validate_remediation_proposal_request(result, investigation_request)
    return result


def validate_remediation_proposal_request(
    request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    """Validate lineage bindings and the non-executable request boundary."""
    if request.schema_version != REMEDIATION_PROPOSAL_SCHEMA_VERSION:
        raise ValueError("Unsupported remediation proposal request schema version")
    if (
        request.authority != REMEDIATION_PROPOSAL_REQUEST_AUTHORITY
        or request.gate_effect != REMEDIATION_PROPOSAL_GATE_EFFECT
    ):
        raise ValueError("Remediation proposal request must remain gate-neutral")
    validate_evidence_explanation_request(request.explanation_request, investigation_request)
    validate_evidence_explanation(
        request.explanation,
        request.explanation_request,
        investigation_request,
    )
    bindings = (
        (request.source_review_sha256, request.explanation.source_review_sha256, "review artifact"),
        (request.graph_sha256, request.explanation.graph_sha256, "evidence graph"),
        (request.correlation_sha256, request.explanation.correlation_sha256, "correlation result"),
        (request.corroboration_sha256, request.explanation.corroboration_sha256, "corroboration result"),
        (request.inspection_sha256, request.explanation.inspection_sha256, "inspection"),
        (
            request.investigation_request_sha256,
            request.explanation.investigation_request_sha256,
            "investigation request",
        ),
        (request.investigation_sha256, request.explanation.investigation_sha256, "investigation"),
        (request.explanation_request_sha256, request.explanation.request_sha256, "explanation request"),
        (request.explanation_sha256, request.explanation.explanation_sha256, "explanation"),
        (request.selected_node_id, request.explanation.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Remediation proposal request is bound to a different {label}")
    if request.allowed_evidence_node_ids != request.explanation_request.allowed_evidence_node_ids:
        raise ValueError("Remediation evidence allow-list does not match explanation context")
    if request.allowed_investigation_item_ids != request.explanation_request.allowed_investigation_item_ids:
        raise ValueError("Remediation investigation allow-list does not match explanation context")
    if request.allowed_explanation_statement_ids != _explanation_statement_ids(request.explanation):
        raise ValueError("Remediation explanation statement allow-list is invalid")
    if request.request_sha256 != _request_digest(request):
        raise ValueError("Remediation proposal request digest mismatch")


def load_remediation_proposal_response(
    path: Path,
    request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
    *,
    max_bytes: int = DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES,
) -> RemediationProposalResult:
    """Load a strict non-executable remediation proposal response."""
    validate_remediation_proposal_request(request, investigation_request)
    if max_bytes <= 0:
        raise ValueError("Remediation proposal response byte limit must be positive")
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"Remediation proposal response exceeds byte limit: {len(raw)} > {max_bytes}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Remediation proposal response must be UTF-8 JSON") from error
    try:
        payload = loads(text)
    except JSONDecodeError as error:
        raise ValueError("Remediation proposal response must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Remediation proposal response root must be an object")

    _require_keys(
        payload,
        allowed={
            "schema_version",
            "request_sha256",
            "source",
            "objective",
            "changes",
            "verification_goals",
            "risks",
        },
        required={
            "schema_version",
            "request_sha256",
            "source",
            "objective",
            "changes",
            "verification_goals",
            "risks",
        },
        label="remediation proposal response",
    )
    if payload["schema_version"] != REMEDIATION_PROPOSAL_SCHEMA_VERSION:
        raise ValueError("Unsupported remediation proposal response schema version")
    if payload["request_sha256"] != request.request_sha256:
        raise ValueError("Remediation proposal response is bound to a different request")

    provider, model = _parse_declared_source(payload["source"])
    objective = _parse_objective(payload["objective"], request)
    changes = _parse_changes(payload["changes"], request)
    verification_goals = _parse_verification_goals(payload["verification_goals"], request)
    risks = _parse_risks(payload["risks"], request)
    total_items = 1 + len(changes) + len(verification_goals) + len(risks)
    if total_items > MAX_REMEDIATION_ITEMS_TOTAL:
        raise ValueError("Remediation proposal contains too many structured items")

    normalized_payload = {
        "source_provider": provider,
        "declared_model": model,
        "identity_status": REMEDIATION_PROPOSAL_IDENTITY_STATUS,
        "source_format": REMEDIATION_PROPOSAL_SOURCE_FORMAT,
        "execution_status": REMEDIATION_PROPOSAL_EXECUTION_STATUS,
        "approval_status": REMEDIATION_PROPOSAL_APPROVAL_STATUS,
        "objective": to_primitive(objective),
        "changes": [to_primitive(item) for item in changes],
        "verification_goals": [to_primitive(item) for item in verification_goals],
        "risks": [to_primitive(item) for item in risks],
    }
    normalized_sha = _canonical_sha256(normalized_payload)
    provisional = RemediationProposalResult(
        schema_version=REMEDIATION_PROPOSAL_SCHEMA_VERSION,
        source_review_sha256=request.source_review_sha256,
        graph_sha256=request.graph_sha256,
        correlation_sha256=request.correlation_sha256,
        corroboration_sha256=request.corroboration_sha256,
        inspection_sha256=request.inspection_sha256,
        investigation_request_sha256=request.investigation_request_sha256,
        investigation_sha256=request.investigation_sha256,
        explanation_request_sha256=request.explanation_request_sha256,
        explanation_sha256=request.explanation_sha256,
        request_sha256=request.request_sha256,
        proposal_sha256="",
        selected_node_id=request.selected_node_id,
        source_provider=provider,
        declared_model=model,
        identity_status=REMEDIATION_PROPOSAL_IDENTITY_STATUS,
        source_format=REMEDIATION_PROPOSAL_SOURCE_FORMAT,
        raw_input_sha256=sha256(raw).hexdigest(),
        raw_input_size_bytes=len(raw),
        normalized_output_sha256=normalized_sha,
        execution_status=REMEDIATION_PROPOSAL_EXECUTION_STATUS,
        approval_status=REMEDIATION_PROPOSAL_APPROVAL_STATUS,
        objective=objective,
        changes=changes,
        verification_goals=verification_goals,
        risks=risks,
    )
    result = RemediationProposalResult(
        **{**provisional.__dict__, "proposal_sha256": _proposal_digest(provisional)}
    )
    validate_remediation_proposal(result, request, investigation_request)
    return result


def validate_remediation_proposal(
    result: RemediationProposalResult,
    request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    """Reject lineage drift, authority upgrades, executable content, and forged IDs."""
    validate_remediation_proposal_request(request, investigation_request)
    if result.schema_version != REMEDIATION_PROPOSAL_SCHEMA_VERSION:
        raise ValueError("Unsupported remediation proposal schema version")
    if result.authority != REMEDIATION_PROPOSAL_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Remediation proposal must remain advisory and gate-neutral")
    bindings = (
        (result.source_review_sha256, request.source_review_sha256, "review artifact"),
        (result.graph_sha256, request.graph_sha256, "evidence graph"),
        (result.correlation_sha256, request.correlation_sha256, "correlation result"),
        (result.corroboration_sha256, request.corroboration_sha256, "corroboration result"),
        (result.inspection_sha256, request.inspection_sha256, "inspection"),
        (
            result.investigation_request_sha256,
            request.investigation_request_sha256,
            "investigation request",
        ),
        (result.investigation_sha256, request.investigation_sha256, "investigation"),
        (result.explanation_request_sha256, request.explanation_request_sha256, "explanation request"),
        (result.explanation_sha256, request.explanation_sha256, "explanation"),
        (result.request_sha256, request.request_sha256, "request"),
        (result.selected_node_id, request.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Remediation proposal is bound to a different {label}")
    if result.identity_status != REMEDIATION_PROPOSAL_IDENTITY_STATUS:
        raise ValueError("Remediation proposer identity must remain declared and unattested")
    if result.source_format != REMEDIATION_PROPOSAL_SOURCE_FORMAT:
        raise ValueError("Unsupported remediation proposal source format")
    if result.execution_status != REMEDIATION_PROPOSAL_EXECUTION_STATUS:
        raise ValueError("Remediation proposal must remain non-executable")
    if result.approval_status != REMEDIATION_PROPOSAL_APPROVAL_STATUS:
        raise ValueError("Remediation proposal cannot self-assert approval")
    _bounded_text(result.source_provider, "source provider", MAX_REMEDIATION_IDENTITY_CHARS)
    if result.declared_model is not None:
        _bounded_text(result.declared_model, "declared model", MAX_REMEDIATION_IDENTITY_CHARS)
    if result.raw_input_size_bytes <= 0:
        raise ValueError("Remediation raw input size must be positive")
    if not _is_sha256(result.raw_input_sha256):
        raise ValueError("Remediation raw input digest must be SHA-256")

    _validate_objective(result.objective, request)
    if not result.changes or len(result.changes) > MAX_REMEDIATION_CHANGES:
        raise ValueError("Remediation proposal change count is outside the supported bounds")
    if not result.verification_goals or len(result.verification_goals) > MAX_REMEDIATION_VERIFICATION_GOALS:
        raise ValueError("Remediation verification goal count is outside the supported bounds")
    if len(result.risks) > MAX_REMEDIATION_RISKS:
        raise ValueError("Remediation proposal contains too many risk statements")
    if 1 + len(result.changes) + len(result.verification_goals) + len(result.risks) > MAX_REMEDIATION_ITEMS_TOTAL:
        raise ValueError("Remediation proposal contains too many structured items")
    for item in result.changes:
        _validate_change(item, request)
    for item in result.verification_goals:
        _validate_verification_goal(item, request)
    for item in result.risks:
        _validate_risk(item, request)

    normalized_payload = {
        "source_provider": result.source_provider,
        "declared_model": result.declared_model,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "execution_status": result.execution_status,
        "approval_status": result.approval_status,
        "objective": to_primitive(result.objective),
        "changes": [to_primitive(item) for item in result.changes],
        "verification_goals": [to_primitive(item) for item in result.verification_goals],
        "risks": [to_primitive(item) for item in result.risks],
    }
    if result.normalized_output_sha256 != _canonical_sha256(normalized_payload):
        raise ValueError("Remediation normalized output digest mismatch")
    if result.proposal_sha256 != _proposal_digest(result):
        raise ValueError("Remediation proposal digest mismatch")


def remediation_proposal_request_to_primitive(request: RemediationProposalRequest) -> dict[str, Any]:
    """Serialize bounded proposal context without code or patch content."""
    return {
        "schema_version": request.schema_version,
        "source_review_sha256": request.source_review_sha256,
        "graph_sha256": request.graph_sha256,
        "correlation_sha256": request.correlation_sha256,
        "corroboration_sha256": request.corroboration_sha256,
        "inspection_sha256": request.inspection_sha256,
        "investigation_request_sha256": request.investigation_request_sha256,
        "investigation_sha256": request.investigation_sha256,
        "explanation_request_sha256": request.explanation_request_sha256,
        "explanation_sha256": request.explanation_sha256,
        "request_sha256": request.request_sha256,
        "selected_node_id": request.selected_node_id,
        "allowed_evidence_node_ids": list(request.allowed_evidence_node_ids),
        "allowed_investigation_item_ids": list(request.allowed_investigation_item_ids),
        "allowed_explanation_statement_ids": list(request.allowed_explanation_statement_ids),
        "authority": request.authority,
        "gate_effect": request.gate_effect,
        "authority_contract": {
            "request_authority": "context_only",
            "proposal_authority": "advisory_only",
            "release_authority": "persisted_policy_decision_only",
            "code_mutation": "forbidden",
            "patch_generation": "forbidden",
            "command_execution": "forbidden",
            "self_approval": "forbidden",
        },
        "response_contract": {
            "schema_version": REMEDIATION_PROPOSAL_SCHEMA_VERSION,
            "source_format": REMEDIATION_PROPOSAL_SOURCE_FORMAT,
            "allowed_content": ["objective", "changes", "verification_goals", "risks"],
            "change_fields": [
                "target_path",
                "intent",
                "rationale",
                "evidence_node_ids",
                "investigation_item_ids",
                "explanation_statement_ids",
            ],
            "forbidden_content": [
                "diff",
                "patch",
                "code",
                "replacement",
                "commands",
                "approved",
                "release_decision",
                "gate_effect",
                "confidence",
                "severity",
            ],
        },
        "explanation_context": evidence_explanation_to_primitive(request.explanation),
    }


def remediation_proposal_to_primitive(result: RemediationProposalResult) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "inspection_sha256": result.inspection_sha256,
        "investigation_request_sha256": result.investigation_request_sha256,
        "investigation_sha256": result.investigation_sha256,
        "explanation_request_sha256": result.explanation_request_sha256,
        "explanation_sha256": result.explanation_sha256,
        "request_sha256": result.request_sha256,
        "proposal_sha256": result.proposal_sha256,
        "selected_node_id": result.selected_node_id,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "execution_status": result.execution_status,
        "approval_status": result.approval_status,
        "authority_contract": {
            "proposal_authority": "advisory_only",
            "release_authority": "persisted_policy_decision_only",
            "code_mutation": "forbidden",
            "patch_generation": "forbidden",
            "command_execution": "forbidden",
            "human_approval_required_before_patch": True,
        },
        "source": {
            "provider": result.source_provider,
            "declared_model": result.declared_model,
            "identity_status": result.identity_status,
            "source_format": result.source_format,
        },
        "raw_input": {"sha256": result.raw_input_sha256, "size_bytes": result.raw_input_size_bytes},
        "normalized_output_sha256": result.normalized_output_sha256,
        "objective": to_primitive(result.objective),
        "changes": [to_primitive(item) for item in result.changes],
        "verification_goals": [to_primitive(item) for item in result.verification_goals],
        "risks": [to_primitive(item) for item in result.risks],
    }


def render_remediation_proposal_request_json(request: RemediationProposalRequest) -> str:
    return dumps(remediation_proposal_request_to_primitive(request), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_remediation_proposal_json(result: RemediationProposalResult) -> str:
    return dumps(remediation_proposal_to_primitive(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_remediation_proposal_request_markdown(request: RemediationProposalRequest) -> str:
    lines = [
        "# Before Deploy Remediation Proposal Request",
        "",
        f"- Selected node: `{request.selected_node_id}`",
        f"- Explanation SHA-256: `{request.explanation_sha256}`",
        f"- Request SHA-256: `{request.request_sha256}`",
        f"- Authority: `{request.authority}`",
        f"- Gate effect: `{request.gate_effect}`",
        "",
        "## Boundary",
        "",
        "This request permits a non-executable remediation plan only.",
        "Do not include code, diffs, replacement text, shell commands, approval claims, or release decisions.",
        "Every objective/change/verification/risk statement must cite bounded evidence, investigation, or explanation identifiers.",
        "Target paths describe intended scope only and do not authorize file access or mutation.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def render_remediation_proposal_markdown(result: RemediationProposalResult) -> str:
    model = result.declared_model or "UNATTESTED"
    lines = [
        "# Before Deploy Remediation Proposal",
        "",
        f"- Proposal SHA-256: `{result.proposal_sha256}`",
        f"- Provider declaration: `{result.source_provider}`",
        f"- Declared model: `{model}`",
        f"- Identity status: `{result.identity_status}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        f"- Execution status: `{result.execution_status}`",
        f"- Approval status: `{result.approval_status}`",
        "",
        "## Objective",
        "",
        result.objective.text,
        "",
        "## Proposed changes",
        "",
    ]
    for item in result.changes:
        lines.append(f"- `{item.target_path}` — {item.intent}")
    lines.extend(["", "## Verification goals", ""])
    for item in result.verification_goals:
        lines.append(f"- `{item.kind}` — {item.statement}")
    lines.extend(["", "## Risks", ""])
    if result.risks:
        for item in result.risks:
            lines.append(f"- {item.statement}")
    else:
        lines.append("No bounded risk statements were supplied.")
    lines.extend(
        [
            "",
            "## Authority boundary",
            "",
            "This artifact is a proposal only. It contains no patch and performs no mutation.",
            "A later patch stage must require separate human approval; this artifact cannot approve itself.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_remediation_proposal_request_terminal(request: RemediationProposalRequest) -> str:
    return (
        "Before Deploy remediation proposal request\n"
        f"Selected node: {request.selected_node_id}\n"
        f"Explanation SHA-256: {request.explanation_sha256}\n"
        f"Request SHA-256: {request.request_sha256}\n"
        f"Authority: {request.authority}, gate_effect={request.gate_effect}\n"
    )


def render_remediation_proposal_terminal(result: RemediationProposalResult) -> str:
    return (
        "Before Deploy remediation proposal: ADVISORY / NON_EXECUTABLE\n"
        f"Selected node: {result.selected_node_id}\n"
        f"Changes: {len(result.changes)}, verification goals: {len(result.verification_goals)}, risks: {len(result.risks)}\n"
        f"Proposal SHA-256: {result.proposal_sha256}\n"
        f"Approval: {result.approval_status}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def _parse_declared_source(value: Any) -> tuple[str, str | None]:
    if not isinstance(value, dict):
        raise ValueError("Remediation proposal source must be an object")
    _require_keys(value, allowed={"provider", "model"}, required={"provider"}, label="remediation proposal source")
    provider = _bounded_text(value["provider"], "source provider", MAX_REMEDIATION_IDENTITY_CHARS)
    model_value = value.get("model")
    model = _bounded_text(model_value, "declared model", MAX_REMEDIATION_IDENTITY_CHARS) if model_value is not None else None
    return provider, model


def _parse_objective(value: Any, request: RemediationProposalRequest) -> RemediationObjective:
    if not isinstance(value, dict):
        raise ValueError("Remediation objective must be an object")
    _require_keys(
        value,
        allowed={"text", "evidence_node_ids", "investigation_item_ids", "explanation_statement_ids"},
        required={"text"},
        label="remediation objective",
    )
    text = _bounded_text(value["text"], "remediation objective")
    citations = _parse_citations(value, request, "remediation objective")
    semantic = {"text": text, "citations": to_primitive(citations)}
    return RemediationObjective(_diagnostic_id("remediation-objective", semantic), text, citations)


def _parse_changes(value: Any, request: RemediationProposalRequest) -> tuple[RemediationChange, ...]:
    items = _list_of_objects(value, "changes", MAX_REMEDIATION_CHANGES)
    if not items:
        raise ValueError("Remediation proposal must contain at least one proposed change")
    parsed: dict[str, RemediationChange] = {}
    for payload in items:
        _require_keys(
            payload,
            allowed={
                "target_path",
                "intent",
                "rationale",
                "evidence_node_ids",
                "investigation_item_ids",
                "explanation_statement_ids",
            },
            required={"target_path", "intent"},
            label="remediation change",
        )
        target_path = _target_path(payload["target_path"])
        intent = _bounded_text(payload["intent"], "remediation change intent")
        rationale = _optional_text(payload.get("rationale"), "remediation change rationale")
        citations = _parse_citations(payload, request, "remediation change")
        semantic = {
            "target_path": target_path,
            "intent": intent,
            "rationale": rationale,
            "citations": to_primitive(citations),
        }
        item_id = _diagnostic_id("remediation-change", semantic)
        parsed[item_id] = RemediationChange(item_id, target_path, intent, rationale, citations)
    return tuple(parsed[key] for key in sorted(parsed))


def _parse_verification_goals(value: Any, request: RemediationProposalRequest) -> tuple[RemediationVerificationGoal, ...]:
    items = _list_of_objects(value, "verification_goals", MAX_REMEDIATION_VERIFICATION_GOALS)
    if not items:
        raise ValueError("Remediation proposal must contain at least one verification goal")
    parsed: dict[str, RemediationVerificationGoal] = {}
    for payload in items:
        _require_keys(
            payload,
            allowed={
                "kind",
                "statement",
                "evidence_node_ids",
                "investigation_item_ids",
                "explanation_statement_ids",
            },
            required={"kind", "statement"},
            label="verification goal",
        )
        kind = payload["kind"]
        if kind not in VERIFICATION_KINDS:
            raise ValueError(f"Unsupported verification goal kind: {kind!r}")
        statement = _bounded_text(payload["statement"], "verification goal statement")
        citations = _parse_citations(payload, request, "verification goal")
        semantic = {"kind": kind, "statement": statement, "citations": to_primitive(citations)}
        item_id = _diagnostic_id("remediation-verification", semantic)
        parsed[item_id] = RemediationVerificationGoal(item_id, kind, statement, citations)
    return tuple(parsed[key] for key in sorted(parsed))


def _parse_risks(value: Any, request: RemediationProposalRequest) -> tuple[RemediationRisk, ...]:
    items = _list_of_objects(value, "risks", MAX_REMEDIATION_RISKS)
    parsed: dict[str, RemediationRisk] = {}
    for payload in items:
        _require_keys(
            payload,
            allowed={"statement", "evidence_node_ids", "investigation_item_ids", "explanation_statement_ids"},
            required={"statement"},
            label="remediation risk",
        )
        statement = _bounded_text(payload["statement"], "remediation risk statement")
        citations = _parse_citations(payload, request, "remediation risk")
        semantic = {"statement": statement, "citations": to_primitive(citations)}
        item_id = _diagnostic_id("remediation-risk", semantic)
        parsed[item_id] = RemediationRisk(item_id, statement, citations)
    return tuple(parsed[key] for key in sorted(parsed))


def _parse_citations(payload: dict[str, Any], request: RemediationProposalRequest, label: str) -> RemediationCitation:
    evidence = _citation_ids(payload.get("evidence_node_ids", []), request.allowed_evidence_node_ids, label, "evidence node")
    investigation = _citation_ids(
        payload.get("investigation_item_ids", []),
        request.allowed_investigation_item_ids,
        label,
        "investigation item",
    )
    explanation = _citation_ids(
        payload.get("explanation_statement_ids", []),
        request.allowed_explanation_statement_ids,
        label,
        "explanation statement",
    )
    if not evidence and not investigation and not explanation:
        raise ValueError(f"{label} must cite bounded evidence, investigation, or explanation context")
    return RemediationCitation(evidence, investigation, explanation)


def _citation_ids(value: Any, allowed: tuple[str, ...], label: str, kind: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} {kind} citations must be a list of strings")
    result = tuple(sorted(set(value)))
    allowed_set = set(allowed)
    invalid = [item for item in result if item not in allowed_set]
    if invalid:
        raise ValueError(f"{label} {kind} citation escapes bounded context: {invalid[0]}")
    return result


def _validate_objective(item: RemediationObjective, request: RemediationProposalRequest) -> None:
    _bounded_text(item.text, "remediation objective")
    _validate_citations(item.citations, request, "remediation objective")
    semantic = {"text": item.text, "citations": to_primitive(item.citations)}
    if item.objective_id != _diagnostic_id("remediation-objective", semantic):
        raise ValueError("Remediation objective ID mismatch")


def _validate_change(item: RemediationChange, request: RemediationProposalRequest) -> None:
    if item.target_path != _target_path(item.target_path):
        raise ValueError("Remediation change target path is not canonical")
    _bounded_text(item.intent, "remediation change intent")
    _optional_text(item.rationale, "remediation change rationale")
    _validate_citations(item.citations, request, "remediation change")
    semantic = {
        "target_path": item.target_path,
        "intent": item.intent,
        "rationale": item.rationale,
        "citations": to_primitive(item.citations),
    }
    if item.change_id != _diagnostic_id("remediation-change", semantic):
        raise ValueError("Remediation change ID mismatch")


def _validate_verification_goal(item: RemediationVerificationGoal, request: RemediationProposalRequest) -> None:
    if item.kind not in VERIFICATION_KINDS:
        raise ValueError("Unsupported remediation verification goal kind")
    _bounded_text(item.statement, "verification goal statement")
    _validate_citations(item.citations, request, "verification goal")
    semantic = {"kind": item.kind, "statement": item.statement, "citations": to_primitive(item.citations)}
    if item.verification_goal_id != _diagnostic_id("remediation-verification", semantic):
        raise ValueError("Remediation verification goal ID mismatch")


def _validate_risk(item: RemediationRisk, request: RemediationProposalRequest) -> None:
    _bounded_text(item.statement, "remediation risk statement")
    _validate_citations(item.citations, request, "remediation risk")
    semantic = {"statement": item.statement, "citations": to_primitive(item.citations)}
    if item.risk_id != _diagnostic_id("remediation-risk", semantic):
        raise ValueError("Remediation risk ID mismatch")


def _validate_citations(citations: RemediationCitation, request: RemediationProposalRequest, label: str) -> None:
    for actual, allowed, kind in (
        (citations.evidence_node_ids, request.allowed_evidence_node_ids, "evidence node"),
        (citations.investigation_item_ids, request.allowed_investigation_item_ids, "investigation item"),
        (citations.explanation_statement_ids, request.allowed_explanation_statement_ids, "explanation statement"),
    ):
        if actual != tuple(sorted(set(actual))):
            raise ValueError(f"{label} {kind} citations must be unique and sorted")
        if any(item not in set(allowed) for item in actual):
            raise ValueError(f"{label} {kind} citation escapes bounded context")
    if not citations.evidence_node_ids and not citations.investigation_item_ids and not citations.explanation_statement_ids:
        raise ValueError(f"{label} must have at least one bounded citation")


def _target_path(value: Any) -> str:
    text = _bounded_text(value, "remediation target path", MAX_REMEDIATION_PATH_CHARS)
    if "\\" in text or text.startswith("/"):
        raise ValueError("Remediation target path must be repository-relative POSIX syntax")
    path = PurePosixPath(text)
    if str(path) != text or text in (".", "") or any(part in (".", "..") for part in path.parts):
        raise ValueError("Remediation target path must be canonical and cannot traverse parents")
    return text


def _explanation_statement_ids(explanation: EvidenceExplanationResult) -> tuple[str, ...]:
    values = [explanation.summary.statement_id]
    values.extend(item.statement_id for item in explanation.details)
    values.extend(item.statement_id for item in explanation.limitations)
    return tuple(sorted(values))


def _list_of_objects(value: Any, label: str, maximum: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    if len(value) > maximum:
        raise ValueError(f"{label} contains too many items: {len(value)} > {maximum}")
    if any(not isinstance(item, dict) for item in value):
        raise ValueError(f"Every {label} item must be an object")
    return value


def _require_keys(payload: dict[str, Any], *, allowed: set[str], required: set[str], label: str) -> None:
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"Missing {label} field: {missing[0]}")
    extras = sorted(set(payload) - allowed)
    if extras:
        raise ValueError(f"Unsupported {label} field: {extras[0]}")


def _bounded_text(value: Any, label: str, maximum: int = MAX_REMEDIATION_TEXT_CHARS) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{label} must not be empty")
    if len(text) > maximum:
        raise ValueError(f"{label} exceeds maximum length")
    return text


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label)


def _canonical_sha256(value: Any) -> str:
    return sha256(dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _diagnostic_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{_canonical_sha256(value)}"


def _request_digest(request: RemediationProposalRequest) -> str:
    payload = {
        "schema_version": request.schema_version,
        "source_review_sha256": request.source_review_sha256,
        "graph_sha256": request.graph_sha256,
        "correlation_sha256": request.correlation_sha256,
        "corroboration_sha256": request.corroboration_sha256,
        "inspection_sha256": request.inspection_sha256,
        "investigation_request_sha256": request.investigation_request_sha256,
        "investigation_sha256": request.investigation_sha256,
        "explanation_request_sha256": request.explanation_request_sha256,
        "explanation_sha256": request.explanation_sha256,
        "selected_node_id": request.selected_node_id,
        "allowed_evidence_node_ids": request.allowed_evidence_node_ids,
        "allowed_investigation_item_ids": request.allowed_investigation_item_ids,
        "allowed_explanation_statement_ids": request.allowed_explanation_statement_ids,
        "authority": request.authority,
        "gate_effect": request.gate_effect,
    }
    return _canonical_sha256(payload)


def _proposal_digest(result: RemediationProposalResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "inspection_sha256": result.inspection_sha256,
        "investigation_request_sha256": result.investigation_request_sha256,
        "investigation_sha256": result.investigation_sha256,
        "explanation_request_sha256": result.explanation_request_sha256,
        "explanation_sha256": result.explanation_sha256,
        "request_sha256": result.request_sha256,
        "selected_node_id": result.selected_node_id,
        "source_provider": result.source_provider,
        "declared_model": result.declared_model,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "raw_input_sha256": result.raw_input_sha256,
        "raw_input_size_bytes": result.raw_input_size_bytes,
        "normalized_output_sha256": result.normalized_output_sha256,
        "execution_status": result.execution_status,
        "approval_status": result.approval_status,
        "objective": to_primitive(result.objective),
        "changes": [to_primitive(item) for item in result.changes],
        "verification_goals": [to_primitive(item) for item in result.verification_goals],
        "risks": [to_primitive(item) for item in result.risks],
        "authority": result.authority,
        "gate_effect": result.gate_effect,
    }
    return _canonical_sha256(payload)


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
