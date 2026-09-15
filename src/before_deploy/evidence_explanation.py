"""Evidence-cited advisory explanations over validated inspection and investigation context."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path
from typing import Any

from before_deploy.evidence_inspect import (
    EvidenceInspectionResult,
    evidence_inspection_to_primitive,
)
from before_deploy.evidence_investigation import (
    EvidenceInvestigationRequest,
    EvidenceInvestigationResult,
    evidence_investigation_to_primitive,
    validate_evidence_investigation,
    validate_evidence_investigation_request,
)
from before_deploy.models import to_primitive

EVIDENCE_EXPLANATION_SCHEMA_VERSION = 1
EVIDENCE_EXPLANATION_REQUEST_AUTHORITY = "EXPLANATION_CONTEXT"
EVIDENCE_EXPLANATION_AUTHORITY = "EXPLANATION_ADVISORY"
EVIDENCE_EXPLANATION_GATE_EFFECT = "NONE"
EVIDENCE_EXPLANATION_SOURCE_FORMAT = "before-deploy-explanation-v1"
EVIDENCE_EXPLANATION_IDENTITY_STATUS = "DECLARED_UNATTESTED"
DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES = 500_000
MAX_EXPLANATION_DETAILS = 64
MAX_EXPLANATION_LIMITATIONS = 32
MAX_EXPLANATION_ITEMS_TOTAL = 96
MAX_EXPLANATION_TEXT_CHARS = 8_000
MAX_EXPLANATION_IDENTITY_CHARS = 200


@dataclass(frozen=True)
class EvidenceExplanationRequest:
    """Content-bound explanation context derived from validated evidence only."""

    schema_version: int
    source_review_sha256: str
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    inspection_sha256: str
    investigation_request_sha256: str
    investigation_sha256: str | None
    request_sha256: str
    selected_node_id: str
    allowed_evidence_node_ids: tuple[str, ...]
    allowed_investigation_item_ids: tuple[str, ...]
    inspection: EvidenceInspectionResult
    investigation: EvidenceInvestigationResult | None
    authority: str = EVIDENCE_EXPLANATION_REQUEST_AUTHORITY
    gate_effect: str = EVIDENCE_EXPLANATION_GATE_EFFECT


@dataclass(frozen=True)
class ExplanationStatement:
    """One content-addressed explanation statement with explicit citations."""

    statement_id: str
    text: str
    evidence_node_ids: tuple[str, ...]
    investigation_item_ids: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceExplanationResult:
    """Normalized, cited explanation that remains outside release authority."""

    schema_version: int
    source_review_sha256: str
    graph_sha256: str
    correlation_sha256: str
    corroboration_sha256: str
    inspection_sha256: str
    investigation_request_sha256: str
    investigation_sha256: str | None
    request_sha256: str
    explanation_sha256: str
    selected_node_id: str
    source_provider: str
    declared_model: str | None
    identity_status: str
    source_format: str
    raw_input_sha256: str
    raw_input_size_bytes: int
    normalized_output_sha256: str
    summary: ExplanationStatement
    details: tuple[ExplanationStatement, ...]
    limitations: tuple[ExplanationStatement, ...]
    authority: str = EVIDENCE_EXPLANATION_AUTHORITY
    gate_effect: str = EVIDENCE_EXPLANATION_GATE_EFFECT


def build_evidence_explanation_request(
    inspection: EvidenceInspectionResult,
    investigation_request: EvidenceInvestigationRequest,
    investigation: EvidenceInvestigationResult | None = None,
) -> EvidenceExplanationRequest:
    """Build bounded explanation context from inspection and optional investigation output."""
    validate_evidence_investigation_request(investigation_request)
    if investigation_request.inspection_sha256 != inspection.inspection_sha256:
        raise ValueError("Explanation context inspection does not match investigation request")
    if investigation_request.selected_node_id != inspection.selected_node_id:
        raise ValueError("Explanation context selected node does not match investigation request")
    if investigation is not None:
        validate_evidence_investigation(investigation, investigation_request)

    allowed_evidence = tuple(sorted(record.node.node_id for record in inspection.nodes))
    allowed_investigation = _investigation_item_ids(investigation)
    provisional = EvidenceExplanationRequest(
        schema_version=EVIDENCE_EXPLANATION_SCHEMA_VERSION,
        source_review_sha256=inspection.source_review_sha256,
        graph_sha256=inspection.graph_sha256,
        correlation_sha256=inspection.correlation_sha256,
        corroboration_sha256=inspection.corroboration_sha256,
        inspection_sha256=inspection.inspection_sha256,
        investigation_request_sha256=investigation_request.request_sha256,
        investigation_sha256=(investigation.investigation_sha256 if investigation is not None else None),
        request_sha256="",
        selected_node_id=inspection.selected_node_id,
        allowed_evidence_node_ids=allowed_evidence,
        allowed_investigation_item_ids=allowed_investigation,
        inspection=inspection,
        investigation=investigation,
    )
    result = EvidenceExplanationRequest(
        **{**provisional.__dict__, "request_sha256": _request_digest(provisional)}
    )
    validate_evidence_explanation_request(result, investigation_request)
    return result


def validate_evidence_explanation_request(
    request: EvidenceExplanationRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    """Validate upstream bindings and the explanation-context authority boundary."""
    validate_evidence_investigation_request(investigation_request)
    if request.schema_version != EVIDENCE_EXPLANATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence explanation request schema version")
    if (
        request.authority != EVIDENCE_EXPLANATION_REQUEST_AUTHORITY
        or request.gate_effect != EVIDENCE_EXPLANATION_GATE_EFFECT
    ):
        raise ValueError("Evidence explanation request must remain gate-neutral")
    inspection = request.inspection
    bindings = (
        (request.source_review_sha256, inspection.source_review_sha256, "review artifact"),
        (request.graph_sha256, inspection.graph_sha256, "evidence graph"),
        (request.correlation_sha256, inspection.correlation_sha256, "correlation result"),
        (request.corroboration_sha256, inspection.corroboration_sha256, "corroboration result"),
        (request.inspection_sha256, inspection.inspection_sha256, "inspection"),
        (
            request.investigation_request_sha256,
            investigation_request.request_sha256,
            "investigation request",
        ),
        (request.selected_node_id, inspection.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Evidence explanation request is bound to a different {label}")
    if inspection.inspection_sha256 != investigation_request.inspection_sha256:
        raise ValueError("Explanation inspection does not match investigation request")
    expected_evidence = tuple(sorted(record.node.node_id for record in inspection.nodes))
    if request.allowed_evidence_node_ids != expected_evidence:
        raise ValueError("Explanation evidence allow-list does not match inspection")

    if request.investigation is None:
        if request.investigation_sha256 is not None or request.allowed_investigation_item_ids:
            raise ValueError("Explanation request claims investigation context that is not present")
    else:
        validate_evidence_investigation(request.investigation, investigation_request)
        if request.investigation_sha256 != request.investigation.investigation_sha256:
            raise ValueError("Explanation request is bound to a different investigation")
        if request.allowed_investigation_item_ids != _investigation_item_ids(request.investigation):
            raise ValueError("Explanation investigation-item allow-list is invalid")
    if request.request_sha256 != _request_digest(request):
        raise ValueError("Evidence explanation request digest mismatch")


def load_evidence_explanation_response(
    path: Path,
    request: EvidenceExplanationRequest,
    investigation_request: EvidenceInvestigationRequest,
    *,
    max_bytes: int = DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES,
) -> EvidenceExplanationResult:
    """Load a strict cited explanation response bound to one explanation request."""
    validate_evidence_explanation_request(request, investigation_request)
    if max_bytes <= 0:
        raise ValueError("Explanation response byte limit must be positive")
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"Explanation response exceeds byte limit: {len(raw)} > {max_bytes}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Explanation response must be UTF-8 JSON") from error
    try:
        payload = loads(text)
    except JSONDecodeError as error:
        raise ValueError("Explanation response must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Explanation response root must be an object")

    _require_keys(
        payload,
        allowed={
            "schema_version",
            "request_sha256",
            "source",
            "summary",
            "details",
            "limitations",
        },
        required={
            "schema_version",
            "request_sha256",
            "source",
            "summary",
            "details",
            "limitations",
        },
        label="explanation response",
    )
    if payload["schema_version"] != EVIDENCE_EXPLANATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence explanation response schema version")
    if payload["request_sha256"] != request.request_sha256:
        raise ValueError("Explanation response is bound to a different request")

    provider, model = _parse_declared_source(payload["source"])
    summary = _parse_statement(payload["summary"], request, "summary", "explanation-summary")
    details = _parse_statement_list(
        payload["details"],
        request,
        "detail",
        "explanation-detail",
        MAX_EXPLANATION_DETAILS,
    )
    limitations = _parse_statement_list(
        payload["limitations"],
        request,
        "limitation",
        "explanation-limitation",
        MAX_EXPLANATION_LIMITATIONS,
    )
    if len(details) + len(limitations) > MAX_EXPLANATION_ITEMS_TOTAL:
        raise ValueError("Explanation response contains too many structured items")

    normalized_payload = {
        "source_provider": provider,
        "declared_model": model,
        "identity_status": EVIDENCE_EXPLANATION_IDENTITY_STATUS,
        "source_format": EVIDENCE_EXPLANATION_SOURCE_FORMAT,
        "summary": to_primitive(summary),
        "details": [to_primitive(item) for item in details],
        "limitations": [to_primitive(item) for item in limitations],
    }
    normalized_sha = _canonical_sha256(normalized_payload)
    provisional = EvidenceExplanationResult(
        schema_version=EVIDENCE_EXPLANATION_SCHEMA_VERSION,
        source_review_sha256=request.source_review_sha256,
        graph_sha256=request.graph_sha256,
        correlation_sha256=request.correlation_sha256,
        corroboration_sha256=request.corroboration_sha256,
        inspection_sha256=request.inspection_sha256,
        investigation_request_sha256=request.investigation_request_sha256,
        investigation_sha256=request.investigation_sha256,
        request_sha256=request.request_sha256,
        explanation_sha256="",
        selected_node_id=request.selected_node_id,
        source_provider=provider,
        declared_model=model,
        identity_status=EVIDENCE_EXPLANATION_IDENTITY_STATUS,
        source_format=EVIDENCE_EXPLANATION_SOURCE_FORMAT,
        raw_input_sha256=sha256(raw).hexdigest(),
        raw_input_size_bytes=len(raw),
        normalized_output_sha256=normalized_sha,
        summary=summary,
        details=details,
        limitations=limitations,
    )
    result = EvidenceExplanationResult(
        **{**provisional.__dict__, "explanation_sha256": _explanation_digest(provisional)}
    )
    validate_evidence_explanation(result, request, investigation_request)
    return result


def validate_evidence_explanation(
    result: EvidenceExplanationResult,
    request: EvidenceExplanationRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    """Reject authority drift, binding drift, forged IDs, and uncited explanation text."""
    validate_evidence_explanation_request(request, investigation_request)
    if result.schema_version != EVIDENCE_EXPLANATION_SCHEMA_VERSION:
        raise ValueError("Unsupported evidence explanation schema version")
    if result.authority != EVIDENCE_EXPLANATION_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Evidence explanation must remain advisory and gate-neutral")
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
        (result.request_sha256, request.request_sha256, "request"),
        (result.selected_node_id, request.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Evidence explanation is bound to a different {label}")
    if result.identity_status != EVIDENCE_EXPLANATION_IDENTITY_STATUS:
        raise ValueError("Explainer identity must remain declared and unattested")
    if result.source_format != EVIDENCE_EXPLANATION_SOURCE_FORMAT:
        raise ValueError("Unsupported evidence explanation source format")
    _bounded_text(result.source_provider, "source provider", MAX_EXPLANATION_IDENTITY_CHARS)
    if result.declared_model is not None:
        _bounded_text(result.declared_model, "declared model", MAX_EXPLANATION_IDENTITY_CHARS)
    if result.raw_input_size_bytes <= 0:
        raise ValueError("Explanation raw input size must be positive")
    if not _is_sha256(result.raw_input_sha256):
        raise ValueError("Explanation raw input digest must be SHA-256")

    _validate_statement(result.summary, request, "explanation-summary")
    for item in result.details:
        _validate_statement(item, request, "explanation-detail")
    for item in result.limitations:
        _validate_statement(item, request, "explanation-limitation")
    if len(result.details) > MAX_EXPLANATION_DETAILS:
        raise ValueError("Explanation contains too many detail statements")
    if len(result.limitations) > MAX_EXPLANATION_LIMITATIONS:
        raise ValueError("Explanation contains too many limitation statements")
    if len(result.details) + len(result.limitations) > MAX_EXPLANATION_ITEMS_TOTAL:
        raise ValueError("Explanation contains too many structured items")

    normalized_payload = {
        "source_provider": result.source_provider,
        "declared_model": result.declared_model,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "summary": to_primitive(result.summary),
        "details": [to_primitive(item) for item in result.details],
        "limitations": [to_primitive(item) for item in result.limitations],
    }
    if result.normalized_output_sha256 != _canonical_sha256(normalized_payload):
        raise ValueError("Explanation normalized output digest mismatch")
    if result.explanation_sha256 != _explanation_digest(result):
        raise ValueError("Evidence explanation digest mismatch")


def evidence_explanation_request_to_primitive(request: EvidenceExplanationRequest) -> dict[str, Any]:
    """Serialize bounded explanation context without raw provider/source payloads."""
    return {
        "schema_version": request.schema_version,
        "source_review_sha256": request.source_review_sha256,
        "graph_sha256": request.graph_sha256,
        "correlation_sha256": request.correlation_sha256,
        "corroboration_sha256": request.corroboration_sha256,
        "inspection_sha256": request.inspection_sha256,
        "investigation_request_sha256": request.investigation_request_sha256,
        "investigation_sha256": request.investigation_sha256,
        "request_sha256": request.request_sha256,
        "selected_node_id": request.selected_node_id,
        "allowed_evidence_node_ids": list(request.allowed_evidence_node_ids),
        "allowed_investigation_item_ids": list(request.allowed_investigation_item_ids),
        "authority": request.authority,
        "gate_effect": request.gate_effect,
        "authority_contract": {
            "request_authority": "context_only",
            "explanation_authority": "advisory_only",
            "release_authority": "persisted_policy_decision_only",
            "new_evidence_creation": "forbidden",
            "finding_authority_promotion": "forbidden",
            "confidence_or_severity_promotion": "forbidden",
            "remediation_proposal": "out_of_scope",
        },
        "response_contract": {
            "schema_version": EVIDENCE_EXPLANATION_SCHEMA_VERSION,
            "source_format": EVIDENCE_EXPLANATION_SOURCE_FORMAT,
            "required_top_level_fields": [
                "schema_version",
                "request_sha256",
                "source",
                "summary",
                "details",
                "limitations",
            ],
            "statement_fields": ["text", "evidence_node_ids", "investigation_item_ids"],
            "citations_required": True,
            "provider_statement_ids": "not_accepted_content_addressed_by_before_deploy",
        },
        "inspection_context": evidence_inspection_to_primitive(request.inspection),
        "investigation_context": (
            evidence_investigation_to_primitive(request.investigation)
            if request.investigation is not None
            else None
        ),
    }


def evidence_explanation_to_primitive(result: EvidenceExplanationResult) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "inspection_sha256": result.inspection_sha256,
        "investigation_request_sha256": result.investigation_request_sha256,
        "investigation_sha256": result.investigation_sha256,
        "request_sha256": result.request_sha256,
        "explanation_sha256": result.explanation_sha256,
        "selected_node_id": result.selected_node_id,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "authority_contract": {
            "explanation_authority": "advisory_only",
            "release_authority": "persisted_policy_decision_only",
            "citations": "bounded_request_ids_only",
            "new_evidence_creation": "forbidden",
            "policy_mutation": "forbidden",
            "confidence_or_severity_promotion": "forbidden",
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
        "summary": to_primitive(result.summary),
        "details": [to_primitive(item) for item in result.details],
        "limitations": [to_primitive(item) for item in result.limitations],
    }


def render_evidence_explanation_request_json(request: EvidenceExplanationRequest) -> str:
    return dumps(evidence_explanation_request_to_primitive(request), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_evidence_explanation_json(result: EvidenceExplanationResult) -> str:
    return dumps(evidence_explanation_to_primitive(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_evidence_explanation_request_markdown(request: EvidenceExplanationRequest) -> str:
    lines = [
        "# Before Deploy Explanation Request",
        "",
        f"- Selected node: `{request.selected_node_id}`",
        f"- Inspection SHA-256: `{request.inspection_sha256}`",
        f"- Investigation SHA-256: `{request.investigation_sha256 or 'NONE'}`",
        f"- Request SHA-256: `{request.request_sha256}`",
        f"- Evidence node citations available: **{len(request.allowed_evidence_node_ids)}**",
        f"- Investigation item citations available: **{len(request.allowed_investigation_item_ids)}**",
        f"- Authority: `{request.authority}`",
        f"- Gate effect: `{request.gate_effect}`",
        "",
        "## Explanation boundary",
        "",
        "The explainer may summarize and connect only the supplied inspection/investigation material.",
        "Every summary, detail, and limitation must cite at least one allow-listed evidence node or investigation item.",
        "The explainer may not introduce new evidence, change severity/confidence, propose release status, or create remediation proposals.",
        "Provider/model identity is treated as declared and unattested.",
        "",
        "## Evidence node IDs",
        "",
    ]
    lines.extend(f"- `{value}`" for value in request.allowed_evidence_node_ids)
    lines.extend(["", "## Investigation item IDs", ""])
    if request.allowed_investigation_item_ids:
        lines.extend(f"- `{value}`" for value in request.allowed_investigation_item_ids)
    else:
        lines.append("No investigation items were supplied.")
    return "\n".join(lines).rstrip() + "\n"


def render_evidence_explanation_markdown(result: EvidenceExplanationResult) -> str:
    model = result.declared_model or "UNATTESTED"
    lines = [
        "# Before Deploy Evidence Explanation",
        "",
        f"- Selected node: `{result.selected_node_id}`",
        f"- Provider declaration: `{result.source_provider}`",
        f"- Declared model: `{model}`",
        f"- Identity status: `{result.identity_status}`",
        f"- Inspection SHA-256: `{result.inspection_sha256}`",
        f"- Investigation SHA-256: `{result.investigation_sha256 or 'NONE'}`",
        f"- Explanation SHA-256: `{result.explanation_sha256}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "## Authority boundary",
        "",
        "This explanation is advisory presentation over already-recorded evidence and investigation content.",
        "It does not create new evidence, modify `PolicyDecision`, promote finding authority, or change severity/confidence.",
        "",
        "## Summary",
        "",
    ]
    _append_statement_markdown(lines, result.summary)
    lines.extend(["", "## Details", ""])
    if result.details:
        for item in result.details:
            _append_statement_markdown(lines, item)
    else:
        lines.append("No additional detail statements were supplied.")
    lines.extend(["", "## Limitations", ""])
    if result.limitations:
        for item in result.limitations:
            _append_statement_markdown(lines, item)
    else:
        lines.append("No explicit limitations were supplied.")
    return "\n".join(lines).rstrip() + "\n"


def render_evidence_explanation_request_terminal(request: EvidenceExplanationRequest) -> str:
    return (
        "Before Deploy explanation request\n"
        f"Selected node: {request.selected_node_id}\n"
        f"Inspection SHA-256: {request.inspection_sha256}\n"
        f"Investigation SHA-256: {request.investigation_sha256 or 'NONE'}\n"
        f"Request SHA-256: {request.request_sha256}\n"
        f"Citation targets: evidence={len(request.allowed_evidence_node_ids)}, investigation={len(request.allowed_investigation_item_ids)}\n"
        f"Authority: {request.authority}, gate_effect={request.gate_effect}\n"
    )


def render_evidence_explanation_terminal(result: EvidenceExplanationResult) -> str:
    return (
        "Before Deploy explanation: ADVISORY\n"
        f"Selected node: {result.selected_node_id}\n"
        f"Provider: {result.source_provider} (identity={result.identity_status})\n"
        f"Statements: summary=1, details={len(result.details)}, limitations={len(result.limitations)}\n"
        f"Explanation SHA-256: {result.explanation_sha256}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def _parse_declared_source(value: Any) -> tuple[str, str | None]:
    if not isinstance(value, dict):
        raise ValueError("Explanation source must be an object")
    _require_keys(value, allowed={"provider", "model"}, required={"provider"}, label="explanation source")
    provider = _bounded_text(value["provider"], "source provider", MAX_EXPLANATION_IDENTITY_CHARS)
    model_value = value.get("model")
    model = (
        _bounded_text(model_value, "declared model", MAX_EXPLANATION_IDENTITY_CHARS)
        if model_value is not None
        else None
    )
    return provider, model


def _parse_statement_list(
    value: Any,
    request: EvidenceExplanationRequest,
    label: str,
    id_kind: str,
    maximum: int,
) -> tuple[ExplanationStatement, ...]:
    if not isinstance(value, list):
        raise ValueError(f"Explanation {label}s must be an array")
    if len(value) > maximum:
        raise ValueError(f"Explanation contains too many {label}s: {len(value)} > {maximum}")
    parsed: dict[str, ExplanationStatement] = {}
    for item in value:
        statement = _parse_statement(item, request, label, id_kind)
        parsed[statement.statement_id] = statement
    return tuple(parsed[key] for key in sorted(parsed))


def _parse_statement(
    value: Any,
    request: EvidenceExplanationRequest,
    label: str,
    id_kind: str,
) -> ExplanationStatement:
    if not isinstance(value, dict):
        raise ValueError(f"Explanation {label} must be an object")
    _require_keys(
        value,
        allowed={"text", "evidence_node_ids", "investigation_item_ids"},
        required={"text", "evidence_node_ids", "investigation_item_ids"},
        label=f"explanation {label}",
    )
    text = _bounded_text(value["text"], f"explanation {label} text")
    evidence_ids = _bounded_ids(
        value["evidence_node_ids"],
        set(request.allowed_evidence_node_ids),
        f"explanation {label} evidence",
    )
    investigation_ids = _bounded_ids(
        value["investigation_item_ids"],
        set(request.allowed_investigation_item_ids),
        f"explanation {label} investigation",
    )
    if not evidence_ids and not investigation_ids:
        raise ValueError(f"Explanation {label} must cite at least one bounded source")
    semantic = {
        "text": text,
        "evidence_node_ids": evidence_ids,
        "investigation_item_ids": investigation_ids,
    }
    return ExplanationStatement(
        statement_id=_diagnostic_id(id_kind, semantic),
        text=text,
        evidence_node_ids=evidence_ids,
        investigation_item_ids=investigation_ids,
    )


def _validate_statement(
    item: ExplanationStatement,
    request: EvidenceExplanationRequest,
    id_kind: str,
) -> None:
    _bounded_text(item.text, "explanation statement")
    allowed_evidence = set(request.allowed_evidence_node_ids)
    allowed_investigation = set(request.allowed_investigation_item_ids)
    if tuple(sorted(set(item.evidence_node_ids))) != item.evidence_node_ids:
        raise ValueError("Explanation evidence citations must be unique and sorted")
    if tuple(sorted(set(item.investigation_item_ids))) != item.investigation_item_ids:
        raise ValueError("Explanation investigation citations must be unique and sorted")
    if any(value not in allowed_evidence for value in item.evidence_node_ids):
        raise ValueError("Explanation evidence citation escapes bounded request context")
    if any(value not in allowed_investigation for value in item.investigation_item_ids):
        raise ValueError("Explanation investigation citation escapes bounded request context")
    if not item.evidence_node_ids and not item.investigation_item_ids:
        raise ValueError("Explanation statement must cite at least one bounded source")
    semantic = {
        "text": item.text,
        "evidence_node_ids": item.evidence_node_ids,
        "investigation_item_ids": item.investigation_item_ids,
    }
    if item.statement_id != _diagnostic_id(id_kind, semantic):
        raise ValueError("Explanation statement ID is not content-addressed")


def _bounded_ids(value: Any, allowed: set[str], label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} citations must be an array of strings")
    result = tuple(sorted(set(value)))
    if any(item not in allowed for item in result):
        raise ValueError(f"{label} citation escapes bounded request context")
    return result


def _investigation_item_ids(
    investigation: EvidenceInvestigationResult | None,
) -> tuple[str, ...]:
    if investigation is None:
        return ()
    values = [item.hypothesis_id for item in investigation.hypotheses]
    values.extend(item.observation_id for item in investigation.observations)
    values.extend(item.question_id for item in investigation.questions)
    return tuple(sorted(values))


def _append_statement_markdown(lines: list[str], item: ExplanationStatement) -> None:
    lines.append(f"- {item.text}")
    if item.evidence_node_ids:
        lines.append("  - Evidence: " + ", ".join(f"`{value}`" for value in item.evidence_node_ids))
    if item.investigation_item_ids:
        lines.append(
            "  - Investigation: "
            + ", ".join(f"`{value}`" for value in item.investigation_item_ids)
        )
    lines.append(f"  - Statement ID: `{item.statement_id}`")


def _bounded_text(value: Any, label: str, maximum: int = MAX_EXPLANATION_TEXT_CHARS) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    result = value.strip()
    if not result:
        raise ValueError(f"{label} must not be empty")
    if len(result) > maximum:
        raise ValueError(f"{label} exceeds character limit: {len(result)} > {maximum}")
    return result


def _require_keys(
    payload: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    extras = sorted(set(payload) - allowed)
    if extras:
        raise ValueError(f"Unsupported {label} field: {extras[0]}")
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"Missing {label} field: {missing[0]}")


def _diagnostic_id(kind: str, payload: Any) -> str:
    return f"{kind}:{_canonical_sha256(payload)}"


def _request_digest(request: EvidenceExplanationRequest) -> str:
    payload = {
        "schema_version": request.schema_version,
        "source_review_sha256": request.source_review_sha256,
        "graph_sha256": request.graph_sha256,
        "correlation_sha256": request.correlation_sha256,
        "corroboration_sha256": request.corroboration_sha256,
        "inspection_sha256": request.inspection_sha256,
        "investigation_request_sha256": request.investigation_request_sha256,
        "investigation_sha256": request.investigation_sha256,
        "selected_node_id": request.selected_node_id,
        "allowed_evidence_node_ids": request.allowed_evidence_node_ids,
        "allowed_investigation_item_ids": request.allowed_investigation_item_ids,
        "authority": request.authority,
        "gate_effect": request.gate_effect,
    }
    return _canonical_sha256(payload)


def _explanation_digest(result: EvidenceExplanationResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "source_review_sha256": result.source_review_sha256,
        "graph_sha256": result.graph_sha256,
        "correlation_sha256": result.correlation_sha256,
        "corroboration_sha256": result.corroboration_sha256,
        "inspection_sha256": result.inspection_sha256,
        "investigation_request_sha256": result.investigation_request_sha256,
        "investigation_sha256": result.investigation_sha256,
        "request_sha256": result.request_sha256,
        "selected_node_id": result.selected_node_id,
        "source_provider": result.source_provider,
        "declared_model": result.declared_model,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "raw_input_sha256": result.raw_input_sha256,
        "raw_input_size_bytes": result.raw_input_size_bytes,
        "normalized_output_sha256": result.normalized_output_sha256,
        "summary": to_primitive(result.summary),
        "details": [to_primitive(item) for item in result.details],
        "limitations": [to_primitive(item) for item in result.limitations],
        "authority": result.authority,
        "gate_effect": result.gate_effect,
    }
    return _canonical_sha256(payload)


def _canonical_sha256(payload: Any) -> str:
    serialized = dumps(to_primitive(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
