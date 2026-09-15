"""Human approval and scoped patch artifacts over one exact remediation proposal."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path
from typing import TYPE_CHECKING, Any

from before_deploy.models import to_primitive
from before_deploy.remediation_proposal import (
    remediation_proposal_to_primitive,
    validate_remediation_proposal,
)

if TYPE_CHECKING:
    # Proposal and investigation request/result types appear only in annotations (this module has
    # `from __future__ import annotations`). Importing them under TYPE_CHECKING narrows this
    # module's dependency on the advisory plane to the two validators it genuinely calls at
    # runtime; it does not remove it, because validating a proposal is a runtime contract.
    from before_deploy.evidence_investigation import EvidenceInvestigationRequest
    from before_deploy.remediation_proposal import (
        RemediationProposalRequest,
        RemediationProposalResult,
    )

HUMAN_APPROVAL_SCHEMA_VERSION = 1
HUMAN_APPROVAL_AUTHORITY = "HUMAN_APPROVAL_WORKFLOW"
HUMAN_APPROVAL_GATE_EFFECT = "NONE"
HUMAN_APPROVAL_SOURCE_FORMAT = "before-deploy-human-approval-v1"
HUMAN_APPROVAL_IDENTITY_STATUS = "DECLARED_UNATTESTED"
HUMAN_APPROVAL_DECISIONS = ("APPROVE", "REJECT")

PATCH_SCHEMA_VERSION = 1
PATCH_REQUEST_AUTHORITY = "PATCH_CONTEXT"
PATCH_AUTHORITY = "PATCH_ARTIFACT"
PATCH_GATE_EFFECT = "NONE"
PATCH_SOURCE_FORMAT = "before-deploy-patch-v1"
PATCH_IDENTITY_STATUS = "DECLARED_UNATTESTED"
PATCH_APPLICATION_STATUS = "NOT_APPLIED"
PATCH_REVIEW_STATUS = "UNREVIEWED"
DEFAULT_MAX_PATCH_RESPONSE_BYTES = 2_000_000
MAX_APPROVER_CHARS = 200
MAX_APPROVAL_RATIONALE_CHARS = 4_000
MAX_PATCH_IDENTITY_CHARS = 200
MAX_PATCH_FILES = 64
MAX_PATCH_DIFF_CHARS = 500_000


@dataclass(frozen=True)
class HumanApproval:
    """Explicit workflow authorization bound to one exact remediation proposal."""

    schema_version: int
    proposal_request_sha256: str
    proposal_sha256: str
    approval_sha256: str
    selected_node_id: str
    decision: str
    approver: str
    identity_status: str
    rationale: str | None
    source_format: str
    authority: str = HUMAN_APPROVAL_AUTHORITY
    gate_effect: str = HUMAN_APPROVAL_GATE_EFFECT


@dataclass(frozen=True)
class PatchRequest:
    """Content-bound patch-generation context unlocked only by approval."""

    schema_version: int
    proposal_request_sha256: str
    proposal_sha256: str
    approval_sha256: str
    request_sha256: str
    selected_node_id: str
    allowed_target_paths: tuple[str, ...]
    verification_goal_ids: tuple[str, ...]
    proposal: RemediationProposalResult
    approval: HumanApproval
    authority: str = PATCH_REQUEST_AUTHORITY
    gate_effect: str = PATCH_GATE_EFFECT


@dataclass(frozen=True)
class PatchFile:
    """One content-addressed text patch for an approved proposal target."""

    patch_file_id: str
    target_path: str
    base_content_sha256: str
    patched_content_sha256: str
    diff_sha256: str
    unified_diff: str


@dataclass(frozen=True)
class PatchResult:
    """Normalized patch artifact. It is not applied and has no release authority."""

    schema_version: int
    proposal_request_sha256: str
    proposal_sha256: str
    approval_sha256: str
    request_sha256: str
    patch_sha256: str
    selected_node_id: str
    source_provider: str
    declared_model: str | None
    identity_status: str
    source_format: str
    raw_input_sha256: str
    raw_input_size_bytes: int
    normalized_output_sha256: str
    application_status: str
    review_status: str
    files: tuple[PatchFile, ...]
    authority: str = PATCH_AUTHORITY
    gate_effect: str = PATCH_GATE_EFFECT


def build_human_approval(
    proposal: RemediationProposalResult,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
    *,
    decision: str,
    approver: str,
    confirmed_proposal_sha256: str,
    rationale: str | None = None,
) -> HumanApproval:
    """Create explicit approval/rejection for one validated proposal digest."""
    validate_remediation_proposal(proposal, proposal_request, investigation_request)
    if confirmed_proposal_sha256 != proposal.proposal_sha256:
        raise ValueError("Confirmed proposal SHA-256 does not match the validated proposal")
    if decision not in HUMAN_APPROVAL_DECISIONS:
        raise ValueError(f"Unsupported human approval decision: {decision}")
    approver_value = _bounded_text(approver, "approver", MAX_APPROVER_CHARS)
    rationale_value = _optional_text(rationale, "approval rationale", MAX_APPROVAL_RATIONALE_CHARS)
    provisional = HumanApproval(
        schema_version=HUMAN_APPROVAL_SCHEMA_VERSION,
        proposal_request_sha256=proposal.request_sha256,
        proposal_sha256=proposal.proposal_sha256,
        approval_sha256="",
        selected_node_id=proposal.selected_node_id,
        decision=decision,
        approver=approver_value,
        identity_status=HUMAN_APPROVAL_IDENTITY_STATUS,
        rationale=rationale_value,
        source_format=HUMAN_APPROVAL_SOURCE_FORMAT,
    )
    result = HumanApproval(
        **{**provisional.__dict__, "approval_sha256": _approval_digest(provisional)}
    )
    validate_human_approval(result, proposal, proposal_request, investigation_request)
    return result


def validate_human_approval(
    approval: HumanApproval,
    proposal: RemediationProposalResult,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    """Validate exact proposal binding without granting release authority."""
    validate_remediation_proposal(proposal, proposal_request, investigation_request)
    if approval.schema_version != HUMAN_APPROVAL_SCHEMA_VERSION:
        raise ValueError("Unsupported human approval schema version")
    if approval.authority != HUMAN_APPROVAL_AUTHORITY or approval.gate_effect != "NONE":
        raise ValueError("Human approval must remain workflow-only and gate-neutral")
    bindings = (
        (approval.proposal_request_sha256, proposal.request_sha256, "proposal request"),
        (approval.proposal_sha256, proposal.proposal_sha256, "proposal"),
        (approval.selected_node_id, proposal.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Human approval is bound to a different {label}")
    if approval.decision not in HUMAN_APPROVAL_DECISIONS:
        raise ValueError("Human approval decision is invalid")
    if approval.identity_status != HUMAN_APPROVAL_IDENTITY_STATUS:
        raise ValueError("Human approval identity must remain declared and unattested")
    if approval.source_format != HUMAN_APPROVAL_SOURCE_FORMAT:
        raise ValueError("Unsupported human approval source format")
    _bounded_text(approval.approver, "approver", MAX_APPROVER_CHARS)
    _optional_text(approval.rationale, "approval rationale", MAX_APPROVAL_RATIONALE_CHARS)
    if approval.approval_sha256 != _approval_digest(approval):
        raise ValueError("Human approval digest mismatch")


def human_approval_to_primitive(approval: HumanApproval) -> dict[str, Any]:
    return {
        "schema_version": approval.schema_version,
        "proposal_request_sha256": approval.proposal_request_sha256,
        "proposal_sha256": approval.proposal_sha256,
        "approval_sha256": approval.approval_sha256,
        "selected_node_id": approval.selected_node_id,
        "decision": approval.decision,
        "approver": approval.approver,
        "identity_status": approval.identity_status,
        "rationale": approval.rationale,
        "source_format": approval.source_format,
        "authority": approval.authority,
        "gate_effect": approval.gate_effect,
        "authority_contract": {
            "approval_scope": "patch_generation_for_exact_proposal_only",
            "patch_application": "not_authorized_by_this_artifact",
            "release_authority": "persisted_policy_decision_only",
            "policy_mutation": "forbidden",
        },
    }


def render_human_approval_json(approval: HumanApproval) -> str:
    return dumps(human_approval_to_primitive(approval), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_human_approval_markdown(approval: HumanApproval) -> str:
    rationale = approval.rationale or "No rationale supplied."
    return (
        "# Before Deploy Human Approval\n\n"
        f"- Proposal SHA-256: `{approval.proposal_sha256}`\n"
        f"- Approval SHA-256: `{approval.approval_sha256}`\n"
        f"- Decision: `{approval.decision}`\n"
        f"- Approver declaration: `{approval.approver}`\n"
        f"- Identity status: `{approval.identity_status}`\n"
        f"- Authority: `{approval.authority}`\n"
        f"- Gate effect: `{approval.gate_effect}`\n\n"
        "## Rationale\n\n"
        f"{rationale}\n\n"
        "## Boundary\n\n"
        "This approval authorizes patch generation for exactly the bound proposal. "
        "It does not approve a generated patch, apply code, alter PolicyDecision, or authorize release.\n"
    )


def render_human_approval_terminal(approval: HumanApproval) -> str:
    return (
        "Before Deploy human approval\n"
        f"Proposal SHA-256: {approval.proposal_sha256}\n"
        f"Decision: {approval.decision}\n"
        f"Approval SHA-256: {approval.approval_sha256}\n"
        f"Authority: {approval.authority}, gate_effect={approval.gate_effect}\n"
    )


def load_human_approval_artifact(
    path: Path,
    proposal: RemediationProposalResult,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> HumanApproval:
    """Load only the canonical approval artifact emitted by Before Deploy."""
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("Human approval artifact must be UTF-8 JSON") from error
    except JSONDecodeError as error:
        raise ValueError("Human approval artifact must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Human approval artifact root must be an object")
    _require_keys(
        payload,
        allowed={
            "schema_version",
            "proposal_request_sha256",
            "proposal_sha256",
            "approval_sha256",
            "selected_node_id",
            "decision",
            "approver",
            "identity_status",
            "rationale",
            "source_format",
            "authority",
            "gate_effect",
            "authority_contract",
        },
        required={
            "schema_version",
            "proposal_request_sha256",
            "proposal_sha256",
            "approval_sha256",
            "selected_node_id",
            "decision",
            "approver",
            "identity_status",
            "rationale",
            "source_format",
            "authority",
            "gate_effect",
        },
        label="human approval artifact",
    )
    result = HumanApproval(
        schema_version=payload["schema_version"],
        proposal_request_sha256=payload["proposal_request_sha256"],
        proposal_sha256=payload["proposal_sha256"],
        approval_sha256=payload["approval_sha256"],
        selected_node_id=payload["selected_node_id"],
        decision=payload["decision"],
        approver=payload["approver"],
        identity_status=payload["identity_status"],
        rationale=payload["rationale"],
        source_format=payload["source_format"],
        authority=payload["authority"],
        gate_effect=payload["gate_effect"],
    )
    validate_human_approval(result, proposal, proposal_request, investigation_request)
    return result


def build_patch_request(
    proposal: RemediationProposalResult,
    proposal_request: RemediationProposalRequest,
    approval: HumanApproval,
    investigation_request: EvidenceInvestigationRequest,
) -> PatchRequest:
    """Build patch context only when the exact proposal has explicit approval."""
    validate_human_approval(approval, proposal, proposal_request, investigation_request)
    if approval.decision != "APPROVE":
        raise ValueError("Patch generation requires an APPROVE human approval decision")
    allowed_paths = tuple(sorted({item.target_path for item in proposal.changes}))
    if not allowed_paths or len(allowed_paths) > MAX_PATCH_FILES:
        raise ValueError("Approved proposal target count is outside patch bounds")
    verification_ids = tuple(sorted(item.verification_goal_id for item in proposal.verification_goals))
    provisional = PatchRequest(
        schema_version=PATCH_SCHEMA_VERSION,
        proposal_request_sha256=proposal.request_sha256,
        proposal_sha256=proposal.proposal_sha256,
        approval_sha256=approval.approval_sha256,
        request_sha256="",
        selected_node_id=proposal.selected_node_id,
        allowed_target_paths=allowed_paths,
        verification_goal_ids=verification_ids,
        proposal=proposal,
        approval=approval,
    )
    result = PatchRequest(
        **{**provisional.__dict__, "request_sha256": _patch_request_digest(provisional)}
    )
    validate_patch_request(result, proposal_request, investigation_request)
    return result


def validate_patch_request(
    request: PatchRequest,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    """Validate proposal/approval bindings before any patch content is accepted."""
    if request.schema_version != PATCH_SCHEMA_VERSION:
        raise ValueError("Unsupported patch request schema version")
    if request.authority != PATCH_REQUEST_AUTHORITY or request.gate_effect != "NONE":
        raise ValueError("Patch request must remain gate-neutral")
    validate_human_approval(
        request.approval,
        request.proposal,
        proposal_request,
        investigation_request,
    )
    if request.approval.decision != "APPROVE":
        raise ValueError("Patch request requires APPROVE human approval")
    bindings = (
        (request.proposal_request_sha256, request.proposal.request_sha256, "proposal request"),
        (request.proposal_sha256, request.proposal.proposal_sha256, "proposal"),
        (request.approval_sha256, request.approval.approval_sha256, "approval"),
        (request.selected_node_id, request.proposal.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Patch request is bound to a different {label}")
    expected_paths = tuple(sorted({item.target_path for item in request.proposal.changes}))
    if request.allowed_target_paths != expected_paths:
        raise ValueError("Patch request target paths do not match approved proposal")
    expected_verification = tuple(
        sorted(item.verification_goal_id for item in request.proposal.verification_goals)
    )
    if request.verification_goal_ids != expected_verification:
        raise ValueError("Patch request verification goals do not match approved proposal")
    if request.request_sha256 != _patch_request_digest(request):
        raise ValueError("Patch request digest mismatch")


def patch_request_to_primitive(request: PatchRequest) -> dict[str, Any]:
    return {
        "schema_version": request.schema_version,
        "proposal_request_sha256": request.proposal_request_sha256,
        "proposal_sha256": request.proposal_sha256,
        "approval_sha256": request.approval_sha256,
        "request_sha256": request.request_sha256,
        "selected_node_id": request.selected_node_id,
        "allowed_target_paths": list(request.allowed_target_paths),
        "verification_goal_ids": list(request.verification_goal_ids),
        "authority": request.authority,
        "gate_effect": request.gate_effect,
        "authority_contract": {
            "approval_scope": "patch_generation_for_exact_proposal_only",
            "path_scope": "approved_proposal_targets_only",
            "patch_application": "forbidden",
            "patch_review": "not_implied",
            "release_authority": "persisted_policy_decision_only",
        },
        "response_contract": {
            "schema_version": PATCH_SCHEMA_VERSION,
            "source_format": PATCH_SOURCE_FORMAT,
            "file_fields": [
                "target_path",
                "base_content_sha256",
                "patched_content_sha256",
                "unified_diff",
            ],
            "file_creation_or_deletion": "unsupported_v1",
            "binary_patch": "forbidden",
            "all_approved_target_paths_required": True,
        },
        "approval": human_approval_to_primitive(request.approval),
        "proposal": remediation_proposal_to_primitive(request.proposal),
    }


def render_patch_request_json(request: PatchRequest) -> str:
    return dumps(patch_request_to_primitive(request), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_patch_request_markdown(request: PatchRequest) -> str:
    lines = [
        "# Before Deploy Patch Request",
        "",
        f"- Proposal SHA-256: `{request.proposal_sha256}`",
        f"- Approval SHA-256: `{request.approval_sha256}`",
        f"- Request SHA-256: `{request.request_sha256}`",
        f"- Authority: `{request.authority}`",
        f"- Gate effect: `{request.gate_effect}`",
        "",
        "## Authorized target paths",
        "",
    ]
    lines.extend(f"- `{path}`" for path in request.allowed_target_paths)
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "Approval authorizes generation of a patch artifact for these paths only.",
            "The generated patch is not applied, not human-reviewed by implication, and has no release authority.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_patch_request_terminal(request: PatchRequest) -> str:
    return (
        "Before Deploy patch request\n"
        f"Proposal SHA-256: {request.proposal_sha256}\n"
        f"Approval SHA-256: {request.approval_sha256}\n"
        f"Target paths: {len(request.allowed_target_paths)}\n"
        f"Request SHA-256: {request.request_sha256}\n"
        f"Authority: {request.authority}, gate_effect={request.gate_effect}\n"
    )


def load_patch_response(
    path: Path,
    request: PatchRequest,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
    *,
    max_bytes: int = DEFAULT_MAX_PATCH_RESPONSE_BYTES,
) -> PatchResult:
    """Import a strict patch response without applying it to the repository."""
    validate_patch_request(request, proposal_request, investigation_request)
    if max_bytes <= 0:
        raise ValueError("Patch response byte limit must be positive")
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"Patch response exceeds byte limit: {len(raw)} > {max_bytes}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Patch response must be UTF-8 JSON") from error
    try:
        payload = loads(text)
    except JSONDecodeError as error:
        raise ValueError("Patch response must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Patch response root must be an object")
    _require_keys(
        payload,
        allowed={"schema_version", "request_sha256", "source", "files"},
        required={"schema_version", "request_sha256", "source", "files"},
        label="patch response",
    )
    if payload["schema_version"] != PATCH_SCHEMA_VERSION:
        raise ValueError("Unsupported patch response schema version")
    if payload["request_sha256"] != request.request_sha256:
        raise ValueError("Patch response is bound to a different request")
    provider, model = _parse_source(payload["source"])
    files = _parse_patch_files(payload["files"], request)
    normalized_payload = {
        "source_provider": provider,
        "declared_model": model,
        "identity_status": PATCH_IDENTITY_STATUS,
        "source_format": PATCH_SOURCE_FORMAT,
        "application_status": PATCH_APPLICATION_STATUS,
        "review_status": PATCH_REVIEW_STATUS,
        "files": [to_primitive(item) for item in files],
    }
    provisional = PatchResult(
        schema_version=PATCH_SCHEMA_VERSION,
        proposal_request_sha256=request.proposal_request_sha256,
        proposal_sha256=request.proposal_sha256,
        approval_sha256=request.approval_sha256,
        request_sha256=request.request_sha256,
        patch_sha256="",
        selected_node_id=request.selected_node_id,
        source_provider=provider,
        declared_model=model,
        identity_status=PATCH_IDENTITY_STATUS,
        source_format=PATCH_SOURCE_FORMAT,
        raw_input_sha256=sha256(raw).hexdigest(),
        raw_input_size_bytes=len(raw),
        normalized_output_sha256=_canonical_sha256(normalized_payload),
        application_status=PATCH_APPLICATION_STATUS,
        review_status=PATCH_REVIEW_STATUS,
        files=files,
    )
    result = PatchResult(**{**provisional.__dict__, "patch_sha256": _patch_digest(provisional)})
    validate_patch_result(result, request, proposal_request, investigation_request)
    return result


def validate_patch_result(
    result: PatchResult,
    request: PatchRequest,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    """Reject path widening, forged status, invalid diffs, and lineage drift."""
    validate_patch_request(request, proposal_request, investigation_request)
    if result.schema_version != PATCH_SCHEMA_VERSION:
        raise ValueError("Unsupported patch schema version")
    if result.authority != PATCH_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Patch artifact must remain gate-neutral")
    bindings = (
        (result.proposal_request_sha256, request.proposal_request_sha256, "proposal request"),
        (result.proposal_sha256, request.proposal_sha256, "proposal"),
        (result.approval_sha256, request.approval_sha256, "approval"),
        (result.request_sha256, request.request_sha256, "patch request"),
        (result.selected_node_id, request.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Patch artifact is bound to a different {label}")
    if result.identity_status != PATCH_IDENTITY_STATUS:
        raise ValueError("Patch generator identity must remain declared and unattested")
    if result.source_format != PATCH_SOURCE_FORMAT:
        raise ValueError("Unsupported patch source format")
    if result.application_status != PATCH_APPLICATION_STATUS:
        raise ValueError("Patch artifact cannot claim application")
    if result.review_status != PATCH_REVIEW_STATUS:
        raise ValueError("Patch artifact cannot claim human review")
    if result.raw_input_size_bytes <= 0 or not _is_sha256(result.raw_input_sha256):
        raise ValueError("Patch raw input provenance is invalid")
    _bounded_text(result.source_provider, "patch source provider", MAX_PATCH_IDENTITY_CHARS)
    if result.declared_model is not None:
        _bounded_text(result.declared_model, "patch declared model", MAX_PATCH_IDENTITY_CHARS)
    if not result.files or len(result.files) > MAX_PATCH_FILES:
        raise ValueError("Patch file count is outside supported bounds")
    for item in result.files:
        _validate_patch_file(item, request)
    paths = tuple(item.target_path for item in result.files)
    if paths != tuple(sorted(set(paths))):
        raise ValueError("Patch file paths must be unique and sorted")
    if paths != request.allowed_target_paths:
        raise ValueError("Patch must cover exactly the approved proposal target paths")
    normalized_payload = {
        "source_provider": result.source_provider,
        "declared_model": result.declared_model,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "application_status": result.application_status,
        "review_status": result.review_status,
        "files": [to_primitive(item) for item in result.files],
    }
    if result.normalized_output_sha256 != _canonical_sha256(normalized_payload):
        raise ValueError("Patch normalized output digest mismatch")
    if result.patch_sha256 != _patch_digest(result):
        raise ValueError("Patch artifact digest mismatch")


def patch_result_to_primitive(result: PatchResult) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "proposal_request_sha256": result.proposal_request_sha256,
        "proposal_sha256": result.proposal_sha256,
        "approval_sha256": result.approval_sha256,
        "request_sha256": result.request_sha256,
        "patch_sha256": result.patch_sha256,
        "selected_node_id": result.selected_node_id,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "application_status": result.application_status,
        "review_status": result.review_status,
        "authority_contract": {
            "patch_authority": "artifact_only",
            "patch_application": "not_performed",
            "patch_review": "not_implied",
            "release_authority": "persisted_policy_decision_only",
        },
        "source": {
            "provider": result.source_provider,
            "declared_model": result.declared_model,
            "identity_status": result.identity_status,
            "source_format": result.source_format,
        },
        "raw_input": {"sha256": result.raw_input_sha256, "size_bytes": result.raw_input_size_bytes},
        "normalized_output_sha256": result.normalized_output_sha256,
        "files": [to_primitive(item) for item in result.files],
    }


def render_patch_json(result: PatchResult) -> str:
    return dumps(patch_result_to_primitive(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_patch_markdown(result: PatchResult) -> str:
    lines = [
        "# Before Deploy Patch Artifact",
        "",
        f"- Patch SHA-256: `{result.patch_sha256}`",
        f"- Proposal SHA-256: `{result.proposal_sha256}`",
        f"- Approval SHA-256: `{result.approval_sha256}`",
        f"- Application status: `{result.application_status}`",
        f"- Review status: `{result.review_status}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "## Files",
        "",
    ]
    for item in result.files:
        lines.extend(
            [
                f"### `{item.target_path}`",
                "",
                f"- Base SHA-256: `{item.base_content_sha256}`",
                f"- Patched SHA-256: `{item.patched_content_sha256}`",
                f"- Diff SHA-256: `{item.diff_sha256}`",
                "",
                "```diff",
                item.unified_diff.rstrip("\n"),
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## Boundary",
            "",
            "This artifact records patch content only. Before Deploy has not applied it and does not imply human review of the generated diff.",
            "Regression evidence and later verification must bind to this exact `patch_sha256`.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_patch_terminal(result: PatchResult) -> str:
    return (
        "Before Deploy patch artifact: NOT_APPLIED / UNREVIEWED\n"
        f"Files: {len(result.files)}\n"
        f"Patch SHA-256: {result.patch_sha256}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def _parse_source(value: Any) -> tuple[str, str | None]:
    if not isinstance(value, dict):
        raise ValueError("Patch source must be an object")
    _require_keys(value, allowed={"provider", "model"}, required={"provider"}, label="patch source")
    provider = _bounded_text(value["provider"], "patch source provider", MAX_PATCH_IDENTITY_CHARS)
    model = value.get("model")
    return (
        provider,
        _bounded_text(model, "patch declared model", MAX_PATCH_IDENTITY_CHARS)
        if model is not None
        else None,
    )


def _parse_patch_files(value: Any, request: PatchRequest) -> tuple[PatchFile, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("Patch files must be a non-empty array")
    if len(value) > MAX_PATCH_FILES:
        raise ValueError("Patch contains too many files")
    parsed: dict[str, PatchFile] = {}
    for payload in value:
        if not isinstance(payload, dict):
            raise ValueError("Patch file entries must be objects")
        _require_keys(
            payload,
            allowed={"target_path", "base_content_sha256", "patched_content_sha256", "unified_diff"},
            required={"target_path", "base_content_sha256", "patched_content_sha256", "unified_diff"},
            label="patch file",
        )
        target = payload["target_path"]
        if not isinstance(target, str) or target not in request.allowed_target_paths:
            raise ValueError("Patch target path escapes approved proposal scope")
        base_sha = payload["base_content_sha256"]
        patched_sha = payload["patched_content_sha256"]
        if not _is_sha256(base_sha) or not _is_sha256(patched_sha):
            raise ValueError("Patch content digests must be SHA-256")
        if base_sha == patched_sha:
            raise ValueError("Patch base and patched content digests must differ")
        unified_diff = payload["unified_diff"]
        if not isinstance(unified_diff, str) or not unified_diff:
            raise ValueError("Patch unified_diff must be a non-empty string")
        if len(unified_diff) > MAX_PATCH_DIFF_CHARS:
            raise ValueError("Patch unified_diff exceeds text bound")
        _validate_unified_diff(unified_diff, target)
        semantic = {
            "target_path": target,
            "base_content_sha256": base_sha,
            "patched_content_sha256": patched_sha,
            "unified_diff": unified_diff,
        }
        item = PatchFile(
            patch_file_id=_diagnostic_id("patch-file", semantic),
            target_path=target,
            base_content_sha256=base_sha,
            patched_content_sha256=patched_sha,
            diff_sha256=sha256(unified_diff.encode("utf-8")).hexdigest(),
            unified_diff=unified_diff,
        )
        if target in parsed:
            raise ValueError(f"Duplicate patch target path: {target}")
        parsed[target] = item
    return tuple(parsed[path] for path in sorted(parsed))


def _validate_patch_file(item: PatchFile, request: PatchRequest) -> None:
    if item.target_path not in request.allowed_target_paths:
        raise ValueError("Patch target path escapes approved proposal scope")
    if not _is_sha256(item.base_content_sha256) or not _is_sha256(item.patched_content_sha256):
        raise ValueError("Patch content digests must be SHA-256")
    if item.base_content_sha256 == item.patched_content_sha256:
        raise ValueError("Patch base and patched content digests must differ")
    _validate_unified_diff(item.unified_diff, item.target_path)
    if item.diff_sha256 != sha256(item.unified_diff.encode("utf-8")).hexdigest():
        raise ValueError("Patch diff digest mismatch")
    semantic = {
        "target_path": item.target_path,
        "base_content_sha256": item.base_content_sha256,
        "patched_content_sha256": item.patched_content_sha256,
        "unified_diff": item.unified_diff,
    }
    if item.patch_file_id != _diagnostic_id("patch-file", semantic):
        raise ValueError("Patch file ID mismatch")


def _validate_unified_diff(diff: str, target_path: str) -> None:
    if "\x00" in diff or "GIT binary patch" in diff or "Binary files " in diff:
        raise ValueError("Binary patch content is not supported")
    lines = diff.splitlines()
    diff_headers = [line for line in lines if line.startswith("diff --git ")]
    old_headers = [line for line in lines if line.startswith("--- ")]
    new_headers = [line for line in lines if line.startswith("+++ ")]
    hunks = [line for line in lines if line.startswith("@@ ")]
    if len(diff_headers) > 1:
        raise ValueError("Patch unified_diff must describe exactly one file")
    if diff_headers and diff_headers[0] != f"diff --git a/{target_path} b/{target_path}":
        raise ValueError("Patch diff header does not match target path")
    if old_headers != [f"--- a/{target_path}"] or new_headers != [f"+++ b/{target_path}"]:
        raise ValueError("Patch file headers do not match target path")
    if not hunks:
        raise ValueError("Patch unified_diff must contain at least one hunk")
    changed_lines = [
        line
        for line in lines
        if (line.startswith("+") and not line.startswith("+++"))
        or (line.startswith("-") and not line.startswith("---"))
    ]
    if not changed_lines:
        raise ValueError("Patch unified_diff must contain at least one changed line")


def _approval_digest(approval: HumanApproval) -> str:
    return _canonical_sha256(
        {
            "schema_version": approval.schema_version,
            "proposal_request_sha256": approval.proposal_request_sha256,
            "proposal_sha256": approval.proposal_sha256,
            "selected_node_id": approval.selected_node_id,
            "decision": approval.decision,
            "approver": approval.approver,
            "identity_status": approval.identity_status,
            "rationale": approval.rationale,
            "source_format": approval.source_format,
            "authority": approval.authority,
            "gate_effect": approval.gate_effect,
        }
    )


def _patch_request_digest(request: PatchRequest) -> str:
    return _canonical_sha256(
        {
            "schema_version": request.schema_version,
            "proposal_request_sha256": request.proposal_request_sha256,
            "proposal_sha256": request.proposal_sha256,
            "approval_sha256": request.approval_sha256,
            "selected_node_id": request.selected_node_id,
            "allowed_target_paths": request.allowed_target_paths,
            "verification_goal_ids": request.verification_goal_ids,
            "authority": request.authority,
            "gate_effect": request.gate_effect,
        }
    )


def _patch_digest(result: PatchResult) -> str:
    return _canonical_sha256(
        {
            "schema_version": result.schema_version,
            "proposal_request_sha256": result.proposal_request_sha256,
            "proposal_sha256": result.proposal_sha256,
            "approval_sha256": result.approval_sha256,
            "request_sha256": result.request_sha256,
            "selected_node_id": result.selected_node_id,
            "source_provider": result.source_provider,
            "declared_model": result.declared_model,
            "identity_status": result.identity_status,
            "source_format": result.source_format,
            "raw_input_sha256": result.raw_input_sha256,
            "raw_input_size_bytes": result.raw_input_size_bytes,
            "normalized_output_sha256": result.normalized_output_sha256,
            "application_status": result.application_status,
            "review_status": result.review_status,
            "files": [to_primitive(item) for item in result.files],
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        }
    )


def _diagnostic_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{_canonical_sha256(value)}"


def _canonical_sha256(value: Any) -> str:
    payload = dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(payload.encode("utf-8")).hexdigest()


def _bounded_text(value: Any, label: str, max_chars: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be empty")
    if len(normalized) > max_chars:
        raise ValueError(f"{label} exceeds character bound")
    return normalized


def _optional_text(value: Any, label: str, max_chars: int) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label, max_chars)


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _require_keys(
    payload: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"Unsupported {label} field: {unknown[0]}")
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"Missing {label} field: {missing[0]}")
