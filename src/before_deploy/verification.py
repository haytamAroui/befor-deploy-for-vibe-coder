"""Deterministic verification over exact patch, materialization, and regression evidence lineage."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path
from typing import Any

from before_deploy.evidence_investigation import EvidenceInvestigationRequest
from before_deploy.human_approval_patch import PatchRequest, PatchResult
from before_deploy.models import to_primitive
from before_deploy.regression_evidence import (
    PatchMaterializationAuthorization,
    PatchMaterializationFile,
    PatchMaterializationResult,
    RegressionEvidenceRequest,
    RegressionEvidenceResult,
    RegressionObservation,
    patch_materialization_authorization_to_primitive,
    patch_materialization_to_primitive,
    regression_evidence_to_primitive,
    validate_patch_materialization,
    validate_patch_materialization_authorization,
    validate_regression_evidence,
)
from before_deploy.remediation_proposal import RemediationProposalRequest

VERIFICATION_SCHEMA_VERSION = 1
VERIFICATION_AUTHORITY = "VERIFICATION_EVIDENCE"
VERIFICATION_GATE_EFFECT = "NONE"
VERIFICATION_METHOD = "DECLARED_REMEDIATION_GOALS_V1"
VERIFICATION_RELEASE_STATUS = "NOT_EVALUATED"
VERIFICATION_REQUIRED_OBSERVATION_STATUS = "PASS"
VERIFICATION_STATUSES = ("PASS", "FAIL", "ERROR", "INCOMPLETE")
VERIFICATION_CHECK_STATUSES = ("SATISFIED", "FAILED", "ERROR", "INCOMPLETE")


@dataclass(frozen=True)
class VerificationRequirement:
    requirement_id: str
    verification_goal_id: str
    kind: str
    statement: str
    required_observation_status: str


@dataclass(frozen=True)
class VerificationCheck:
    check_id: str
    requirement_id: str
    observation_id: str
    observed_status: str
    status: str


@dataclass(frozen=True)
class VerificationResult:
    schema_version: int
    proposal_sha256: str
    approval_sha256: str
    patch_request_sha256: str
    patch_sha256: str
    materialization_authorization_sha256: str
    materialization_sha256: str
    regression_request_sha256: str
    regression_evidence_sha256: str
    verification_sha256: str
    selected_node_id: str
    method: str
    evidence_identity_status: str
    patch_review_status: str
    materialization_review_status: str
    overall_status: str
    release_status: str
    requirements: tuple[VerificationRequirement, ...]
    checks: tuple[VerificationCheck, ...]
    authority: str = VERIFICATION_AUTHORITY
    gate_effect: str = VERIFICATION_GATE_EFFECT


def load_patch_materialization_authorization_artifact(
    path: Path,
    patch: PatchResult,
    patch_request: PatchRequest,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> PatchMaterializationAuthorization:
    """Load and canonically validate the PR34 materialization authorization artifact."""
    payload = _load_json_object(path, "patch materialization authorization")
    _require_keys(
        payload,
        allowed={
            "schema_version",
            "patch_request_sha256",
            "patch_sha256",
            "authorization_sha256",
            "selected_node_id",
            "operator",
            "identity_status",
            "scope",
            "authority",
            "gate_effect",
            "authority_contract",
        },
        required={
            "schema_version",
            "patch_request_sha256",
            "patch_sha256",
            "authorization_sha256",
            "selected_node_id",
            "operator",
            "identity_status",
            "scope",
            "authority",
            "gate_effect",
            "authority_contract",
        },
        label="patch materialization authorization",
    )
    result = PatchMaterializationAuthorization(
        schema_version=payload["schema_version"],
        patch_request_sha256=payload["patch_request_sha256"],
        patch_sha256=payload["patch_sha256"],
        authorization_sha256=payload["authorization_sha256"],
        selected_node_id=payload["selected_node_id"],
        operator=payload["operator"],
        identity_status=payload["identity_status"],
        scope=payload["scope"],
        authority=payload["authority"],
        gate_effect=payload["gate_effect"],
    )
    validate_patch_materialization_authorization(
        result,
        patch,
        patch_request,
        proposal_request,
        investigation_request,
    )
    if payload != patch_materialization_authorization_to_primitive(result):
        raise ValueError("Patch materialization authorization is not canonical")
    return result


def load_patch_materialization_artifact(
    path: Path,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> PatchMaterializationResult:
    """Load hash-verified materialization evidence without mutating the workspace."""
    payload = _load_json_object(path, "patch materialization")
    _require_keys(
        payload,
        allowed={
            "schema_version",
            "patch_request_sha256",
            "patch_sha256",
            "authorization_sha256",
            "materialization_sha256",
            "selected_node_id",
            "application_status",
            "review_status",
            "authority",
            "gate_effect",
            "files",
            "authority_contract",
        },
        required={
            "schema_version",
            "patch_request_sha256",
            "patch_sha256",
            "authorization_sha256",
            "materialization_sha256",
            "selected_node_id",
            "application_status",
            "review_status",
            "authority",
            "gate_effect",
            "files",
            "authority_contract",
        },
        label="patch materialization",
    )
    files_value = payload["files"]
    if not isinstance(files_value, list):
        raise ValueError("Patch materialization files must be an array")
    files: list[PatchMaterializationFile] = []
    for value in files_value:
        if not isinstance(value, dict):
            raise ValueError("Patch materialization file entries must be objects")
        _require_keys(
            value,
            allowed={
                "patch_file_id",
                "target_path",
                "before_content_sha256",
                "after_content_sha256",
            },
            required={
                "patch_file_id",
                "target_path",
                "before_content_sha256",
                "after_content_sha256",
            },
            label="patch materialization file",
        )
        files.append(
            PatchMaterializationFile(
                patch_file_id=value["patch_file_id"],
                target_path=value["target_path"],
                before_content_sha256=value["before_content_sha256"],
                after_content_sha256=value["after_content_sha256"],
            )
        )
    result = PatchMaterializationResult(
        schema_version=payload["schema_version"],
        patch_request_sha256=payload["patch_request_sha256"],
        patch_sha256=payload["patch_sha256"],
        authorization_sha256=payload["authorization_sha256"],
        materialization_sha256=payload["materialization_sha256"],
        selected_node_id=payload["selected_node_id"],
        application_status=payload["application_status"],
        review_status=payload["review_status"],
        files=tuple(files),
        authority=payload["authority"],
        gate_effect=payload["gate_effect"],
    )
    validate_patch_materialization(
        result,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    if payload != patch_materialization_to_primitive(result):
        raise ValueError("Patch materialization artifact is not canonical")
    return result


def load_regression_evidence_artifact(
    path: Path,
    request: RegressionEvidenceRequest,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> RegressionEvidenceResult:
    """Load canonical PR34 regression evidence and revalidate the complete lineage."""
    payload = _load_json_object(path, "regression evidence")
    _require_keys(
        payload,
        allowed={
            "schema_version",
            "patch_request_sha256",
            "patch_sha256",
            "authorization_sha256",
            "materialization_sha256",
            "request_sha256",
            "regression_evidence_sha256",
            "selected_node_id",
            "authority",
            "gate_effect",
            "aggregate_status",
            "source",
            "raw_input",
            "normalized_output_sha256",
            "observations",
            "authority_contract",
        },
        required={
            "schema_version",
            "patch_request_sha256",
            "patch_sha256",
            "authorization_sha256",
            "materialization_sha256",
            "request_sha256",
            "regression_evidence_sha256",
            "selected_node_id",
            "authority",
            "gate_effect",
            "aggregate_status",
            "source",
            "raw_input",
            "normalized_output_sha256",
            "observations",
            "authority_contract",
        },
        label="regression evidence",
    )
    source = payload["source"]
    raw_input = payload["raw_input"]
    if not isinstance(source, dict):
        raise ValueError("Regression evidence source must be an object")
    if not isinstance(raw_input, dict):
        raise ValueError("Regression evidence raw_input must be an object")
    _require_keys(
        source,
        allowed={"runner", "environment", "identity_status", "source_format"},
        required={"runner", "environment", "identity_status", "source_format"},
        label="regression evidence source",
    )
    _require_keys(
        raw_input,
        allowed={"sha256", "size_bytes"},
        required={"sha256", "size_bytes"},
        label="regression evidence raw input",
    )
    observations_value = payload["observations"]
    if not isinstance(observations_value, list):
        raise ValueError("Regression evidence observations must be an array")
    observations: list[RegressionObservation] = []
    for value in observations_value:
        if not isinstance(value, dict):
            raise ValueError("Regression evidence observation entries must be objects")
        _require_keys(
            value,
            allowed={
                "observation_id",
                "verification_goal_id",
                "kind",
                "status",
                "command",
                "exit_code",
                "duration_ms",
                "stdout_sha256",
                "stderr_sha256",
                "statement",
            },
            required={
                "observation_id",
                "verification_goal_id",
                "kind",
                "status",
                "command",
                "exit_code",
                "duration_ms",
                "stdout_sha256",
                "stderr_sha256",
                "statement",
            },
            label="regression evidence observation",
        )
        command = value["command"]
        if not isinstance(command, list):
            raise ValueError("Regression evidence observation command must be an array")
        observations.append(
            RegressionObservation(
                observation_id=value["observation_id"],
                verification_goal_id=value["verification_goal_id"],
                kind=value["kind"],
                status=value["status"],
                command=tuple(command),
                exit_code=value["exit_code"],
                duration_ms=value["duration_ms"],
                stdout_sha256=value["stdout_sha256"],
                stderr_sha256=value["stderr_sha256"],
                statement=value["statement"],
            )
        )
    result = RegressionEvidenceResult(
        schema_version=payload["schema_version"],
        patch_request_sha256=payload["patch_request_sha256"],
        patch_sha256=payload["patch_sha256"],
        authorization_sha256=payload["authorization_sha256"],
        materialization_sha256=payload["materialization_sha256"],
        request_sha256=payload["request_sha256"],
        regression_evidence_sha256=payload["regression_evidence_sha256"],
        selected_node_id=payload["selected_node_id"],
        source_runner=source["runner"],
        source_environment=source["environment"],
        identity_status=source["identity_status"],
        source_format=source["source_format"],
        raw_input_sha256=raw_input["sha256"],
        raw_input_size_bytes=raw_input["size_bytes"],
        normalized_output_sha256=payload["normalized_output_sha256"],
        aggregate_status=payload["aggregate_status"],
        observations=tuple(observations),
        authority=payload["authority"],
        gate_effect=payload["gate_effect"],
    )
    validate_regression_evidence(
        result,
        request,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    if payload != regression_evidence_to_primitive(result):
        raise ValueError("Regression evidence artifact is not canonical")
    return result


def build_verification(
    regression: RegressionEvidenceResult,
    regression_request: RegressionEvidenceRequest,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> VerificationResult:
    """Deterministically evaluate declared remediation verification goals."""
    validate_regression_evidence(
        regression,
        regression_request,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    goal_map = {
        item.verification_goal_id: item
        for item in patch_request.proposal.verification_goals
    }
    observation_map = {
        item.verification_goal_id: item
        for item in regression.observations
    }
    requirements: list[VerificationRequirement] = []
    checks: list[VerificationCheck] = []
    for goal_id in sorted(goal_map):
        goal = goal_map[goal_id]
        semantic = {
            "verification_goal_id": goal.verification_goal_id,
            "kind": goal.kind,
            "statement": goal.statement,
            "required_observation_status": VERIFICATION_REQUIRED_OBSERVATION_STATUS,
        }
        requirement = VerificationRequirement(
            requirement_id=_diagnostic_id("verification-requirement", semantic),
            verification_goal_id=goal.verification_goal_id,
            kind=goal.kind,
            statement=goal.statement,
            required_observation_status=VERIFICATION_REQUIRED_OBSERVATION_STATUS,
        )
        observation = observation_map[goal_id]
        check_status = _check_status(observation.status)
        check_semantic = {
            "requirement_id": requirement.requirement_id,
            "observation_id": observation.observation_id,
            "observed_status": observation.status,
            "status": check_status,
        }
        check = VerificationCheck(
            check_id=_diagnostic_id("verification-check", check_semantic),
            requirement_id=requirement.requirement_id,
            observation_id=observation.observation_id,
            observed_status=observation.status,
            status=check_status,
        )
        requirements.append(requirement)
        checks.append(check)

    provisional = VerificationResult(
        schema_version=VERIFICATION_SCHEMA_VERSION,
        proposal_sha256=patch.proposal_sha256,
        approval_sha256=patch.approval_sha256,
        patch_request_sha256=patch.request_sha256,
        patch_sha256=patch.patch_sha256,
        materialization_authorization_sha256=authorization.authorization_sha256,
        materialization_sha256=regression.materialization_sha256,
        regression_request_sha256=regression.request_sha256,
        regression_evidence_sha256=regression.regression_evidence_sha256,
        verification_sha256="",
        selected_node_id=patch.selected_node_id,
        method=VERIFICATION_METHOD,
        evidence_identity_status=regression.identity_status,
        patch_review_status=patch.review_status,
        materialization_review_status=regression_request.materialization.review_status,
        overall_status=_overall_status(tuple(checks)),
        release_status=VERIFICATION_RELEASE_STATUS,
        requirements=tuple(requirements),
        checks=tuple(checks),
    )
    result = VerificationResult(
        **{**provisional.__dict__, "verification_sha256": _verification_digest(provisional)}
    )
    validate_verification(
        result,
        regression,
        regression_request,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    return result


def validate_verification(
    result: VerificationResult,
    regression: RegressionEvidenceResult,
    regression_request: RegressionEvidenceRequest,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    validate_regression_evidence(
        regression,
        regression_request,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    if result.schema_version != VERIFICATION_SCHEMA_VERSION:
        raise ValueError("Unsupported verification schema version")
    if result.authority != VERIFICATION_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Verification evidence must remain gate-neutral")
    bindings = (
        (result.proposal_sha256, patch.proposal_sha256, "proposal"),
        (result.approval_sha256, patch.approval_sha256, "approval"),
        (result.patch_request_sha256, patch.request_sha256, "patch request"),
        (result.patch_sha256, patch.patch_sha256, "patch"),
        (
            result.materialization_authorization_sha256,
            authorization.authorization_sha256,
            "materialization authorization",
        ),
        (result.materialization_sha256, regression.materialization_sha256, "materialization"),
        (result.regression_request_sha256, regression.request_sha256, "regression request"),
        (
            result.regression_evidence_sha256,
            regression.regression_evidence_sha256,
            "regression evidence",
        ),
        (result.selected_node_id, patch.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Verification is bound to a different {label}")
    if result.method != VERIFICATION_METHOD:
        raise ValueError("Unsupported verification method")
    if result.evidence_identity_status != regression.identity_status:
        raise ValueError("Verification evidence identity status does not match regression evidence")
    if result.patch_review_status != patch.review_status:
        raise ValueError("Verification cannot rewrite patch review status")
    if result.materialization_review_status != regression_request.materialization.review_status:
        raise ValueError("Verification cannot rewrite materialization review status")
    if result.release_status != VERIFICATION_RELEASE_STATUS:
        raise ValueError("Verification cannot claim release disposition")

    goal_map = {
        item.verification_goal_id: item
        for item in patch_request.proposal.verification_goals
    }
    observation_map = {
        item.verification_goal_id: item
        for item in regression.observations
    }
    if len(result.requirements) != len(goal_map) or len(result.checks) != len(goal_map):
        raise ValueError("Verification must evaluate every declared remediation verification goal exactly once")
    requirement_by_id: dict[str, VerificationRequirement] = {}
    for requirement in result.requirements:
        goal = goal_map.get(requirement.verification_goal_id)
        if goal is None:
            raise ValueError("Verification requirement references an unknown verification goal")
        if requirement.kind != goal.kind or requirement.statement != goal.statement:
            raise ValueError("Verification requirement does not match declared remediation goal")
        if requirement.required_observation_status != VERIFICATION_REQUIRED_OBSERVATION_STATUS:
            raise ValueError("Verification requirements must require PASS observations")
        semantic = {
            "verification_goal_id": requirement.verification_goal_id,
            "kind": requirement.kind,
            "statement": requirement.statement,
            "required_observation_status": requirement.required_observation_status,
        }
        if requirement.requirement_id != _diagnostic_id("verification-requirement", semantic):
            raise ValueError("Verification requirement ID mismatch")
        if requirement.requirement_id in requirement_by_id:
            raise ValueError("Duplicate verification requirement ID")
        requirement_by_id[requirement.requirement_id] = requirement
    if tuple(item.verification_goal_id for item in result.requirements) != tuple(sorted(goal_map)):
        raise ValueError("Verification requirements must be sorted by verification goal ID")

    expected_check_ids: list[str] = []
    for requirement, check in zip(result.requirements, result.checks, strict=True):
        observation = observation_map[requirement.verification_goal_id]
        if check.requirement_id != requirement.requirement_id:
            raise ValueError("Verification check is bound to a different requirement")
        if check.observation_id != observation.observation_id:
            raise ValueError("Verification check is bound to a different regression observation")
        if check.observed_status != observation.status:
            raise ValueError("Verification check observed status does not match regression evidence")
        expected_status = _check_status(observation.status)
        if check.status != expected_status:
            raise ValueError("Verification check status mismatch")
        semantic = {
            "requirement_id": check.requirement_id,
            "observation_id": check.observation_id,
            "observed_status": check.observed_status,
            "status": check.status,
        }
        expected_id = _diagnostic_id("verification-check", semantic)
        if check.check_id != expected_id:
            raise ValueError("Verification check ID mismatch")
        expected_check_ids.append(expected_id)
    if len(set(expected_check_ids)) != len(expected_check_ids):
        raise ValueError("Duplicate verification check ID")
    if result.overall_status not in VERIFICATION_STATUSES:
        raise ValueError("Unsupported verification overall status")
    if result.overall_status != _overall_status(result.checks):
        raise ValueError("Verification overall status mismatch")
    if result.verification_sha256 != _verification_digest(result):
        raise ValueError("Verification digest mismatch")


def verification_to_primitive(result: VerificationResult) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "proposal_sha256": result.proposal_sha256,
        "approval_sha256": result.approval_sha256,
        "patch_request_sha256": result.patch_request_sha256,
        "patch_sha256": result.patch_sha256,
        "materialization_authorization_sha256": result.materialization_authorization_sha256,
        "materialization_sha256": result.materialization_sha256,
        "regression_request_sha256": result.regression_request_sha256,
        "regression_evidence_sha256": result.regression_evidence_sha256,
        "verification_sha256": result.verification_sha256,
        "selected_node_id": result.selected_node_id,
        "method": result.method,
        "evidence_identity_status": result.evidence_identity_status,
        "patch_review_status": result.patch_review_status,
        "materialization_review_status": result.materialization_review_status,
        "overall_status": result.overall_status,
        "release_status": result.release_status,
        "requirements": [to_primitive(item) for item in result.requirements],
        "checks": [to_primitive(item) for item in result.checks],
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "authority_contract": {
            "evaluation": "deterministic_declared_verification_requirements_only",
            "required_observation_status": VERIFICATION_REQUIRED_OBSERVATION_STATUS,
            "external_runner_identity": result.evidence_identity_status,
            "patch_review": result.patch_review_status,
            "release_disposition": "not_evaluated_by_pr35",
            "release_authority": "future_release_disposition_only",
            "policy_mutation": "forbidden",
        },
    }


def render_verification_json(result: VerificationResult) -> str:
    return dumps(verification_to_primitive(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_verification_markdown(result: VerificationResult) -> str:
    lines = [
        "# Before Deploy Verification",
        "",
        f"- Verification SHA-256: `{result.verification_sha256}`",
        f"- Patch SHA-256: `{result.patch_sha256}`",
        f"- Regression evidence SHA-256: `{result.regression_evidence_sha256}`",
        f"- Overall status: `{result.overall_status}`",
        f"- Evidence identity status: `{result.evidence_identity_status}`",
        f"- Patch review status: `{result.patch_review_status}`",
        f"- Release status: `{result.release_status}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "## Requirements",
        "",
    ]
    for requirement, check in zip(result.requirements, result.checks, strict=True):
        lines.append(
            f"- `{check.status}` `{requirement.kind}` `{requirement.verification_goal_id}` "
            f"(observed `{check.observed_status}`, required `{requirement.required_observation_status}`)"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "This artifact deterministically evaluates the declared remediation verification goals against the bound regression evidence. ",
            "A PASS means every declared goal has a recorded PASS observation for this exact patch/materialization lineage. ",
            "It does not attest an external runner identity, imply human review of generated patch bytes, mutate PolicyDecision, or decide release readiness.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_verification_terminal(result: VerificationResult) -> str:
    return (
        f"Before Deploy verification: {result.overall_status}\n"
        f"Requirements: {len(result.requirements)}\n"
        f"Patch SHA-256: {result.patch_sha256}\n"
        f"Verification SHA-256: {result.verification_sha256}\n"
        f"Evidence identity: {result.evidence_identity_status}\n"
        f"Release status: {result.release_status}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def _check_status(observed_status: str) -> str:
    mapping = {
        "PASS": "SATISFIED",
        "FAIL": "FAILED",
        "ERROR": "ERROR",
        "NOT_RUN": "INCOMPLETE",
    }
    try:
        return mapping[observed_status]
    except KeyError as error:
        raise ValueError(f"Unsupported regression observation status for verification: {observed_status}") from error


def _overall_status(checks: tuple[VerificationCheck, ...]) -> str:
    statuses = {item.status for item in checks}
    if "ERROR" in statuses:
        return "ERROR"
    if "FAILED" in statuses:
        return "FAIL"
    if "INCOMPLETE" in statuses:
        return "INCOMPLETE"
    return "PASS"


def _verification_digest(result: VerificationResult) -> str:
    return _canonical_sha256(
        {
            "schema_version": result.schema_version,
            "proposal_sha256": result.proposal_sha256,
            "approval_sha256": result.approval_sha256,
            "patch_request_sha256": result.patch_request_sha256,
            "patch_sha256": result.patch_sha256,
            "materialization_authorization_sha256": result.materialization_authorization_sha256,
            "materialization_sha256": result.materialization_sha256,
            "regression_request_sha256": result.regression_request_sha256,
            "regression_evidence_sha256": result.regression_evidence_sha256,
            "selected_node_id": result.selected_node_id,
            "method": result.method,
            "evidence_identity_status": result.evidence_identity_status,
            "patch_review_status": result.patch_review_status,
            "materialization_review_status": result.materialization_review_status,
            "overall_status": result.overall_status,
            "release_status": result.release_status,
            "requirements": [to_primitive(item) for item in result.requirements],
            "checks": [to_primitive(item) for item in result.checks],
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        }
    )


def _diagnostic_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{_canonical_sha256(value)}"


def _canonical_sha256(value: Any) -> str:
    payload = dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(payload.encode("utf-8")).hexdigest()


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError(f"{label.capitalize()} artifact must be UTF-8 JSON") from error
    except JSONDecodeError as error:
        raise ValueError(f"{label.capitalize()} artifact must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{label.capitalize()} artifact root must be an object")
    return payload


def _require_keys(
    value: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise ValueError(f"Unsupported {label} field: {extra[0]}")
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"Missing {label} field: {missing[0]}")
