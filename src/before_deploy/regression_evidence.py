"""Controlled patch materialization and regression evidence bound to one exact patch."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from before_deploy.human_approval_patch import (
    PatchRequest,
    PatchResult,
    validate_patch_result,
)

if TYPE_CHECKING:
    # These types appear only in annotations (this module has `from __future__ import
    # annotations`), so importing them under TYPE_CHECKING keeps the authoritative release
    # decision free of any import-time dependency on the advisory plane.
    from before_deploy.evidence_investigation import EvidenceInvestigationRequest
    from before_deploy.remediation_proposal import RemediationProposalRequest

from before_deploy.models import to_primitive

PATCH_MATERIALIZATION_AUTHORIZATION_SCHEMA_VERSION = 1
PATCH_MATERIALIZATION_AUTHORIZATION_AUTHORITY = "PATCH_MATERIALIZATION_WORKFLOW"
PATCH_MATERIALIZATION_AUTHORIZATION_GATE_EFFECT = "NONE"
PATCH_MATERIALIZATION_AUTHORIZATION_IDENTITY_STATUS = "DECLARED_UNATTESTED"
PATCH_MATERIALIZATION_AUTHORIZATION_SCOPE = "APPLY_EXACT_PATCH_FOR_REGRESSION_ONLY"

PATCH_MATERIALIZATION_SCHEMA_VERSION = 1
PATCH_MATERIALIZATION_AUTHORITY = "PATCH_MATERIALIZATION_EVIDENCE"
PATCH_MATERIALIZATION_GATE_EFFECT = "NONE"
PATCH_MATERIALIZATION_STATUS = "APPLIED_HASH_VERIFIED"
PATCH_MATERIALIZATION_REVIEW_STATUS = "UNREVIEWED"

REGRESSION_EVIDENCE_SCHEMA_VERSION = 1
REGRESSION_EVIDENCE_REQUEST_AUTHORITY = "REGRESSION_EVIDENCE_CONTEXT"
REGRESSION_EVIDENCE_AUTHORITY = "REGRESSION_EVIDENCE"
REGRESSION_EVIDENCE_GATE_EFFECT = "NONE"
REGRESSION_EVIDENCE_SOURCE_FORMAT = "before-deploy-regression-evidence-v1"
REGRESSION_EVIDENCE_IDENTITY_STATUS = "DECLARED_UNATTESTED"
DEFAULT_MAX_REGRESSION_RESPONSE_BYTES = 1_000_000
MAX_OPERATOR_CHARS = 200
MAX_RUNNER_CHARS = 200
MAX_ENVIRONMENT_CHARS = 500
MAX_REGRESSION_STATEMENT_CHARS = 8_000
MAX_COMMAND_ITEMS = 128
MAX_COMMAND_ITEM_CHARS = 2_000
REGRESSION_STATUSES = ("PASS", "FAIL", "ERROR", "NOT_RUN")

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")


@dataclass(frozen=True)
class PatchMaterializationAuthorization:
    schema_version: int
    patch_request_sha256: str
    patch_sha256: str
    authorization_sha256: str
    selected_node_id: str
    operator: str
    identity_status: str
    scope: str
    authority: str = PATCH_MATERIALIZATION_AUTHORIZATION_AUTHORITY
    gate_effect: str = PATCH_MATERIALIZATION_AUTHORIZATION_GATE_EFFECT


@dataclass(frozen=True)
class PatchMaterializationFile:
    patch_file_id: str
    target_path: str
    before_content_sha256: str
    after_content_sha256: str


@dataclass(frozen=True)
class PatchMaterializationResult:
    schema_version: int
    patch_request_sha256: str
    patch_sha256: str
    authorization_sha256: str
    materialization_sha256: str
    selected_node_id: str
    application_status: str
    review_status: str
    files: tuple[PatchMaterializationFile, ...]
    authority: str = PATCH_MATERIALIZATION_AUTHORITY
    gate_effect: str = PATCH_MATERIALIZATION_GATE_EFFECT


@dataclass(frozen=True)
class RegressionVerificationGoal:
    verification_goal_id: str
    kind: str


@dataclass(frozen=True)
class RegressionEvidenceRequest:
    schema_version: int
    patch_request_sha256: str
    patch_sha256: str
    authorization_sha256: str
    materialization_sha256: str
    request_sha256: str
    selected_node_id: str
    verification_goals: tuple[RegressionVerificationGoal, ...]
    materialization: PatchMaterializationResult
    authority: str = REGRESSION_EVIDENCE_REQUEST_AUTHORITY
    gate_effect: str = REGRESSION_EVIDENCE_GATE_EFFECT


@dataclass(frozen=True)
class RegressionObservation:
    observation_id: str
    verification_goal_id: str
    kind: str
    status: str
    command: tuple[str, ...]
    exit_code: int | None
    duration_ms: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    statement: str | None


@dataclass(frozen=True)
class RegressionEvidenceResult:
    schema_version: int
    patch_request_sha256: str
    patch_sha256: str
    authorization_sha256: str
    materialization_sha256: str
    request_sha256: str
    regression_evidence_sha256: str
    selected_node_id: str
    source_runner: str
    source_environment: str | None
    identity_status: str
    source_format: str
    raw_input_sha256: str
    raw_input_size_bytes: int
    normalized_output_sha256: str
    aggregate_status: str
    observations: tuple[RegressionObservation, ...]
    authority: str = REGRESSION_EVIDENCE_AUTHORITY
    gate_effect: str = REGRESSION_EVIDENCE_GATE_EFFECT


def build_patch_materialization_authorization(
    patch: PatchResult,
    patch_request: PatchRequest,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
    *,
    confirmed_patch_sha256: str,
    operator: str,
) -> PatchMaterializationAuthorization:
    """Record explicit operator authorization to materialize one exact patch for regression work."""
    validate_patch_result(patch, patch_request, proposal_request, investigation_request)
    if confirmed_patch_sha256 != patch.patch_sha256:
        raise ValueError("Confirmed patch SHA-256 does not match the validated patch")
    operator_value = _bounded_text(operator, "materialization operator", MAX_OPERATOR_CHARS)
    provisional = PatchMaterializationAuthorization(
        schema_version=PATCH_MATERIALIZATION_AUTHORIZATION_SCHEMA_VERSION,
        patch_request_sha256=patch.request_sha256,
        patch_sha256=patch.patch_sha256,
        authorization_sha256="",
        selected_node_id=patch.selected_node_id,
        operator=operator_value,
        identity_status=PATCH_MATERIALIZATION_AUTHORIZATION_IDENTITY_STATUS,
        scope=PATCH_MATERIALIZATION_AUTHORIZATION_SCOPE,
    )
    result = PatchMaterializationAuthorization(
        **{**provisional.__dict__, "authorization_sha256": _materialization_authorization_digest(provisional)}
    )
    validate_patch_materialization_authorization(
        result,
        patch,
        patch_request,
        proposal_request,
        investigation_request,
    )
    return result


def validate_patch_materialization_authorization(
    authorization: PatchMaterializationAuthorization,
    patch: PatchResult,
    patch_request: PatchRequest,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    validate_patch_result(patch, patch_request, proposal_request, investigation_request)
    if authorization.schema_version != PATCH_MATERIALIZATION_AUTHORIZATION_SCHEMA_VERSION:
        raise ValueError("Unsupported patch materialization authorization schema version")
    if (
        authorization.authority != PATCH_MATERIALIZATION_AUTHORIZATION_AUTHORITY
        or authorization.gate_effect != "NONE"
    ):
        raise ValueError("Patch materialization authorization must remain workflow-only and gate-neutral")
    bindings = (
        (authorization.patch_request_sha256, patch.request_sha256, "patch request"),
        (authorization.patch_sha256, patch.patch_sha256, "patch"),
        (authorization.selected_node_id, patch.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Patch materialization authorization is bound to a different {label}")
    if authorization.identity_status != PATCH_MATERIALIZATION_AUTHORIZATION_IDENTITY_STATUS:
        raise ValueError("Patch materialization operator identity must remain declared and unattested")
    if authorization.scope != PATCH_MATERIALIZATION_AUTHORIZATION_SCOPE:
        raise ValueError("Patch materialization authorization scope is invalid")
    _bounded_text(authorization.operator, "materialization operator", MAX_OPERATOR_CHARS)
    if authorization.authorization_sha256 != _materialization_authorization_digest(authorization):
        raise ValueError("Patch materialization authorization digest mismatch")


def materialize_patch(
    repository: Path,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> PatchMaterializationResult:
    """Apply one authorized text patch after complete preflight and verify resulting content hashes."""
    validate_patch_materialization_authorization(
        authorization,
        patch,
        patch_request,
        proposal_request,
        investigation_request,
    )
    root = _validated_repository_root(repository)
    plans: list[tuple[Path, bytes, bytes, int, str]] = []
    for patch_file in patch.files:
        target = _validated_existing_regular_target(root, patch_file.target_path)
        before = target.read_bytes()
        before_sha = sha256(before).hexdigest()
        if before_sha != patch_file.base_content_sha256:
            raise ValueError(
                f"Patch base-content SHA-256 mismatch for {patch_file.target_path}: "
                f"expected {patch_file.base_content_sha256}, observed {before_sha}"
            )
        after = _apply_unified_diff(before, patch_file.unified_diff, patch_file.target_path)
        after_sha = sha256(after).hexdigest()
        if after_sha != patch_file.patched_content_sha256:
            raise ValueError(
                f"Patch result-content SHA-256 mismatch for {patch_file.target_path}: "
                f"expected {patch_file.patched_content_sha256}, derived {after_sha}"
            )
        mode = stat.S_IMODE(os.lstat(target).st_mode)
        plans.append((target, before, after, mode, patch_file.patch_file_id))

    staged: list[tuple[Path, Path, bytes]] = []
    try:
        for target, before, after, mode, _ in plans:
            fd, raw_temp = tempfile.mkstemp(prefix=".before-deploy-", dir=target.parent)
            temp_path = Path(raw_temp)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(after)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_path, mode)
            except BaseException:
                try:
                    temp_path.unlink(missing_ok=True)
                finally:
                    raise
            staged.append((target, temp_path, before))

        replaced: list[tuple[Path, bytes]] = []
        try:
            for target, temp_path, before in staged:
                os.replace(temp_path, target)
                replaced.append((target, before))
        except BaseException:
            for target, before in reversed(replaced):
                target.write_bytes(before)
            raise
    finally:
        for _, temp_path, _ in staged:
            temp_path.unlink(missing_ok=True)

    evidence_files: list[PatchMaterializationFile] = []
    try:
        for (target, before, _, _, patch_file_id), patch_file in zip(plans, patch.files, strict=True):
            observed = target.read_bytes()
            observed_sha = sha256(observed).hexdigest()
            if observed_sha != patch_file.patched_content_sha256:
                raise ValueError(
                    f"Post-materialization SHA-256 mismatch for {patch_file.target_path}: "
                    f"expected {patch_file.patched_content_sha256}, observed {observed_sha}"
                )
            evidence_files.append(
                PatchMaterializationFile(
                    patch_file_id=patch_file_id,
                    target_path=patch_file.target_path,
                    before_content_sha256=sha256(before).hexdigest(),
                    after_content_sha256=observed_sha,
                )
            )
    except BaseException:
        for target, before, _, _, _ in plans:
            target.write_bytes(before)
        raise

    provisional = PatchMaterializationResult(
        schema_version=PATCH_MATERIALIZATION_SCHEMA_VERSION,
        patch_request_sha256=patch.request_sha256,
        patch_sha256=patch.patch_sha256,
        authorization_sha256=authorization.authorization_sha256,
        materialization_sha256="",
        selected_node_id=patch.selected_node_id,
        application_status=PATCH_MATERIALIZATION_STATUS,
        review_status=PATCH_MATERIALIZATION_REVIEW_STATUS,
        files=tuple(evidence_files),
    )
    result = PatchMaterializationResult(
        **{**provisional.__dict__, "materialization_sha256": _materialization_digest(provisional)}
    )
    validate_patch_materialization(
        result,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    return result


def validate_patch_materialization(
    result: PatchMaterializationResult,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    validate_patch_materialization_authorization(
        authorization,
        patch,
        patch_request,
        proposal_request,
        investigation_request,
    )
    if result.schema_version != PATCH_MATERIALIZATION_SCHEMA_VERSION:
        raise ValueError("Unsupported patch materialization schema version")
    if result.authority != PATCH_MATERIALIZATION_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Patch materialization evidence must remain gate-neutral")
    bindings = (
        (result.patch_request_sha256, patch.request_sha256, "patch request"),
        (result.patch_sha256, patch.patch_sha256, "patch"),
        (result.authorization_sha256, authorization.authorization_sha256, "materialization authorization"),
        (result.selected_node_id, patch.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Patch materialization is bound to a different {label}")
    if result.application_status != PATCH_MATERIALIZATION_STATUS:
        raise ValueError("Patch materialization must record hash-verified application")
    if result.review_status != PATCH_MATERIALIZATION_REVIEW_STATUS:
        raise ValueError("Patch materialization cannot imply human patch review")
    expected = tuple(
        PatchMaterializationFile(
            patch_file_id=item.patch_file_id,
            target_path=item.target_path,
            before_content_sha256=item.base_content_sha256,
            after_content_sha256=item.patched_content_sha256,
        )
        for item in patch.files
    )
    if result.files != expected:
        raise ValueError("Patch materialization file evidence does not match patch hashes")
    if result.materialization_sha256 != _materialization_digest(result):
        raise ValueError("Patch materialization digest mismatch")


def build_regression_evidence_request(
    materialization: PatchMaterializationResult,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> RegressionEvidenceRequest:
    validate_patch_materialization(
        materialization,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    goals = tuple(
        sorted(
            (
                RegressionVerificationGoal(
                    verification_goal_id=item.verification_goal_id,
                    kind=item.kind,
                )
                for item in patch_request.proposal.verification_goals
            ),
            key=lambda item: item.verification_goal_id,
        )
    )
    if not goals:
        raise ValueError("Regression evidence requires at least one approved verification goal")
    provisional = RegressionEvidenceRequest(
        schema_version=REGRESSION_EVIDENCE_SCHEMA_VERSION,
        patch_request_sha256=patch.request_sha256,
        patch_sha256=patch.patch_sha256,
        authorization_sha256=authorization.authorization_sha256,
        materialization_sha256=materialization.materialization_sha256,
        request_sha256="",
        selected_node_id=patch.selected_node_id,
        verification_goals=goals,
        materialization=materialization,
    )
    result = RegressionEvidenceRequest(
        **{**provisional.__dict__, "request_sha256": _regression_request_digest(provisional)}
    )
    validate_regression_evidence_request(
        result,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    return result


def validate_regression_evidence_request(
    request: RegressionEvidenceRequest,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    validate_patch_materialization(
        request.materialization,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    if request.schema_version != REGRESSION_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("Unsupported regression evidence request schema version")
    if request.authority != REGRESSION_EVIDENCE_REQUEST_AUTHORITY or request.gate_effect != "NONE":
        raise ValueError("Regression evidence request must remain gate-neutral")
    bindings = (
        (request.patch_request_sha256, patch.request_sha256, "patch request"),
        (request.patch_sha256, patch.patch_sha256, "patch"),
        (request.authorization_sha256, authorization.authorization_sha256, "materialization authorization"),
        (
            request.materialization_sha256,
            request.materialization.materialization_sha256,
            "patch materialization",
        ),
        (request.selected_node_id, patch.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Regression evidence request is bound to a different {label}")
    expected_goals = tuple(
        sorted(
            (
                RegressionVerificationGoal(item.verification_goal_id, item.kind)
                for item in patch_request.proposal.verification_goals
            ),
            key=lambda item: item.verification_goal_id,
        )
    )
    if request.verification_goals != expected_goals:
        raise ValueError("Regression evidence verification goals do not match approved proposal")
    if request.request_sha256 != _regression_request_digest(request):
        raise ValueError("Regression evidence request digest mismatch")


def load_regression_evidence_response(
    path: Path,
    request: RegressionEvidenceRequest,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
    *,
    max_bytes: int = DEFAULT_MAX_REGRESSION_RESPONSE_BYTES,
) -> RegressionEvidenceResult:
    """Import bounded regression observations without treating declared runner output as release authority."""
    validate_regression_evidence_request(
        request,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    if max_bytes <= 0:
        raise ValueError("Regression evidence response byte limit must be positive")
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"Regression evidence response exceeds byte limit: {len(raw)} > {max_bytes}")
    try:
        payload = loads(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("Regression evidence response must be UTF-8 JSON") from error
    except JSONDecodeError as error:
        raise ValueError("Regression evidence response must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Regression evidence response root must be an object")
    _require_keys(
        payload,
        allowed={"schema_version", "request_sha256", "source", "observations"},
        required={"schema_version", "request_sha256", "source", "observations"},
        label="regression evidence response",
    )
    if payload["schema_version"] != REGRESSION_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("Unsupported regression evidence response schema version")
    if payload["request_sha256"] != request.request_sha256:
        raise ValueError("Regression evidence response is bound to a different request")
    runner, environment = _parse_regression_source(payload["source"])
    observations = _parse_regression_observations(payload["observations"], request)
    aggregate = _aggregate_regression_status(observations)
    normalized_payload = {
        "source_runner": runner,
        "source_environment": environment,
        "identity_status": REGRESSION_EVIDENCE_IDENTITY_STATUS,
        "source_format": REGRESSION_EVIDENCE_SOURCE_FORMAT,
        "aggregate_status": aggregate,
        "observations": [to_primitive(item) for item in observations],
    }
    provisional = RegressionEvidenceResult(
        schema_version=REGRESSION_EVIDENCE_SCHEMA_VERSION,
        patch_request_sha256=request.patch_request_sha256,
        patch_sha256=request.patch_sha256,
        authorization_sha256=request.authorization_sha256,
        materialization_sha256=request.materialization_sha256,
        request_sha256=request.request_sha256,
        regression_evidence_sha256="",
        selected_node_id=request.selected_node_id,
        source_runner=runner,
        source_environment=environment,
        identity_status=REGRESSION_EVIDENCE_IDENTITY_STATUS,
        source_format=REGRESSION_EVIDENCE_SOURCE_FORMAT,
        raw_input_sha256=sha256(raw).hexdigest(),
        raw_input_size_bytes=len(raw),
        normalized_output_sha256=_canonical_sha256(normalized_payload),
        aggregate_status=aggregate,
        observations=observations,
    )
    result = RegressionEvidenceResult(
        **{**provisional.__dict__, "regression_evidence_sha256": _regression_evidence_digest(provisional)}
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
    return result


def validate_regression_evidence(
    result: RegressionEvidenceResult,
    request: RegressionEvidenceRequest,
    patch: PatchResult,
    patch_request: PatchRequest,
    authorization: PatchMaterializationAuthorization,
    proposal_request: RemediationProposalRequest,
    investigation_request: EvidenceInvestigationRequest,
) -> None:
    validate_regression_evidence_request(
        request,
        patch,
        patch_request,
        authorization,
        proposal_request,
        investigation_request,
    )
    if result.schema_version != REGRESSION_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("Unsupported regression evidence schema version")
    if result.authority != REGRESSION_EVIDENCE_AUTHORITY or result.gate_effect != "NONE":
        raise ValueError("Regression evidence must remain gate-neutral")
    bindings = (
        (result.patch_request_sha256, request.patch_request_sha256, "patch request"),
        (result.patch_sha256, request.patch_sha256, "patch"),
        (result.authorization_sha256, request.authorization_sha256, "materialization authorization"),
        (result.materialization_sha256, request.materialization_sha256, "patch materialization"),
        (result.request_sha256, request.request_sha256, "regression evidence request"),
        (result.selected_node_id, request.selected_node_id, "selected node"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Regression evidence is bound to a different {label}")
    if result.identity_status != REGRESSION_EVIDENCE_IDENTITY_STATUS:
        raise ValueError("Regression runner identity must remain declared and unattested")
    if result.source_format != REGRESSION_EVIDENCE_SOURCE_FORMAT:
        raise ValueError("Unsupported regression evidence source format")
    _bounded_text(result.source_runner, "regression runner", MAX_RUNNER_CHARS)
    if result.source_environment is not None:
        _bounded_text(result.source_environment, "regression environment", MAX_ENVIRONMENT_CHARS)
    if result.raw_input_size_bytes <= 0 or not _is_sha256(result.raw_input_sha256):
        raise ValueError("Regression evidence raw input provenance is invalid")
    expected_goal_ids = tuple(item.verification_goal_id for item in request.verification_goals)
    observed_goal_ids = tuple(item.verification_goal_id for item in result.observations)
    if observed_goal_ids != expected_goal_ids:
        raise ValueError("Regression evidence must cover each approved verification goal exactly once")
    goal_map = {item.verification_goal_id: item.kind for item in request.verification_goals}
    for observation in result.observations:
        _validate_regression_observation(observation, goal_map[observation.verification_goal_id])
    if result.aggregate_status != _aggregate_regression_status(result.observations):
        raise ValueError("Regression evidence aggregate status mismatch")
    normalized_payload = {
        "source_runner": result.source_runner,
        "source_environment": result.source_environment,
        "identity_status": result.identity_status,
        "source_format": result.source_format,
        "aggregate_status": result.aggregate_status,
        "observations": [to_primitive(item) for item in result.observations],
    }
    if result.normalized_output_sha256 != _canonical_sha256(normalized_payload):
        raise ValueError("Regression evidence normalized output digest mismatch")
    if result.regression_evidence_sha256 != _regression_evidence_digest(result):
        raise ValueError("Regression evidence digest mismatch")


def patch_materialization_authorization_to_primitive(
    authorization: PatchMaterializationAuthorization,
) -> dict[str, Any]:
    return {
        "schema_version": authorization.schema_version,
        "patch_request_sha256": authorization.patch_request_sha256,
        "patch_sha256": authorization.patch_sha256,
        "authorization_sha256": authorization.authorization_sha256,
        "selected_node_id": authorization.selected_node_id,
        "operator": authorization.operator,
        "identity_status": authorization.identity_status,
        "scope": authorization.scope,
        "authority": authorization.authority,
        "gate_effect": authorization.gate_effect,
        "authority_contract": {
            "scope": "materialize_exact_patch_for_regression_only",
            "patch_review": "not_implied",
            "release_authority": "persisted_policy_decision_only",
        },
    }


def patch_materialization_to_primitive(result: PatchMaterializationResult) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "patch_request_sha256": result.patch_request_sha256,
        "patch_sha256": result.patch_sha256,
        "authorization_sha256": result.authorization_sha256,
        "materialization_sha256": result.materialization_sha256,
        "selected_node_id": result.selected_node_id,
        "application_status": result.application_status,
        "review_status": result.review_status,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "files": [to_primitive(item) for item in result.files],
        "authority_contract": {
            "materialization": "deterministic_hash_verified_workspace_mutation",
            "patch_review": "not_implied",
            "release_authority": "persisted_policy_decision_only",
        },
    }


def regression_evidence_request_to_primitive(request: RegressionEvidenceRequest) -> dict[str, Any]:
    return {
        "schema_version": request.schema_version,
        "patch_request_sha256": request.patch_request_sha256,
        "patch_sha256": request.patch_sha256,
        "authorization_sha256": request.authorization_sha256,
        "materialization_sha256": request.materialization_sha256,
        "request_sha256": request.request_sha256,
        "selected_node_id": request.selected_node_id,
        "verification_goals": [to_primitive(item) for item in request.verification_goals],
        "authority": request.authority,
        "gate_effect": request.gate_effect,
        "authority_contract": {
            "regression_evidence": "diagnostic_input_to_later_verification",
            "runner_identity": "declared_unattested",
            "command_execution": "external_to_before_deploy_pr34",
            "release_authority": "persisted_policy_decision_only",
        },
        "response_contract": {
            "schema_version": REGRESSION_EVIDENCE_SCHEMA_VERSION,
            "source_format": REGRESSION_EVIDENCE_SOURCE_FORMAT,
            "all_verification_goals_required": True,
            "raw_stdout_stderr": "not_accepted_digests_only",
            "provider_aggregate_status": "not_accepted_derived_by_before_deploy",
        },
        "materialization": patch_materialization_to_primitive(request.materialization),
    }


def regression_evidence_to_primitive(result: RegressionEvidenceResult) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "patch_request_sha256": result.patch_request_sha256,
        "patch_sha256": result.patch_sha256,
        "authorization_sha256": result.authorization_sha256,
        "materialization_sha256": result.materialization_sha256,
        "request_sha256": result.request_sha256,
        "regression_evidence_sha256": result.regression_evidence_sha256,
        "selected_node_id": result.selected_node_id,
        "authority": result.authority,
        "gate_effect": result.gate_effect,
        "aggregate_status": result.aggregate_status,
        "source": {
            "runner": result.source_runner,
            "environment": result.source_environment,
            "identity_status": result.identity_status,
            "source_format": result.source_format,
        },
        "raw_input": {"sha256": result.raw_input_sha256, "size_bytes": result.raw_input_size_bytes},
        "normalized_output_sha256": result.normalized_output_sha256,
        "observations": [to_primitive(item) for item in result.observations],
        "authority_contract": {
            "regression_evidence": "diagnostic_only",
            "release_authority": "persisted_policy_decision_only",
            "policy_mutation": "forbidden",
        },
    }


def render_patch_materialization_authorization_json(
    authorization: PatchMaterializationAuthorization,
) -> str:
    return dumps(
        patch_materialization_authorization_to_primitive(authorization),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_patch_materialization_json(result: PatchMaterializationResult) -> str:
    return dumps(patch_materialization_to_primitive(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_regression_evidence_request_json(request: RegressionEvidenceRequest) -> str:
    return dumps(regression_evidence_request_to_primitive(request), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_regression_evidence_json(result: RegressionEvidenceResult) -> str:
    return dumps(regression_evidence_to_primitive(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_patch_materialization_authorization_markdown(
    authorization: PatchMaterializationAuthorization,
) -> str:
    return (
        "# Before Deploy Patch Materialization Authorization\n\n"
        f"- Patch SHA-256: `{authorization.patch_sha256}`\n"
        f"- Authorization SHA-256: `{authorization.authorization_sha256}`\n"
        f"- Operator declaration: `{authorization.operator}`\n"
        f"- Identity status: `{authorization.identity_status}`\n"
        f"- Scope: `{authorization.scope}`\n"
        f"- Authority: `{authorization.authority}`\n"
        f"- Gate effect: `{authorization.gate_effect}`\n\n"
        "This authorizes materialization of exactly the bound patch for regression work. "
        "It is not patch review and does not authorize release.\n"
    )


def render_patch_materialization_markdown(result: PatchMaterializationResult) -> str:
    lines = [
        "# Before Deploy Patch Materialization",
        "",
        f"- Patch SHA-256: `{result.patch_sha256}`",
        f"- Materialization SHA-256: `{result.materialization_sha256}`",
        f"- Application status: `{result.application_status}`",
        f"- Review status: `{result.review_status}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "## Files",
        "",
    ]
    for item in result.files:
        lines.append(
            f"- `{item.target_path}`: `{item.before_content_sha256}` -> `{item.after_content_sha256}`"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_regression_evidence_request_markdown(request: RegressionEvidenceRequest) -> str:
    lines = [
        "# Before Deploy Regression Evidence Request",
        "",
        f"- Patch SHA-256: `{request.patch_sha256}`",
        f"- Materialization SHA-256: `{request.materialization_sha256}`",
        f"- Request SHA-256: `{request.request_sha256}`",
        f"- Authority: `{request.authority}`",
        f"- Gate effect: `{request.gate_effect}`",
        "",
        "## Required verification goals",
        "",
    ]
    lines.extend(f"- `{item.kind}` `{item.verification_goal_id}`" for item in request.verification_goals)
    lines.extend(
        [
            "",
            "Regression commands run outside PR34. Import structured observations with output digests only; "
            "raw stdout/stderr is not persisted by this artifact.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_regression_evidence_markdown(result: RegressionEvidenceResult) -> str:
    lines = [
        "# Before Deploy Regression Evidence",
        "",
        f"- Patch SHA-256: `{result.patch_sha256}`",
        f"- Materialization SHA-256: `{result.materialization_sha256}`",
        f"- Regression evidence SHA-256: `{result.regression_evidence_sha256}`",
        f"- Aggregate status: `{result.aggregate_status}`",
        f"- Runner declaration: `{result.source_runner}`",
        f"- Identity status: `{result.identity_status}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "## Observations",
        "",
    ]
    for item in result.observations:
        lines.append(f"- `{item.status}` `{item.kind}` `{item.verification_goal_id}`")
    return "\n".join(lines).rstrip() + "\n"


def render_patch_materialization_terminal(result: PatchMaterializationResult) -> str:
    return (
        "Before Deploy patch materialization: APPLIED_HASH_VERIFIED / UNREVIEWED\n"
        f"Files: {len(result.files)}\n"
        f"Patch SHA-256: {result.patch_sha256}\n"
        f"Materialization SHA-256: {result.materialization_sha256}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def render_regression_evidence_request_terminal(request: RegressionEvidenceRequest) -> str:
    return (
        "Before Deploy regression evidence request\n"
        f"Patch SHA-256: {request.patch_sha256}\n"
        f"Materialization SHA-256: {request.materialization_sha256}\n"
        f"Verification goals: {len(request.verification_goals)}\n"
        f"Request SHA-256: {request.request_sha256}\n"
        f"Authority: {request.authority}, gate_effect={request.gate_effect}\n"
    )


def render_regression_evidence_terminal(result: RegressionEvidenceResult) -> str:
    return (
        f"Before Deploy regression evidence: {result.aggregate_status}\n"
        f"Observations: {len(result.observations)}\n"
        f"Patch SHA-256: {result.patch_sha256}\n"
        f"Regression evidence SHA-256: {result.regression_evidence_sha256}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def _validated_repository_root(repository: Path) -> Path:
    if repository.is_symlink():
        raise ValueError("Patch materialization repository root must not be a symlink")
    try:
        root = repository.resolve(strict=True)
    except OSError as error:
        raise ValueError("Patch materialization repository does not exist") from error
    if not root.is_dir():
        raise ValueError("Patch materialization repository must be a directory")
    return root


def _validated_existing_regular_target(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise ValueError(f"Patch target path is not canonical: {relative_path}")
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Patch target path contains a symlink: {relative_path}")
    target = root.joinpath(*pure.parts)
    try:
        resolved = target.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"Patch target does not exist: {relative_path}") from error
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"Patch target escapes repository root: {relative_path}") from error
    mode = os.lstat(target).st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f"Patch target is not a regular file: {relative_path}")
    return target


def _apply_unified_diff(original: bytes, diff: str, target_path: str) -> bytes:
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"Patch target must be UTF-8 text: {target_path}") from error
    if "\r\n" in text:
        raise ValueError(f"CRLF patch materialization is not supported in v1: {target_path}")
    source = text.splitlines(keepends=True)
    diff_lines = diff.splitlines(keepends=True)
    hunk_indices = [index for index, line in enumerate(diff_lines) if line.startswith("@@ ")]
    if not hunk_indices:
        raise ValueError(f"Patch contains no hunks for {target_path}")
    result: list[str] = []
    source_pos = 0
    for hunk_number, hunk_index in enumerate(hunk_indices):
        header = diff_lines[hunk_index].rstrip("\n")
        match = _HUNK_RE.fullmatch(header)
        if match is None:
            raise ValueError(f"Invalid unified diff hunk header for {target_path}")
        old_start = int(match.group(1))
        old_count = int(match.group(2) or "1")
        new_start = int(match.group(3))
        new_count = int(match.group(4) or "1")
        if old_count == 0 or new_count == 0:
            raise ValueError(f"Zero-line unified diff hunks are not supported in v1: {target_path}")
        target_pos = old_start - 1
        if target_pos < source_pos or target_pos > len(source):
            raise ValueError(f"Unified diff hunk position is invalid for {target_path}")
        result.extend(source[source_pos:target_pos])
        if len(result) != new_start - 1:
            raise ValueError(f"Unified diff new-line position is invalid for {target_path}")
        cursor = target_pos
        old_seen = 0
        new_seen = 0
        end = hunk_indices[hunk_number + 1] if hunk_number + 1 < len(hunk_indices) else len(diff_lines)
        for line in diff_lines[hunk_index + 1 : end]:
            prefix = line[:1]
            payload = line[1:]
            if prefix == " ":
                if cursor >= len(source) or source[cursor] != payload:
                    raise ValueError(f"Unified diff context mismatch for {target_path}")
                result.append(payload)
                cursor += 1
                old_seen += 1
                new_seen += 1
            elif prefix == "-":
                if line.startswith("--- "):
                    raise ValueError(f"Unexpected file header inside hunk for {target_path}")
                if cursor >= len(source) or source[cursor] != payload:
                    raise ValueError(f"Unified diff removal mismatch for {target_path}")
                cursor += 1
                old_seen += 1
            elif prefix == "+":
                if line.startswith("+++ "):
                    raise ValueError(f"Unexpected file header inside hunk for {target_path}")
                result.append(payload)
                new_seen += 1
            elif line.startswith("\\ No newline at end of file"):
                raise ValueError(f"No-newline diff markers are not supported in v1: {target_path}")
            else:
                raise ValueError(f"Unsupported unified diff line for {target_path}")
        if old_seen != old_count or new_seen != new_count:
            raise ValueError(f"Unified diff hunk count mismatch for {target_path}")
        source_pos = cursor
    result.extend(source[source_pos:])
    return "".join(result).encode("utf-8")


def _parse_regression_source(value: Any) -> tuple[str, str | None]:
    if not isinstance(value, dict):
        raise ValueError("Regression evidence source must be an object")
    _require_keys(
        value,
        allowed={"runner", "environment"},
        required={"runner"},
        label="regression evidence source",
    )
    runner = _bounded_text(value["runner"], "regression runner", MAX_RUNNER_CHARS)
    environment = value.get("environment")
    return (
        runner,
        _bounded_text(environment, "regression environment", MAX_ENVIRONMENT_CHARS)
        if environment is not None
        else None,
    )


def _parse_regression_observations(
    value: Any,
    request: RegressionEvidenceRequest,
) -> tuple[RegressionObservation, ...]:
    if not isinstance(value, list):
        raise ValueError("Regression observations must be an array")
    goal_map = {item.verification_goal_id: item.kind for item in request.verification_goals}
    parsed: dict[str, RegressionObservation] = {}
    for payload in value:
        if not isinstance(payload, dict):
            raise ValueError("Regression observation entries must be objects")
        _require_keys(
            payload,
            allowed={
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
            label="regression observation",
        )
        goal_id = payload["verification_goal_id"]
        if not isinstance(goal_id, str) or goal_id not in goal_map:
            raise ValueError("Regression observation references an unknown verification goal")
        if goal_id in parsed:
            raise ValueError(f"Duplicate regression observation for verification goal: {goal_id}")
        kind = payload["kind"]
        if kind != goal_map[goal_id]:
            raise ValueError("Regression observation kind does not match approved verification goal")
        command = _parse_command(payload["command"])
        status_value = payload["status"]
        exit_code = payload["exit_code"]
        duration_ms = payload["duration_ms"]
        stdout_digest = _optional_sha256(payload["stdout_sha256"], "stdout digest")
        stderr_digest = _optional_sha256(payload["stderr_sha256"], "stderr digest")
        statement = payload["statement"]
        if statement is not None:
            statement = _bounded_text(statement, "regression observation statement", MAX_REGRESSION_STATEMENT_CHARS)
        semantic = {
            "verification_goal_id": goal_id,
            "kind": kind,
            "status": status_value,
            "command": command,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout_sha256": stdout_digest,
            "stderr_sha256": stderr_digest,
            "statement": statement,
        }
        observation = RegressionObservation(
            observation_id=_diagnostic_id("regression-observation", semantic),
            verification_goal_id=goal_id,
            kind=kind,
            status=status_value,
            command=command,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_sha256=stdout_digest,
            stderr_sha256=stderr_digest,
            statement=statement,
        )
        _validate_regression_observation(observation, goal_map[goal_id])
        parsed[goal_id] = observation
    expected = tuple(item.verification_goal_id for item in request.verification_goals)
    if tuple(sorted(parsed)) != expected:
        raise ValueError("Regression evidence must cover each approved verification goal exactly once")
    return tuple(parsed[goal_id] for goal_id in expected)


def _validate_regression_observation(observation: RegressionObservation, expected_kind: str) -> None:
    if observation.kind != expected_kind:
        raise ValueError("Regression observation kind does not match approved verification goal")
    if observation.status not in REGRESSION_STATUSES:
        raise ValueError("Unsupported regression observation status")
    if len(observation.command) > MAX_COMMAND_ITEMS:
        raise ValueError("Regression command contains too many arguments")
    for item in observation.command:
        _bounded_text(item, "regression command argument", MAX_COMMAND_ITEM_CHARS)
    if observation.exit_code is not None and (
        not isinstance(observation.exit_code, int) or isinstance(observation.exit_code, bool)
    ):
        raise ValueError("Regression exit_code must be an integer or null")
    if observation.duration_ms is not None and (
        not isinstance(observation.duration_ms, int)
        or isinstance(observation.duration_ms, bool)
        or observation.duration_ms < 0
    ):
        raise ValueError("Regression duration_ms must be a non-negative integer or null")
    _optional_sha256(observation.stdout_sha256, "stdout digest")
    _optional_sha256(observation.stderr_sha256, "stderr digest")
    if observation.statement is not None:
        _bounded_text(observation.statement, "regression observation statement", MAX_REGRESSION_STATEMENT_CHARS)
    if observation.status == "NOT_RUN":
        if observation.command or observation.exit_code is not None or observation.duration_ms is not None:
            raise ValueError("NOT_RUN regression observations cannot claim execution metadata")
    elif observation.command and observation.exit_code is None:
        raise ValueError("Executed regression command metadata requires exit_code")
    if observation.status == "PASS" and observation.exit_code not in (None, 0):
        raise ValueError("PASS regression observation cannot have a non-zero exit code")
    if observation.status == "FAIL" and observation.exit_code == 0:
        raise ValueError("FAIL regression observation cannot have exit code zero")
    semantic = {
        "verification_goal_id": observation.verification_goal_id,
        "kind": observation.kind,
        "status": observation.status,
        "command": observation.command,
        "exit_code": observation.exit_code,
        "duration_ms": observation.duration_ms,
        "stdout_sha256": observation.stdout_sha256,
        "stderr_sha256": observation.stderr_sha256,
        "statement": observation.statement,
    }
    if observation.observation_id != _diagnostic_id("regression-observation", semantic):
        raise ValueError("Regression observation ID mismatch")


def _parse_command(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("Regression command must be an array")
    if len(value) > MAX_COMMAND_ITEMS:
        raise ValueError("Regression command contains too many arguments")
    return tuple(_bounded_text(item, "regression command argument", MAX_COMMAND_ITEM_CHARS) for item in value)


def _aggregate_regression_status(observations: tuple[RegressionObservation, ...]) -> str:
    statuses = {item.status for item in observations}
    if "ERROR" in statuses:
        return "ERROR"
    if "FAIL" in statuses:
        return "FAIL"
    if "NOT_RUN" in statuses:
        return "INCOMPLETE"
    return "PASS"


def _materialization_authorization_digest(authorization: PatchMaterializationAuthorization) -> str:
    return _canonical_sha256(
        {
            "schema_version": authorization.schema_version,
            "patch_request_sha256": authorization.patch_request_sha256,
            "patch_sha256": authorization.patch_sha256,
            "selected_node_id": authorization.selected_node_id,
            "operator": authorization.operator,
            "identity_status": authorization.identity_status,
            "scope": authorization.scope,
            "authority": authorization.authority,
            "gate_effect": authorization.gate_effect,
        }
    )


def _materialization_digest(result: PatchMaterializationResult) -> str:
    return _canonical_sha256(
        {
            "schema_version": result.schema_version,
            "patch_request_sha256": result.patch_request_sha256,
            "patch_sha256": result.patch_sha256,
            "authorization_sha256": result.authorization_sha256,
            "selected_node_id": result.selected_node_id,
            "application_status": result.application_status,
            "review_status": result.review_status,
            "files": [to_primitive(item) for item in result.files],
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        }
    )


def _regression_request_digest(request: RegressionEvidenceRequest) -> str:
    return _canonical_sha256(
        {
            "schema_version": request.schema_version,
            "patch_request_sha256": request.patch_request_sha256,
            "patch_sha256": request.patch_sha256,
            "authorization_sha256": request.authorization_sha256,
            "materialization_sha256": request.materialization_sha256,
            "selected_node_id": request.selected_node_id,
            "verification_goals": [to_primitive(item) for item in request.verification_goals],
            "authority": request.authority,
            "gate_effect": request.gate_effect,
        }
    )


def _regression_evidence_digest(result: RegressionEvidenceResult) -> str:
    return _canonical_sha256(
        {
            "schema_version": result.schema_version,
            "patch_request_sha256": result.patch_request_sha256,
            "patch_sha256": result.patch_sha256,
            "authorization_sha256": result.authorization_sha256,
            "materialization_sha256": result.materialization_sha256,
            "request_sha256": result.request_sha256,
            "selected_node_id": result.selected_node_id,
            "source_runner": result.source_runner,
            "source_environment": result.source_environment,
            "identity_status": result.identity_status,
            "source_format": result.source_format,
            "raw_input_sha256": result.raw_input_sha256,
            "raw_input_size_bytes": result.raw_input_size_bytes,
            "normalized_output_sha256": result.normalized_output_sha256,
            "aggregate_status": result.aggregate_status,
            "observations": [to_primitive(item) for item in result.observations],
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        }
    )


def _diagnostic_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{_canonical_sha256(value)}"


def _canonical_sha256(value: Any) -> str:
    payload = dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(payload.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _optional_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not _is_sha256(value):
        raise ValueError(f"Regression {label} must be SHA-256 or null")
    return value


def _bounded_text(value: Any, label: str, max_chars: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be empty")
    if len(normalized) > max_chars:
        raise ValueError(f"{label} exceeds character bound")
    return normalized


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
