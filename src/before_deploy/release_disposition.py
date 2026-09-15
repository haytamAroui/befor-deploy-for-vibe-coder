"""Deterministic final release disposition over policy and verification evidence."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path, PurePosixPath
from typing import Any

from before_deploy.inventory import DEFAULT_MAX_FILE_BYTES, collect_inventory, compute_repository_digest
from before_deploy.models import GateOutcome, to_primitive
from before_deploy.regression_evidence import (
    PATCH_MATERIALIZATION_AUTHORITY,
    PATCH_MATERIALIZATION_GATE_EFFECT,
    PATCH_MATERIALIZATION_REVIEW_STATUS,
    PATCH_MATERIALIZATION_SCHEMA_VERSION,
    PATCH_MATERIALIZATION_STATUS,
    PatchMaterializationFile,
    PatchMaterializationResult,
    patch_materialization_to_primitive,
)
from before_deploy.verification_history import VerificationHistory, validate_verification_history

RELEASE_DISPOSITION_SCHEMA_VERSION = 1
RELEASE_DISPOSITION_AUTHORITY = "RELEASE_DISPOSITION"
RELEASE_DISPOSITION_METHOD = "POLICY_PLUS_CURRENT_VERIFICATION_AND_BOUND_SNAPSHOT_V1"
RELEASE_STATUSES = ("READY", "HOLD", "BLOCK", "ERROR")
RELEASE_GATE_EFFECTS = {"READY": "ALLOW", "HOLD": "HOLD", "BLOCK": "BLOCK", "ERROR": "ERROR"}


@dataclass(frozen=True)
class ReleaseRequirements:
    require_attested_evidence: bool = False
    require_reviewed_patch: bool = False
    require_reviewed_materialization: bool = False


@dataclass(frozen=True)
class PolicyReleaseEvidence:
    source_report_sha256: str
    policy_evidence_sha256: str
    scan_id: str
    repository_digest: str
    policy_digest: str
    policy_name: str
    policy_outcome: str
    reason_codes: tuple[str, ...]
    blocking_fingerprints: tuple[str, ...]
    waiver_required_fingerprints: tuple[str, ...]
    waived_fingerprints: tuple[str, ...]
    advisory_fingerprints: tuple[str, ...]
    error_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseSnapshotAssessment:
    repository_status: str
    observed_repository_digest: str | None
    patch_targets_status: str
    drifted_target_paths: tuple[str, ...]
    out_of_scan_scope_paths: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseDisposition:
    schema_version: int
    disposition_sha256: str
    status: str
    gate_effect: str
    method: str
    source_report_sha256: str
    policy_evidence_sha256: str
    repository_digest: str
    policy_digest: str
    policy_name: str
    policy_outcome: str
    verification_history_sha256: str
    current_verification_sha256: str
    current_verification_status: str
    selected_node_id: str
    patch_sha256: str
    materialization_sha256: str
    requirements_sha256: str
    requirements: ReleaseRequirements
    snapshot: ReleaseSnapshotAssessment
    evidence_identity_status: str
    patch_review_status: str
    materialization_review_status: str
    reason_codes: tuple[str, ...]
    limitations: tuple[str, ...]
    authority: str = RELEASE_DISPOSITION_AUTHORITY


def load_policy_release_evidence(path: Path) -> PolicyReleaseEvidence:
    raw = path.read_bytes()
    try:
        payload = loads(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("Policy report must be UTF-8 JSON") from error
    except JSONDecodeError as error:
        raise ValueError("Policy report must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Policy report root must be an object")
    _require_keys(payload, {"schema_version", "scan"}, {"schema_version", "scan"}, "policy report")
    if payload["schema_version"] != 1:
        raise ValueError("Unsupported policy report schema version")
    scan = payload["scan"]
    if not isinstance(scan, dict):
        raise ValueError("Policy report scan must be an object")
    _require_keys(
        scan,
        {
            "manifest",
            "executions",
            "findings",
            "waivers",
            "decision",
            "project_profile",
            "security_analysis_plan",
            "coverage_audit",
        },
        {"manifest", "executions", "findings", "waivers", "decision"},
        "policy report scan",
    )
    manifest = scan["manifest"]
    decision = scan["decision"]
    if not isinstance(manifest, dict) or not isinstance(decision, dict):
        raise ValueError("Policy report manifest and decision must be objects")
    _require_keys(
        manifest,
        {
            "scan_id",
            "repository_path",
            "repository_digest",
            "policy_digest",
            "policy_name",
            "started_at",
            "completed_at",
            "git_revision",
            "scanned_file_count",
            "excluded_file_count",
            "limitations",
        },
        {
            "scan_id",
            "repository_path",
            "repository_digest",
            "policy_digest",
            "policy_name",
            "started_at",
            "completed_at",
            "git_revision",
            "scanned_file_count",
            "excluded_file_count",
            "limitations",
        },
        "policy report manifest",
    )
    decision_keys = {
        "outcome",
        "reason_codes",
        "blocking_fingerprints",
        "waiver_required_fingerprints",
        "waived_fingerprints",
        "advisory_fingerprints",
        "error_control_ids",
    }
    _require_keys(decision, decision_keys, decision_keys, "policy decision")
    try:
        outcome = GateOutcome(decision["outcome"]).value
    except (TypeError, ValueError) as error:
        raise ValueError("Policy decision has an unsupported outcome") from error
    values = {
        "reason_codes": _sorted_unique_strings(decision["reason_codes"], "policy reason codes"),
        "blocking_fingerprints": _sorted_unique_strings(decision["blocking_fingerprints"], "blocking fingerprints"),
        "waiver_required_fingerprints": _sorted_unique_strings(
            decision["waiver_required_fingerprints"], "waiver-required fingerprints"
        ),
        "waived_fingerprints": _sorted_unique_strings(decision["waived_fingerprints"], "waived fingerprints"),
        "advisory_fingerprints": _sorted_unique_strings(decision["advisory_fingerprints"], "advisory fingerprints"),
        "error_control_ids": _sorted_unique_strings(decision["error_control_ids"], "error control IDs"),
    }
    _validate_policy_decision_shape(
        outcome,
        values["blocking_fingerprints"],
        values["waiver_required_fingerprints"],
        values["error_control_ids"],
    )
    semantic = {
        "scan_id": _nonempty_text(manifest["scan_id"], "scan ID"),
        "repository_digest": _sha256_text(manifest["repository_digest"], "repository digest"),
        "policy_digest": _sha256_text(manifest["policy_digest"], "policy digest"),
        "policy_name": _nonempty_text(manifest["policy_name"], "policy name"),
        "policy_outcome": outcome,
        **values,
    }
    return PolicyReleaseEvidence(
        source_report_sha256=sha256(raw).hexdigest(),
        policy_evidence_sha256=_canonical_sha256(semantic),
        scan_id=semantic["scan_id"],
        repository_digest=semantic["repository_digest"],
        policy_digest=semantic["policy_digest"],
        policy_name=semantic["policy_name"],
        policy_outcome=outcome,
        **values,
    )


def load_release_materialization(path: Path, history: VerificationHistory) -> PatchMaterializationResult:
    validate_verification_history(history)
    payload = _load_json_object(path, "patch materialization")
    allowed = {
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
    }
    _require_keys(payload, allowed, allowed, "patch materialization")
    files_value = payload["files"]
    if not isinstance(files_value, list) or not files_value:
        raise ValueError("Patch materialization files must be a non-empty array")
    files: list[PatchMaterializationFile] = []
    seen_paths: set[str] = set()
    for value in files_value:
        if not isinstance(value, dict):
            raise ValueError("Patch materialization file entries must be objects")
        keys = {"patch_file_id", "target_path", "before_content_sha256", "after_content_sha256"}
        _require_keys(value, keys, keys, "patch materialization file")
        target_path = _canonical_relative_path(value["target_path"])
        if target_path in seen_paths:
            raise ValueError("Patch materialization contains duplicate target paths")
        seen_paths.add(target_path)
        files.append(
            PatchMaterializationFile(
                patch_file_id=_nonempty_text(value["patch_file_id"], "patch file ID"),
                target_path=target_path,
                before_content_sha256=_sha256_text(value["before_content_sha256"], "before-content digest"),
                after_content_sha256=_sha256_text(value["after_content_sha256"], "after-content digest"),
            )
        )
    result = PatchMaterializationResult(
        schema_version=payload["schema_version"],
        patch_request_sha256=_sha256_text(payload["patch_request_sha256"], "patch request digest"),
        patch_sha256=_sha256_text(payload["patch_sha256"], "patch digest"),
        authorization_sha256=_sha256_text(payload["authorization_sha256"], "authorization digest"),
        materialization_sha256=_sha256_text(payload["materialization_sha256"], "materialization digest"),
        selected_node_id=_nonempty_text(payload["selected_node_id"], "selected node ID"),
        application_status=payload["application_status"],
        review_status=payload["review_status"],
        files=tuple(files),
        authority=payload["authority"],
        gate_effect=payload["gate_effect"],
    )
    _validate_release_materialization(result, history)
    if payload != patch_materialization_to_primitive(result):
        raise ValueError("Patch materialization artifact is not canonical")
    return result


def assess_release_snapshot(
    repository: Path,
    policy: PolicyReleaseEvidence,
    materialization: PatchMaterializationResult,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> ReleaseSnapshotAssessment:
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be greater than zero")
    if repository.is_symlink():
        raise ValueError("Release repository root must not be a symlink")
    inventory = collect_inventory(repository, max_file_bytes=max_file_bytes)
    observed_digest = compute_repository_digest(inventory)
    included = {item.relative_to(inventory.root).as_posix() for item in inventory.files}
    drifted: set[str] = set()
    out_of_scope: set[str] = set()
    for item in materialization.files:
        if item.target_path not in included:
            out_of_scope.add(item.target_path)
        try:
            target = _validated_release_target(inventory.root, item.target_path)
            if sha256(target.read_bytes()).hexdigest() != item.after_content_sha256:
                drifted.add(item.target_path)
        except (OSError, ValueError):
            drifted.add(item.target_path)
    return ReleaseSnapshotAssessment(
        repository_status="MATCHED" if observed_digest == policy.repository_digest else "DRIFTED",
        observed_repository_digest=observed_digest,
        patch_targets_status="MATCHED" if not drifted and not out_of_scope else "DRIFTED",
        drifted_target_paths=tuple(sorted(drifted)),
        out_of_scan_scope_paths=tuple(sorted(out_of_scope)),
    )


def build_release_disposition(
    policy: PolicyReleaseEvidence,
    history: VerificationHistory,
    materialization: PatchMaterializationResult,
    snapshot: ReleaseSnapshotAssessment,
    *,
    requirements: ReleaseRequirements | None = None,
) -> ReleaseDisposition:
    validate_verification_history(history)
    _validate_release_materialization(materialization, history)
    requirements = requirements or ReleaseRequirements()
    _validate_requirements(requirements)
    current = history.entries[-1].verification
    reasons: set[str] = set()
    status = _derive_release_status(policy, history, snapshot, requirements, reasons)
    limitations = _limitations(current.evidence_identity_status, current.patch_review_status, current.materialization_review_status)
    provisional = ReleaseDisposition(
        schema_version=RELEASE_DISPOSITION_SCHEMA_VERSION,
        disposition_sha256="",
        status=status,
        gate_effect=RELEASE_GATE_EFFECTS[status],
        method=RELEASE_DISPOSITION_METHOD,
        source_report_sha256=policy.source_report_sha256,
        policy_evidence_sha256=policy.policy_evidence_sha256,
        repository_digest=policy.repository_digest,
        policy_digest=policy.policy_digest,
        policy_name=policy.policy_name,
        policy_outcome=policy.policy_outcome,
        verification_history_sha256=history.history_sha256,
        current_verification_sha256=history.current_verification_sha256,
        current_verification_status=history.current_status,
        selected_node_id=history.selected_node_id,
        patch_sha256=current.patch_sha256,
        materialization_sha256=current.materialization_sha256,
        requirements_sha256=_canonical_sha256(to_primitive(requirements)),
        requirements=requirements,
        snapshot=snapshot,
        evidence_identity_status=current.evidence_identity_status,
        patch_review_status=current.patch_review_status,
        materialization_review_status=current.materialization_review_status,
        reason_codes=tuple(sorted(reasons)),
        limitations=limitations,
    )
    result = replace_disposition_digest(provisional)
    validate_release_disposition(result, policy, history, materialization, snapshot)
    return result


def replace_disposition_digest(result: ReleaseDisposition) -> ReleaseDisposition:
    return ReleaseDisposition(**{**result.__dict__, "disposition_sha256": _release_digest(result)})


def validate_release_disposition(
    result: ReleaseDisposition,
    policy: PolicyReleaseEvidence,
    history: VerificationHistory,
    materialization: PatchMaterializationResult,
    snapshot: ReleaseSnapshotAssessment,
) -> None:
    validate_verification_history(history)
    _validate_release_materialization(materialization, history)
    _validate_requirements(result.requirements)
    if result.schema_version != RELEASE_DISPOSITION_SCHEMA_VERSION:
        raise ValueError("Unsupported release disposition schema version")
    if result.authority != RELEASE_DISPOSITION_AUTHORITY:
        raise ValueError("Release disposition authority is invalid")
    if result.status not in RELEASE_STATUSES or result.gate_effect != RELEASE_GATE_EFFECTS[result.status]:
        raise ValueError("Release disposition status/gate effect is invalid")
    if result.method != RELEASE_DISPOSITION_METHOD:
        raise ValueError("Unsupported release disposition method")
    current = history.entries[-1].verification
    bindings = (
        (result.source_report_sha256, policy.source_report_sha256, "source policy report"),
        (result.policy_evidence_sha256, policy.policy_evidence_sha256, "policy evidence"),
        (result.repository_digest, policy.repository_digest, "repository digest"),
        (result.policy_digest, policy.policy_digest, "policy digest"),
        (result.policy_name, policy.policy_name, "policy name"),
        (result.policy_outcome, policy.policy_outcome, "policy outcome"),
        (result.verification_history_sha256, history.history_sha256, "verification history"),
        (result.current_verification_sha256, history.current_verification_sha256, "current verification"),
        (result.current_verification_status, history.current_status, "current verification status"),
        (result.selected_node_id, history.selected_node_id, "selected node"),
        (result.patch_sha256, current.patch_sha256, "patch"),
        (result.materialization_sha256, current.materialization_sha256, "materialization"),
        (result.evidence_identity_status, current.evidence_identity_status, "evidence identity status"),
        (result.patch_review_status, current.patch_review_status, "patch review status"),
        (result.materialization_review_status, current.materialization_review_status, "materialization review status"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ValueError(f"Release disposition is bound to a different {label}")
    if result.snapshot != snapshot:
        raise ValueError("Release disposition snapshot assessment mismatch")
    if result.requirements_sha256 != _canonical_sha256(to_primitive(result.requirements)):
        raise ValueError("Release requirements digest mismatch")
    expected_reasons: set[str] = set()
    expected_status = _derive_release_status(policy, history, snapshot, result.requirements, expected_reasons)
    if result.status != expected_status or result.reason_codes != tuple(sorted(expected_reasons)):
        raise ValueError("Release disposition derivation mismatch")
    expected_limitations = _limitations(
        current.evidence_identity_status,
        current.patch_review_status,
        current.materialization_review_status,
    )
    if result.limitations != expected_limitations:
        raise ValueError("Release disposition limitations mismatch")
    if result.disposition_sha256 != _release_digest(result):
        raise ValueError("Release disposition digest mismatch")


def release_disposition_to_primitive(result: ReleaseDisposition) -> dict[str, Any]:
    return {
        "schema_version": result.schema_version,
        "disposition_sha256": result.disposition_sha256,
        "status": result.status,
        "gate_effect": result.gate_effect,
        "method": result.method,
        "source_report_sha256": result.source_report_sha256,
        "policy_evidence_sha256": result.policy_evidence_sha256,
        "repository_digest": result.repository_digest,
        "policy_digest": result.policy_digest,
        "policy_name": result.policy_name,
        "policy_outcome": result.policy_outcome,
        "verification_history_sha256": result.verification_history_sha256,
        "current_verification_sha256": result.current_verification_sha256,
        "current_verification_status": result.current_verification_status,
        "selected_node_id": result.selected_node_id,
        "patch_sha256": result.patch_sha256,
        "materialization_sha256": result.materialization_sha256,
        "requirements_sha256": result.requirements_sha256,
        "requirements": to_primitive(result.requirements),
        "snapshot": to_primitive(result.snapshot),
        "evidence_identity_status": result.evidence_identity_status,
        "patch_review_status": result.patch_review_status,
        "materialization_review_status": result.materialization_review_status,
        "reason_codes": list(result.reason_codes),
        "limitations": list(result.limitations),
        "authority": result.authority,
        "authority_contract": {
            "security_policy_authority": "persisted_deterministic_policy_decision",
            "verification_selection": "current_entry_from_validated_verification_history",
            "workspace_binding": "current_repository_digest_and_materialized_file_hashes",
            "advisory_provider_input": "structurally_excluded",
            "llm_release_decision": "forbidden",
            "ready_scope": "declared_release_requirements_only",
        },
    }


def render_release_disposition_json(result: ReleaseDisposition) -> str:
    return dumps(release_disposition_to_primitive(result), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_release_disposition_markdown(result: ReleaseDisposition) -> str:
    lines = [
        "# Before Deploy Release Disposition",
        "",
        f"- Status: **{result.status}**",
        f"- Gate effect: `{result.gate_effect}`",
        f"- Disposition SHA-256: `{result.disposition_sha256}`",
        f"- Policy: `{result.policy_name}` / `{result.policy_outcome}`",
        f"- Repository digest: `{result.repository_digest}`",
        f"- Current verification: `{result.current_verification_status}` / `{result.current_verification_sha256}`",
        f"- Verification history: `{result.verification_history_sha256}`",
        f"- Patch: `{result.patch_sha256}`",
        f"- Workspace snapshot: `{result.snapshot.repository_status}`",
        f"- Patch targets: `{result.snapshot.patch_targets_status}`",
        f"- Authority: `{result.authority}`",
        "",
        "## Reasons",
        "",
        *(f"- `{item}`" for item in result.reason_codes),
        "",
        "## Assurance limitations",
        "",
        *(f"- `{item}`" for item in result.limitations),
        "",
        "## Boundary",
        "",
        "READY means the persisted deterministic policy decision is PASS, the current verification is PASS, the current workspace matches the policy scan digest, all materialized target hashes still match, and all explicitly configured release requirements are satisfied. It does not prove absence of defects outside the declared scan/evidence scope.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def render_release_disposition_terminal(result: ReleaseDisposition) -> str:
    return (
        f"Before Deploy release: {result.status}\n"
        f"Policy: {result.policy_outcome}\n"
        f"Verification: {result.current_verification_status}\n"
        f"Workspace: {result.snapshot.repository_status}\n"
        f"Patch targets: {result.snapshot.patch_targets_status}\n"
        f"Disposition SHA-256: {result.disposition_sha256}\n"
        f"Authority: {result.authority}, gate_effect={result.gate_effect}\n"
    )


def _derive_release_status(
    policy: PolicyReleaseEvidence,
    history: VerificationHistory,
    snapshot: ReleaseSnapshotAssessment,
    requirements: ReleaseRequirements,
    reasons: set[str],
) -> str:
    outcome = policy.policy_outcome
    if outcome == GateOutcome.ERROR.value:
        reasons.add("POLICY_ERROR")
        return "ERROR"
    if outcome == GateOutcome.BLOCK.value:
        reasons.add("POLICY_BLOCK")
        return "BLOCK"
    if outcome == GateOutcome.WAIVER_REQUIRED.value:
        reasons.add("POLICY_WAIVER_REQUIRED")
        return "HOLD"
    if outcome == GateOutcome.NOT_EVALUATED.value:
        reasons.add("POLICY_NOT_EVALUATED")
        return "HOLD"
    if outcome != GateOutcome.PASS.value:
        raise ValueError("Unsupported policy outcome for release disposition")
    reasons.add("POLICY_PASS")
    if snapshot.repository_status != "MATCHED":
        reasons.add("WORKSPACE_DRIFTED_SINCE_POLICY_SCAN")
        return "HOLD"
    reasons.add("WORKSPACE_MATCHES_POLICY_SCAN")
    if snapshot.patch_targets_status != "MATCHED":
        if snapshot.drifted_target_paths:
            reasons.add("PATCH_TARGET_CONTENT_DRIFT")
        if snapshot.out_of_scan_scope_paths:
            reasons.add("PATCH_TARGET_OUTSIDE_POLICY_SCAN_SCOPE")
        return "HOLD"
    reasons.add("PATCH_TARGETS_MATCH_MATERIALIZATION")
    current = history.entries[-1].verification
    if current.overall_status == "ERROR":
        reasons.add("CURRENT_VERIFICATION_ERROR")
        return "ERROR"
    if current.overall_status == "FAIL":
        reasons.add("CURRENT_VERIFICATION_FAIL")
        return "BLOCK"
    if current.overall_status == "INCOMPLETE":
        reasons.add("CURRENT_VERIFICATION_INCOMPLETE")
        return "HOLD"
    if current.overall_status != "PASS":
        raise ValueError("Unsupported current verification status")
    reasons.add("CURRENT_VERIFICATION_PASS")
    if requirements.require_attested_evidence and current.evidence_identity_status != "ATTESTED":
        reasons.add("ATTESTED_EVIDENCE_REQUIRED")
        return "HOLD"
    if requirements.require_reviewed_patch and current.patch_review_status != "REVIEWED":
        reasons.add("REVIEWED_PATCH_REQUIRED")
        return "HOLD"
    if requirements.require_reviewed_materialization and current.materialization_review_status != "REVIEWED":
        reasons.add("REVIEWED_MATERIALIZATION_REQUIRED")
        return "HOLD"
    reasons.add("DECLARED_RELEASE_REQUIREMENTS_SATISFIED")
    return "READY"


def _validate_release_materialization(result: PatchMaterializationResult, history: VerificationHistory) -> None:
    if result.schema_version != PATCH_MATERIALIZATION_SCHEMA_VERSION:
        raise ValueError("Unsupported patch materialization schema version")
    if result.authority != PATCH_MATERIALIZATION_AUTHORITY or result.gate_effect != PATCH_MATERIALIZATION_GATE_EFFECT:
        raise ValueError("Patch materialization must remain gate-neutral evidence")
    if result.application_status != PATCH_MATERIALIZATION_STATUS:
        raise ValueError("Patch materialization must be hash-verified")
    if result.review_status != PATCH_MATERIALIZATION_REVIEW_STATUS:
        raise ValueError("Patch materialization cannot rewrite review status")
    current = history.entries[-1].verification
    if result.materialization_sha256 != current.materialization_sha256:
        raise ValueError("Patch materialization is not the current verification materialization")
    if result.patch_sha256 != current.patch_sha256:
        raise ValueError("Patch materialization is bound to a different current patch")
    if result.selected_node_id != history.selected_node_id:
        raise ValueError("Patch materialization is bound to a different selected node")
    expected = _canonical_sha256(
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
    if result.materialization_sha256 != expected:
        raise ValueError("Patch materialization digest mismatch")


def _validate_policy_decision_shape(
    outcome: str,
    blocking: tuple[str, ...],
    waiver_required: tuple[str, ...],
    errors: tuple[str, ...],
) -> None:
    if outcome == GateOutcome.ERROR.value and not errors:
        raise ValueError("ERROR policy decision must identify deterministic error controls/evidence")
    if outcome == GateOutcome.BLOCK.value and not blocking:
        raise ValueError("BLOCK policy decision must identify blocking fingerprints")
    if outcome == GateOutcome.WAIVER_REQUIRED.value and not waiver_required:
        raise ValueError("WAIVER_REQUIRED policy decision must identify waiver-required fingerprints")
    if outcome == GateOutcome.PASS.value and (blocking or waiver_required or errors):
        raise ValueError("PASS policy decision cannot contain unresolved blocking/error evidence")


def _validated_release_target(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(_canonical_relative_path(relative_path))
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Release target contains a symlink: {relative_path}")
    target = root.joinpath(*pure.parts)
    resolved = target.resolve(strict=True)
    resolved.relative_to(root)
    if not stat.S_ISREG(os.lstat(target).st_mode):
        raise ValueError(f"Release target is not a regular file: {relative_path}")
    return target


def _limitations(evidence: str, patch_review: str, materialization_review: str) -> tuple[str, ...]:
    values: set[str] = set()
    if evidence != "ATTESTED":
        values.add("REGRESSION_EVIDENCE_IDENTITY_NOT_ATTESTED")
    if patch_review != "REVIEWED":
        values.add("PATCH_NOT_HUMAN_REVIEW_ATTESTED")
    if materialization_review != "REVIEWED":
        values.add("MATERIALIZATION_NOT_HUMAN_REVIEW_ATTESTED")
    return tuple(sorted(values))


def _release_digest(result: ReleaseDisposition) -> str:
    value = release_disposition_to_primitive(result).copy()
    value.pop("disposition_sha256")
    value.pop("authority_contract")
    return _canonical_sha256(value)


def _validate_requirements(requirements: ReleaseRequirements) -> None:
    if any(not isinstance(value, bool) for value in to_primitive(requirements).values()):
        raise ValueError("Release requirements must be boolean")


def _canonical_relative_path(value: Any) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("Release target path must be a canonical POSIX string")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise ValueError(f"Release target path is not canonical: {value}")
    if pure.as_posix() != value:
        raise ValueError(f"Release target path is not canonical: {value}")
    return value


def _sorted_unique_strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    parsed = tuple(_nonempty_text(item, label) for item in value)
    if parsed != tuple(sorted(parsed)) or len(parsed) != len(set(parsed)):
        raise ValueError(f"{label} must be sorted and unique")
    return parsed


def _nonempty_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _sha256_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256(dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


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


def _require_keys(value: dict[str, Any], allowed: set[str], required: set[str], label: str) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise ValueError(f"Unsupported {label} field: {extra[0]}")
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"Missing {label} field: {missing[0]}")
