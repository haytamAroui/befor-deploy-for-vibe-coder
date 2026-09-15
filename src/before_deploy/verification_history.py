"""Immutable verification history and explicit supersession over canonical verification artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from pathlib import Path
from typing import Any

from before_deploy.models import to_primitive
from before_deploy.verification import (
    VERIFICATION_AUTHORITY,
    VERIFICATION_GATE_EFFECT,
    VERIFICATION_METHOD,
    VERIFICATION_RELEASE_STATUS,
    VERIFICATION_REQUIRED_OBSERVATION_STATUS,
    VERIFICATION_SCHEMA_VERSION,
    VERIFICATION_STATUSES,
    VerificationCheck,
    VerificationRequirement,
    VerificationResult,
    verification_to_primitive,
)

VERIFICATION_HISTORY_SCHEMA_VERSION = 1
VERIFICATION_HISTORY_AUTHORITY = "VERIFICATION_HISTORY"
VERIFICATION_HISTORY_GATE_EFFECT = "NONE"
VERIFICATION_HISTORY_RELEASE_STATUS = "NOT_EVALUATED"
VERIFICATION_HISTORY_RESOLUTION = "APPEND_ORDER_EXPLICIT_SUPERSESSION_V1"
VERIFICATION_CHECK_STATUSES = ("SATISFIED", "FAILED", "ERROR", "INCOMPLETE")


@dataclass(frozen=True)
class VerificationHistoryEntry:
    sequence: int
    entry_sha256: str
    verification_sha256: str
    supersedes_verification_sha256: str | None
    selected_node_id: str
    patch_sha256: str
    overall_status: str
    evidence_identity_status: str
    patch_review_status: str
    materialization_review_status: str
    verification: VerificationResult


@dataclass(frozen=True)
class VerificationHistory:
    schema_version: int
    history_sha256: str
    selected_node_id: str
    current_entry_sha256: str
    current_verification_sha256: str
    current_status: str
    entry_count: int
    resolution: str
    release_status: str
    entries: tuple[VerificationHistoryEntry, ...]
    authority: str = VERIFICATION_HISTORY_AUTHORITY
    gate_effect: str = VERIFICATION_HISTORY_GATE_EFFECT


def load_verification_artifact(path: Path) -> VerificationResult:
    """Load one canonical verification artifact and validate its internal content addressing."""
    payload = _load_json_object(path, "verification")
    return verification_from_primitive(payload)


def verification_from_primitive(payload: dict[str, Any]) -> VerificationResult:
    """Reconstruct and structurally validate a canonical PR35 verification artifact."""
    _require_keys(
        payload,
        allowed={
            "schema_version",
            "proposal_sha256",
            "approval_sha256",
            "patch_request_sha256",
            "patch_sha256",
            "materialization_authorization_sha256",
            "materialization_sha256",
            "regression_request_sha256",
            "regression_evidence_sha256",
            "verification_sha256",
            "selected_node_id",
            "method",
            "evidence_identity_status",
            "patch_review_status",
            "materialization_review_status",
            "overall_status",
            "release_status",
            "requirements",
            "checks",
            "authority",
            "gate_effect",
            "authority_contract",
        },
        required={
            "schema_version",
            "proposal_sha256",
            "approval_sha256",
            "patch_request_sha256",
            "patch_sha256",
            "materialization_authorization_sha256",
            "materialization_sha256",
            "regression_request_sha256",
            "regression_evidence_sha256",
            "verification_sha256",
            "selected_node_id",
            "method",
            "evidence_identity_status",
            "patch_review_status",
            "materialization_review_status",
            "overall_status",
            "release_status",
            "requirements",
            "checks",
            "authority",
            "gate_effect",
            "authority_contract",
        },
        label="verification",
    )
    requirements_value = payload["requirements"]
    checks_value = payload["checks"]
    if not isinstance(requirements_value, list):
        raise ValueError("Verification requirements must be an array")
    if not isinstance(checks_value, list):
        raise ValueError("Verification checks must be an array")
    requirements: list[VerificationRequirement] = []
    for value in requirements_value:
        if not isinstance(value, dict):
            raise ValueError("Verification requirement entries must be objects")
        _require_keys(
            value,
            allowed={
                "requirement_id",
                "verification_goal_id",
                "kind",
                "statement",
                "required_observation_status",
            },
            required={
                "requirement_id",
                "verification_goal_id",
                "kind",
                "statement",
                "required_observation_status",
            },
            label="verification requirement",
        )
        requirements.append(
            VerificationRequirement(
                requirement_id=value["requirement_id"],
                verification_goal_id=value["verification_goal_id"],
                kind=value["kind"],
                statement=value["statement"],
                required_observation_status=value["required_observation_status"],
            )
        )
    checks: list[VerificationCheck] = []
    for value in checks_value:
        if not isinstance(value, dict):
            raise ValueError("Verification check entries must be objects")
        _require_keys(
            value,
            allowed={
                "check_id",
                "requirement_id",
                "observation_id",
                "observed_status",
                "status",
            },
            required={
                "check_id",
                "requirement_id",
                "observation_id",
                "observed_status",
                "status",
            },
            label="verification check",
        )
        checks.append(
            VerificationCheck(
                check_id=value["check_id"],
                requirement_id=value["requirement_id"],
                observation_id=value["observation_id"],
                observed_status=value["observed_status"],
                status=value["status"],
            )
        )
    result = VerificationResult(
        schema_version=payload["schema_version"],
        proposal_sha256=payload["proposal_sha256"],
        approval_sha256=payload["approval_sha256"],
        patch_request_sha256=payload["patch_request_sha256"],
        patch_sha256=payload["patch_sha256"],
        materialization_authorization_sha256=payload["materialization_authorization_sha256"],
        materialization_sha256=payload["materialization_sha256"],
        regression_request_sha256=payload["regression_request_sha256"],
        regression_evidence_sha256=payload["regression_evidence_sha256"],
        verification_sha256=payload["verification_sha256"],
        selected_node_id=payload["selected_node_id"],
        method=payload["method"],
        evidence_identity_status=payload["evidence_identity_status"],
        patch_review_status=payload["patch_review_status"],
        materialization_review_status=payload["materialization_review_status"],
        overall_status=payload["overall_status"],
        release_status=payload["release_status"],
        requirements=tuple(requirements),
        checks=tuple(checks),
        authority=payload["authority"],
        gate_effect=payload["gate_effect"],
    )
    validate_verification_snapshot(result)
    if payload != verification_to_primitive(result):
        raise ValueError("Verification artifact is not canonical")
    return result


def validate_verification_snapshot(result: VerificationResult) -> None:
    """Validate one verification artifact without re-executing or loading its upstream evidence."""
    if result.schema_version != VERIFICATION_SCHEMA_VERSION:
        raise ValueError("Unsupported verification schema version")
    if result.authority != VERIFICATION_AUTHORITY or result.gate_effect != VERIFICATION_GATE_EFFECT:
        raise ValueError("Verification evidence must remain gate-neutral")
    if result.method != VERIFICATION_METHOD:
        raise ValueError("Unsupported verification method")
    if result.release_status != VERIFICATION_RELEASE_STATUS:
        raise ValueError("Verification cannot claim release disposition")
    if result.overall_status not in VERIFICATION_STATUSES:
        raise ValueError("Unsupported verification overall status")
    if len(result.requirements) != len(result.checks) or not result.requirements:
        raise ValueError("Verification must contain one check for every requirement")

    goal_ids = tuple(item.verification_goal_id for item in result.requirements)
    if goal_ids != tuple(sorted(goal_ids)) or len(set(goal_ids)) != len(goal_ids):
        raise ValueError("Verification requirements must have unique sorted verification goal IDs")
    requirement_ids: set[str] = set()
    check_ids: set[str] = set()
    for requirement, check in zip(result.requirements, result.checks, strict=True):
        if requirement.required_observation_status != VERIFICATION_REQUIRED_OBSERVATION_STATUS:
            raise ValueError("Verification requirements must require PASS observations")
        requirement_semantic = {
            "verification_goal_id": requirement.verification_goal_id,
            "kind": requirement.kind,
            "statement": requirement.statement,
            "required_observation_status": requirement.required_observation_status,
        }
        expected_requirement_id = _diagnostic_id("verification-requirement", requirement_semantic)
        if requirement.requirement_id != expected_requirement_id:
            raise ValueError("Verification requirement ID mismatch")
        if requirement.requirement_id in requirement_ids:
            raise ValueError("Duplicate verification requirement ID")
        requirement_ids.add(requirement.requirement_id)

        if check.requirement_id != requirement.requirement_id:
            raise ValueError("Verification check is bound to a different requirement")
        expected_check_status = _check_status(check.observed_status)
        if check.status != expected_check_status or check.status not in VERIFICATION_CHECK_STATUSES:
            raise ValueError("Verification check status mismatch")
        check_semantic = {
            "requirement_id": check.requirement_id,
            "observation_id": check.observation_id,
            "observed_status": check.observed_status,
            "status": check.status,
        }
        expected_check_id = _diagnostic_id("verification-check", check_semantic)
        if check.check_id != expected_check_id:
            raise ValueError("Verification check ID mismatch")
        if check.check_id in check_ids:
            raise ValueError("Duplicate verification check ID")
        check_ids.add(check.check_id)

    if result.overall_status != _overall_status(result.checks):
        raise ValueError("Verification overall status mismatch")
    if not _is_sha256(result.verification_sha256):
        raise ValueError("Verification digest must be SHA-256")
    if result.verification_sha256 != _verification_digest(result):
        raise ValueError("Verification digest mismatch")


def append_verification_history(
    verification: VerificationResult,
    previous: VerificationHistory | None = None,
) -> VerificationHistory:
    """Create or append an immutable linear verification history for one selected node."""
    validate_verification_snapshot(verification)
    entries: tuple[VerificationHistoryEntry, ...]
    if previous is None:
        sequence = 1
        supersedes = None
        entries = ()
    else:
        validate_verification_history(previous)
        if verification.selected_node_id != previous.selected_node_id:
            raise ValueError("Verification history cannot mix different selected node IDs")
        if any(item.verification_sha256 == verification.verification_sha256 for item in previous.entries):
            raise ValueError("Verification history cannot append a duplicate verification SHA-256")
        sequence = previous.entry_count + 1
        supersedes = previous.current_verification_sha256
        entries = previous.entries

    provisional_entry = VerificationHistoryEntry(
        sequence=sequence,
        entry_sha256="",
        verification_sha256=verification.verification_sha256,
        supersedes_verification_sha256=supersedes,
        selected_node_id=verification.selected_node_id,
        patch_sha256=verification.patch_sha256,
        overall_status=verification.overall_status,
        evidence_identity_status=verification.evidence_identity_status,
        patch_review_status=verification.patch_review_status,
        materialization_review_status=verification.materialization_review_status,
        verification=verification,
    )
    entry = VerificationHistoryEntry(
        **{**provisional_entry.__dict__, "entry_sha256": _entry_digest(provisional_entry)}
    )
    all_entries = entries + (entry,)
    provisional = VerificationHistory(
        schema_version=VERIFICATION_HISTORY_SCHEMA_VERSION,
        history_sha256="",
        selected_node_id=verification.selected_node_id,
        current_entry_sha256=entry.entry_sha256,
        current_verification_sha256=verification.verification_sha256,
        current_status=verification.overall_status,
        entry_count=len(all_entries),
        resolution=VERIFICATION_HISTORY_RESOLUTION,
        release_status=VERIFICATION_HISTORY_RELEASE_STATUS,
        entries=all_entries,
    )
    result = VerificationHistory(
        **{**provisional.__dict__, "history_sha256": _history_digest(provisional)}
    )
    validate_verification_history(result)
    if previous is not None and result.entries[:-1] != previous.entries:
        raise ValueError("Verification history append mutated prior entries")
    return result


def validate_verification_history(history: VerificationHistory) -> None:
    if history.schema_version != VERIFICATION_HISTORY_SCHEMA_VERSION:
        raise ValueError("Unsupported verification history schema version")
    if history.authority != VERIFICATION_HISTORY_AUTHORITY or history.gate_effect != "NONE":
        raise ValueError("Verification history must remain gate-neutral")
    if history.release_status != VERIFICATION_HISTORY_RELEASE_STATUS:
        raise ValueError("Verification history cannot claim release disposition")
    if history.resolution != VERIFICATION_HISTORY_RESOLUTION:
        raise ValueError("Unsupported verification history resolution rule")
    if not history.entries:
        raise ValueError("Verification history must contain at least one entry")
    if history.entry_count != len(history.entries):
        raise ValueError("Verification history entry count mismatch")

    seen_entries: set[str] = set()
    seen_verifications: set[str] = set()
    previous_verification: str | None = None
    for expected_sequence, entry in enumerate(history.entries, start=1):
        validate_verification_snapshot(entry.verification)
        if entry.sequence != expected_sequence:
            raise ValueError("Verification history sequence must be contiguous and one-based")
        if entry.selected_node_id != history.selected_node_id:
            raise ValueError("Verification history entry is bound to a different selected node")
        if entry.verification.selected_node_id != history.selected_node_id:
            raise ValueError("Embedded verification is bound to a different selected node")
        if entry.verification_sha256 != entry.verification.verification_sha256:
            raise ValueError("Verification history entry digest binding mismatch")
        if entry.patch_sha256 != entry.verification.patch_sha256:
            raise ValueError("Verification history patch binding mismatch")
        if entry.overall_status != entry.verification.overall_status:
            raise ValueError("Verification history status does not match embedded verification")
        if entry.evidence_identity_status != entry.verification.evidence_identity_status:
            raise ValueError("Verification history cannot rewrite evidence identity status")
        if entry.patch_review_status != entry.verification.patch_review_status:
            raise ValueError("Verification history cannot rewrite patch review status")
        if entry.materialization_review_status != entry.verification.materialization_review_status:
            raise ValueError("Verification history cannot rewrite materialization review status")
        if entry.supersedes_verification_sha256 != previous_verification:
            raise ValueError("Verification history supersession chain is invalid")
        if entry.entry_sha256 != _entry_digest(entry):
            raise ValueError("Verification history entry digest mismatch")
        if entry.entry_sha256 in seen_entries:
            raise ValueError("Duplicate verification history entry digest")
        if entry.verification_sha256 in seen_verifications:
            raise ValueError("Duplicate verification SHA-256 in verification history")
        seen_entries.add(entry.entry_sha256)
        seen_verifications.add(entry.verification_sha256)
        previous_verification = entry.verification_sha256

    current = history.entries[-1]
    if history.current_entry_sha256 != current.entry_sha256:
        raise ValueError("Verification history current entry is not the last appended entry")
    if history.current_verification_sha256 != current.verification_sha256:
        raise ValueError("Verification history current verification is not the last appended verification")
    if history.current_status != current.overall_status:
        raise ValueError("Verification history current status mismatch")
    if history.history_sha256 != _history_digest(history):
        raise ValueError("Verification history digest mismatch")


def load_verification_history(path: Path) -> VerificationHistory:
    payload = _load_json_object(path, "verification history")
    _require_keys(
        payload,
        allowed={
            "schema_version",
            "history_sha256",
            "selected_node_id",
            "current_entry_sha256",
            "current_verification_sha256",
            "current_status",
            "entry_count",
            "resolution",
            "release_status",
            "entries",
            "authority",
            "gate_effect",
            "authority_contract",
        },
        required={
            "schema_version",
            "history_sha256",
            "selected_node_id",
            "current_entry_sha256",
            "current_verification_sha256",
            "current_status",
            "entry_count",
            "resolution",
            "release_status",
            "entries",
            "authority",
            "gate_effect",
            "authority_contract",
        },
        label="verification history",
    )
    entries_value = payload["entries"]
    if not isinstance(entries_value, list):
        raise ValueError("Verification history entries must be an array")
    entries: list[VerificationHistoryEntry] = []
    for value in entries_value:
        if not isinstance(value, dict):
            raise ValueError("Verification history entries must be objects")
        _require_keys(
            value,
            allowed={
                "sequence",
                "entry_sha256",
                "verification_sha256",
                "supersedes_verification_sha256",
                "selected_node_id",
                "patch_sha256",
                "overall_status",
                "evidence_identity_status",
                "patch_review_status",
                "materialization_review_status",
                "verification",
            },
            required={
                "sequence",
                "entry_sha256",
                "verification_sha256",
                "supersedes_verification_sha256",
                "selected_node_id",
                "patch_sha256",
                "overall_status",
                "evidence_identity_status",
                "patch_review_status",
                "materialization_review_status",
                "verification",
            },
            label="verification history entry",
        )
        verification_value = value["verification"]
        if not isinstance(verification_value, dict):
            raise ValueError("Embedded verification must be an object")
        verification = verification_from_primitive(verification_value)
        entries.append(
            VerificationHistoryEntry(
                sequence=value["sequence"],
                entry_sha256=value["entry_sha256"],
                verification_sha256=value["verification_sha256"],
                supersedes_verification_sha256=value["supersedes_verification_sha256"],
                selected_node_id=value["selected_node_id"],
                patch_sha256=value["patch_sha256"],
                overall_status=value["overall_status"],
                evidence_identity_status=value["evidence_identity_status"],
                patch_review_status=value["patch_review_status"],
                materialization_review_status=value["materialization_review_status"],
                verification=verification,
            )
        )
    history = VerificationHistory(
        schema_version=payload["schema_version"],
        history_sha256=payload["history_sha256"],
        selected_node_id=payload["selected_node_id"],
        current_entry_sha256=payload["current_entry_sha256"],
        current_verification_sha256=payload["current_verification_sha256"],
        current_status=payload["current_status"],
        entry_count=payload["entry_count"],
        resolution=payload["resolution"],
        release_status=payload["release_status"],
        entries=tuple(entries),
        authority=payload["authority"],
        gate_effect=payload["gate_effect"],
    )
    validate_verification_history(history)
    if payload != verification_history_to_primitive(history):
        raise ValueError("Verification history artifact is not canonical")
    return history


def verification_history_to_primitive(history: VerificationHistory) -> dict[str, Any]:
    return {
        "schema_version": history.schema_version,
        "history_sha256": history.history_sha256,
        "selected_node_id": history.selected_node_id,
        "current_entry_sha256": history.current_entry_sha256,
        "current_verification_sha256": history.current_verification_sha256,
        "current_status": history.current_status,
        "entry_count": history.entry_count,
        "resolution": history.resolution,
        "release_status": history.release_status,
        "entries": [
            {
                "sequence": item.sequence,
                "entry_sha256": item.entry_sha256,
                "verification_sha256": item.verification_sha256,
                "supersedes_verification_sha256": item.supersedes_verification_sha256,
                "selected_node_id": item.selected_node_id,
                "patch_sha256": item.patch_sha256,
                "overall_status": item.overall_status,
                "evidence_identity_status": item.evidence_identity_status,
                "patch_review_status": item.patch_review_status,
                "materialization_review_status": item.materialization_review_status,
                "verification": verification_to_primitive(item.verification),
            }
            for item in history.entries
        ],
        "authority": history.authority,
        "gate_effect": history.gate_effect,
        "authority_contract": {
            "history": "append_only_explicit_linear_supersession",
            "current_resolution": "last_valid_appended_entry_not_best_status",
            "verification_authority": "evidence_only",
            "release_disposition": "not_evaluated_by_pr36",
            "release_authority": "future_release_disposition_only",
            "policy_mutation": "forbidden",
        },
    }


def render_verification_history_json(history: VerificationHistory) -> str:
    return dumps(
        verification_history_to_primitive(history),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_verification_history_markdown(history: VerificationHistory) -> str:
    lines = [
        "# Before Deploy Verification History",
        "",
        f"- History SHA-256: `{history.history_sha256}`",
        f"- Selected node: `{history.selected_node_id}`",
        f"- Current verification SHA-256: `{history.current_verification_sha256}`",
        f"- Current status: `{history.current_status}`",
        f"- Entries: `{history.entry_count}`",
        f"- Resolution: `{history.resolution}`",
        f"- Release status: `{history.release_status}`",
        f"- Authority: `{history.authority}`",
        f"- Gate effect: `{history.gate_effect}`",
        "",
        "## Entries",
        "",
    ]
    for entry in history.entries:
        predecessor = entry.supersedes_verification_sha256 or "ROOT"
        lines.append(
            f"- `{entry.sequence}` `{entry.overall_status}` `{entry.verification_sha256}` "
            f"supersedes `{predecessor}`; patch `{entry.patch_sha256}`"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "Current means the last valid appended verification in the explicit supersession chain. ",
            "History does not rank statuses, attest external runners, upgrade patch review, mutate PolicyDecision, or decide release readiness.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_verification_history_terminal(history: VerificationHistory) -> str:
    return (
        f"Before Deploy verification history: current={history.current_status}\n"
        f"Entries: {history.entry_count}\n"
        f"Current verification SHA-256: {history.current_verification_sha256}\n"
        f"History SHA-256: {history.history_sha256}\n"
        f"Release status: {history.release_status}\n"
        f"Authority: {history.authority}, gate_effect={history.gate_effect}\n"
    )


def _entry_digest(entry: VerificationHistoryEntry) -> str:
    return _canonical_sha256(
        {
            "sequence": entry.sequence,
            "verification_sha256": entry.verification_sha256,
            "supersedes_verification_sha256": entry.supersedes_verification_sha256,
            "selected_node_id": entry.selected_node_id,
            "patch_sha256": entry.patch_sha256,
            "overall_status": entry.overall_status,
            "evidence_identity_status": entry.evidence_identity_status,
            "patch_review_status": entry.patch_review_status,
            "materialization_review_status": entry.materialization_review_status,
            "verification": verification_to_primitive(entry.verification),
        }
    )


def _history_digest(history: VerificationHistory) -> str:
    return _canonical_sha256(
        {
            "schema_version": history.schema_version,
            "selected_node_id": history.selected_node_id,
            "current_entry_sha256": history.current_entry_sha256,
            "current_verification_sha256": history.current_verification_sha256,
            "current_status": history.current_status,
            "entry_count": history.entry_count,
            "resolution": history.resolution,
            "release_status": history.release_status,
            "entries": [
                {
                    "sequence": item.sequence,
                    "entry_sha256": item.entry_sha256,
                    "verification_sha256": item.verification_sha256,
                    "supersedes_verification_sha256": item.supersedes_verification_sha256,
                    "selected_node_id": item.selected_node_id,
                    "patch_sha256": item.patch_sha256,
                    "overall_status": item.overall_status,
                    "evidence_identity_status": item.evidence_identity_status,
                    "patch_review_status": item.patch_review_status,
                    "materialization_review_status": item.materialization_review_status,
                    "verification": verification_to_primitive(item.verification),
                }
                for item in history.entries
            ],
            "authority": history.authority,
            "gate_effect": history.gate_effect,
        }
    )


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
        raise ValueError(
            f"Unsupported regression observation status for verification: {observed_status}"
        ) from error


def _overall_status(checks: tuple[VerificationCheck, ...]) -> str:
    statuses = {item.status for item in checks}
    if "ERROR" in statuses:
        return "ERROR"
    if "FAILED" in statuses:
        return "FAIL"
    if "INCOMPLETE" in statuses:
        return "INCOMPLETE"
    return "PASS"


def _diagnostic_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{_canonical_sha256(value)}"


def _canonical_sha256(value: Any) -> str:
    payload = dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(payload.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


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
