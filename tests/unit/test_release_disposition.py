from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from json import dumps, loads

import pytest

import before_deploy.release_disposition as release
import before_deploy.verification_history as history
from before_deploy.inventory import collect_inventory, compute_repository_digest
from before_deploy.regression_evidence import PatchMaterializationFile, PatchMaterializationResult
from before_deploy.verification import VerificationCheck, VerificationRequirement, VerificationResult


def _materialization(content: bytes, *, target_path: str = "app.py") -> PatchMaterializationResult:
    file = PatchMaterializationFile(
        patch_file_id="patch-file:test",
        target_path=target_path,
        before_content_sha256="a" * 64,
        after_content_sha256=sha256(content).hexdigest(),
    )
    provisional = PatchMaterializationResult(
        schema_version=1,
        patch_request_sha256="c" * 64,
        patch_sha256="2" * 64,
        authorization_sha256="d" * 64,
        materialization_sha256="",
        selected_node_id="advisory-finding:test",
        application_status="APPLIED_HASH_VERIFIED",
        review_status="UNREVIEWED",
        files=(file,),
    )
    digest = release._canonical_sha256(
        {
            "schema_version": provisional.schema_version,
            "patch_request_sha256": provisional.patch_request_sha256,
            "patch_sha256": provisional.patch_sha256,
            "authorization_sha256": provisional.authorization_sha256,
            "selected_node_id": provisional.selected_node_id,
            "application_status": provisional.application_status,
            "review_status": provisional.review_status,
            "files": [history.to_primitive(item) for item in provisional.files],
            "authority": provisional.authority,
            "gate_effect": provisional.gate_effect,
        }
    )
    return replace(provisional, materialization_sha256=digest)


def _verification(materialization: PatchMaterializationResult, *, status: str = "PASS") -> VerificationResult:
    observed = {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "ERROR", "INCOMPLETE": "NOT_RUN"}[status]
    check_status = {"PASS": "SATISFIED", "FAIL": "FAILED", "ERROR": "ERROR", "INCOMPLETE": "INCOMPLETE"}[status]
    requirement_semantic = {
        "verification_goal_id": "remediation-verification:test",
        "kind": "TEST",
        "statement": "Run focused regression",
        "required_observation_status": "PASS",
    }
    requirement = VerificationRequirement(
        requirement_id=history._diagnostic_id("verification-requirement", requirement_semantic),
        verification_goal_id=requirement_semantic["verification_goal_id"],
        kind=requirement_semantic["kind"],
        statement=requirement_semantic["statement"],
        required_observation_status="PASS",
    )
    check_semantic = {
        "requirement_id": requirement.requirement_id,
        "observation_id": f"regression-observation:{status.lower()}",
        "observed_status": observed,
        "status": check_status,
    }
    check = VerificationCheck(
        check_id=history._diagnostic_id("verification-check", check_semantic),
        requirement_id=requirement.requirement_id,
        observation_id=check_semantic["observation_id"],
        observed_status=observed,
        status=check_status,
    )
    provisional = VerificationResult(
        schema_version=1,
        proposal_sha256="a" * 64,
        approval_sha256="b" * 64,
        patch_request_sha256=materialization.patch_request_sha256,
        patch_sha256=materialization.patch_sha256,
        materialization_authorization_sha256=materialization.authorization_sha256,
        materialization_sha256=materialization.materialization_sha256,
        regression_request_sha256="f" * 64,
        regression_evidence_sha256=(status[0].lower() if status != "INCOMPLETE" else "9") * 64,
        verification_sha256="",
        selected_node_id=materialization.selected_node_id,
        method="DECLARED_REMEDIATION_GOALS_V1",
        evidence_identity_status="DECLARED_UNATTESTED",
        patch_review_status="UNREVIEWED",
        materialization_review_status="UNREVIEWED",
        overall_status=status,
        release_status="NOT_EVALUATED",
        requirements=(requirement,),
        checks=(check,),
    )
    return replace(provisional, verification_sha256=history._verification_digest(provisional))


def _history(materialization: PatchMaterializationResult, *, status: str = "PASS"):
    return history.append_verification_history(_verification(materialization, status=status))


def _policy_report(tmp_path, repository_digest: str, *, outcome: str = "PASS"):
    blocking = ["blocking-fingerprint"] if outcome == "BLOCK" else []
    waiver_required = ["waiver-fingerprint"] if outcome == "WAIVER_REQUIRED" else []
    errors = ["SEC-TEST-001"] if outcome == "ERROR" else []
    reason_codes = {
        "PASS": ["REQUIRED_CONTROLS_SATISFIED"],
        "BLOCK": ["BLOCKING_FINDING:SEC-TEST-001"],
        "WAIVER_REQUIRED": ["WAIVER_REQUIRED:SEC-TEST-001"],
        "ERROR": ["CONTROL_ERROR:SEC-TEST-001"],
        "NOT_EVALUATED": ["NO_APPLICABLE_CONTROLS"],
    }[outcome]
    payload = {
        "schema_version": 1,
        "scan": {
            "manifest": {
                "scan_id": "scan-release-test",
                "repository_path": "/redacted/not-carried-forward",
                "repository_digest": repository_digest,
                "policy_digest": "1" * 64,
                "policy_name": "release-test",
                "started_at": "2026-09-15T00:00:00Z",
                "completed_at": "2026-09-15T00:01:00Z",
                "git_revision": None,
                "scanned_file_count": 1,
                "excluded_file_count": 0,
                "limitations": [],
            },
            "executions": [],
            "findings": [],
            "waivers": [],
            "decision": {
                "outcome": outcome,
                "reason_codes": reason_codes,
                "blocking_fingerprints": blocking,
                "waiver_required_fingerprints": waiver_required,
                "waived_fingerprints": [],
                "advisory_fingerprints": [],
                "error_control_ids": errors,
            },
            "project_profile": None,
            "security_analysis_plan": None,
            "coverage_audit": None,
        },
    }
    path = tmp_path / f"report-{outcome.lower()}.json"
    path.write_text(dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _ready_inputs(tmp_path, *, verification_status: str = "PASS", policy_outcome: str = "PASS"):
    repo = tmp_path / "repo"
    repo.mkdir()
    content = b"new value\n"
    (repo / "app.py").write_bytes(content)
    repository_digest = compute_repository_digest(collect_inventory(repo))
    materialization = _materialization(content)
    verification_history = _history(materialization, status=verification_status)
    policy = release.load_policy_release_evidence(
        _policy_report(tmp_path, repository_digest, outcome=policy_outcome)
    )
    snapshot = release.assess_release_snapshot(repo, policy, materialization)
    return repo, policy, materialization, verification_history, snapshot


def test_release_ready_binds_policy_verification_and_current_workspace(tmp_path):
    _, policy, materialization, verification_history, snapshot = _ready_inputs(tmp_path)

    result = release.build_release_disposition(policy, verification_history, materialization, snapshot)

    assert result.status == "READY"
    assert result.gate_effect == "ALLOW"
    assert result.authority == "RELEASE_DISPOSITION"
    assert result.snapshot.repository_status == "MATCHED"
    assert result.snapshot.patch_targets_status == "MATCHED"
    assert "REGRESSION_EVIDENCE_IDENTITY_NOT_ATTESTED" in result.limitations
    assert "DECLARED_RELEASE_REQUIREMENTS_SATISFIED" in result.reason_codes
    release.validate_release_disposition(result, policy, verification_history, materialization, snapshot)


@pytest.mark.parametrize(
    ("verification_status", "expected_release"),
    [("FAIL", "BLOCK"), ("INCOMPLETE", "HOLD"), ("ERROR", "ERROR")],
)
def test_current_verification_status_controls_release_after_policy_pass(
    tmp_path,
    verification_status,
    expected_release,
):
    _, policy, materialization, verification_history, snapshot = _ready_inputs(
        tmp_path,
        verification_status=verification_status,
    )

    result = release.build_release_disposition(policy, verification_history, materialization, snapshot)

    assert result.status == expected_release


@pytest.mark.parametrize(
    ("policy_outcome", "expected_release"),
    [("BLOCK", "BLOCK"), ("WAIVER_REQUIRED", "HOLD"), ("NOT_EVALUATED", "HOLD"), ("ERROR", "ERROR")],
)
def test_negative_policy_outcome_cannot_be_softened_by_passing_verification(
    tmp_path,
    policy_outcome,
    expected_release,
):
    _, policy, materialization, verification_history, snapshot = _ready_inputs(
        tmp_path,
        policy_outcome=policy_outcome,
    )

    result = release.build_release_disposition(policy, verification_history, materialization, snapshot)

    assert result.status == expected_release


def test_workspace_drift_after_policy_scan_holds_release(tmp_path):
    repo, policy, materialization, verification_history, _ = _ready_inputs(tmp_path)
    (repo / "other.py").write_text("drift\n", encoding="utf-8")
    snapshot = release.assess_release_snapshot(repo, policy, materialization)

    result = release.build_release_disposition(policy, verification_history, materialization, snapshot)

    assert result.status == "HOLD"
    assert "WORKSPACE_DRIFTED_SINCE_POLICY_SCAN" in result.reason_codes


def test_materialized_target_drift_holds_release(tmp_path):
    repo, policy, materialization, verification_history, _ = _ready_inputs(tmp_path)
    (repo / "app.py").write_text("changed after verification\n", encoding="utf-8")
    snapshot = release.assess_release_snapshot(repo, policy, materialization)

    result = release.build_release_disposition(policy, verification_history, materialization, snapshot)

    assert result.status == "HOLD"
    assert "PATCH_TARGET_CONTENT_DRIFT" in result.reason_codes or "WORKSPACE_DRIFTED_SINCE_POLICY_SCAN" in result.reason_codes


def test_explicit_trust_requirement_holds_unattested_evidence(tmp_path):
    _, policy, materialization, verification_history, snapshot = _ready_inputs(tmp_path)

    result = release.build_release_disposition(
        policy,
        verification_history,
        materialization,
        snapshot,
        requirements=release.ReleaseRequirements(require_attested_evidence=True),
    )

    assert result.status == "HOLD"
    assert "ATTESTED_EVIDENCE_REQUIRED" in result.reason_codes


def test_release_materialization_must_match_current_history(tmp_path):
    content = b"new value\n"
    materialization = _materialization(content)
    verification_history = _history(materialization)
    forged = replace(materialization, materialization_sha256="0" * 64)

    with pytest.raises(ValueError, match="current verification materialization"):
        release._validate_release_materialization(forged, verification_history)


def test_policy_report_rejects_forged_pass_with_blocking_fingerprint(tmp_path):
    path = _policy_report(tmp_path, "1" * 64)
    payload = loads(path.read_text(encoding="utf-8"))
    payload["scan"]["decision"]["blocking_fingerprints"] = ["forged"]
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="PASS policy decision"):
        release.load_policy_release_evidence(path)


def test_release_digest_changes_with_release_requirements(tmp_path):
    _, policy, materialization, verification_history, snapshot = _ready_inputs(tmp_path)
    default = release.build_release_disposition(policy, verification_history, materialization, snapshot)
    stricter = release.build_release_disposition(
        policy,
        verification_history,
        materialization,
        snapshot,
        requirements=release.ReleaseRequirements(require_reviewed_patch=True),
    )

    assert default.disposition_sha256 != stricter.disposition_sha256
    assert stricter.status == "HOLD"


def test_release_json_does_not_copy_absolute_repository_path(tmp_path):
    _, policy, materialization, verification_history, snapshot = _ready_inputs(tmp_path)
    result = release.build_release_disposition(policy, verification_history, materialization, snapshot)
    rendered = release.render_release_disposition_json(result)

    assert "/redacted/not-carried-forward" not in rendered
    assert "advisory_provider_input" in rendered
