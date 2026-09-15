from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from json import dumps
from types import SimpleNamespace

import pytest

import before_deploy.regression_evidence as regression
from before_deploy.human_approval_patch import PatchFile, PatchRequest, PatchResult


def _patch(tmp_path, *, target_path: str = "app.py", expected_after: bytes | None = None):
    before = b"line one\nold value\n"
    after = expected_after or b"line one\nnew value\n"
    diff = (
        f"diff --git a/{target_path} b/{target_path}\n"
        f"--- a/{target_path}\n"
        f"+++ b/{target_path}\n"
        "@@ -1,2 +1,2 @@\n"
        " line one\n"
        "-old value\n"
        "+new value\n"
    )
    patch_file = PatchFile(
        patch_file_id="patch-file:test",
        target_path=target_path,
        base_content_sha256=sha256(before).hexdigest(),
        patched_content_sha256=sha256(after).hexdigest(),
        diff_sha256=sha256(diff.encode()).hexdigest(),
        unified_diff=diff,
    )
    proposal = SimpleNamespace(
        verification_goals=(
            SimpleNamespace(verification_goal_id="remediation-verification:test", kind="TEST"),
        )
    )
    request = PatchRequest(
        schema_version=1,
        proposal_request_sha256="1" * 64,
        proposal_sha256="2" * 64,
        approval_sha256="3" * 64,
        request_sha256="4" * 64,
        selected_node_id="advisory-finding:test",
        allowed_target_paths=(target_path,),
        verification_goal_ids=("remediation-verification:test",),
        proposal=proposal,
        approval=SimpleNamespace(),
    )
    patch = PatchResult(
        schema_version=1,
        proposal_request_sha256=request.proposal_request_sha256,
        proposal_sha256=request.proposal_sha256,
        approval_sha256=request.approval_sha256,
        request_sha256=request.request_sha256,
        patch_sha256="5" * 64,
        selected_node_id=request.selected_node_id,
        source_provider="generator",
        declared_model=None,
        identity_status="DECLARED_UNATTESTED",
        source_format="before-deploy-patch-v1",
        raw_input_sha256="6" * 64,
        raw_input_size_bytes=10,
        normalized_output_sha256="7" * 64,
        application_status="NOT_APPLIED",
        review_status="UNREVIEWED",
        files=(patch_file,),
    )
    authorization = regression.PatchMaterializationAuthorization(
        schema_version=1,
        patch_request_sha256=request.request_sha256,
        patch_sha256=patch.patch_sha256,
        authorization_sha256="8" * 64,
        selected_node_id=patch.selected_node_id,
        operator="human@example.test",
        identity_status="DECLARED_UNATTESTED",
        scope="APPLY_EXACT_PATCH_FOR_REGRESSION_ONLY",
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / target_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(before)
    return repo, target, before, after, request, patch, authorization


def test_materialization_authorization_requires_exact_patch_digest(monkeypatch):
    monkeypatch.setattr(regression, "validate_patch_result", lambda *args, **kwargs: None)
    patch = SimpleNamespace(
        request_sha256="1" * 64,
        patch_sha256="2" * 64,
        selected_node_id="node:test",
    )

    with pytest.raises(ValueError, match="Confirmed patch SHA-256"):
        regression.build_patch_materialization_authorization(
            patch,
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            confirmed_patch_sha256="3" * 64,
            operator="human@example.test",
        )

    result = regression.build_patch_materialization_authorization(
        patch,
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        confirmed_patch_sha256=patch.patch_sha256,
        operator="human@example.test",
    )
    assert result.scope == "APPLY_EXACT_PATCH_FOR_REGRESSION_ONLY"
    assert result.authority == "PATCH_MATERIALIZATION_WORKFLOW"
    assert result.gate_effect == "NONE"


def test_materialize_patch_preflights_and_verifies_hashes(tmp_path, monkeypatch):
    repo, target, before, after, request, patch, authorization = _patch(tmp_path)
    monkeypatch.setattr(
        regression,
        "validate_patch_materialization_authorization",
        lambda *args, **kwargs: None,
    )

    result = regression.materialize_patch(
        repo,
        patch,
        request,
        authorization,
        SimpleNamespace(),
        SimpleNamespace(),
    )

    assert target.read_bytes() == after
    assert result.application_status == "APPLIED_HASH_VERIFIED"
    assert result.review_status == "UNREVIEWED"
    assert result.authority == "PATCH_MATERIALIZATION_EVIDENCE"
    assert result.gate_effect == "NONE"
    assert result.files[0].before_content_sha256 == sha256(before).hexdigest()
    assert result.files[0].after_content_sha256 == sha256(after).hexdigest()


def test_materialization_base_mismatch_fails_before_mutation(tmp_path, monkeypatch):
    repo, target, before, _, request, patch, authorization = _patch(tmp_path)
    target.write_bytes(b"workspace drift\n")
    monkeypatch.setattr(
        regression,
        "validate_patch_materialization_authorization",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(ValueError, match="base-content SHA-256 mismatch"):
        regression.materialize_patch(
            repo,
            patch,
            request,
            authorization,
            SimpleNamespace(),
            SimpleNamespace(),
        )
    assert target.read_bytes() == b"workspace drift\n"
    assert target.read_bytes() != before


def test_materialization_result_hash_mismatch_fails_before_mutation(tmp_path, monkeypatch):
    wrong_after = b"not the derived bytes\n"
    repo, target, before, _, request, patch, authorization = _patch(
        tmp_path,
        expected_after=wrong_after,
    )
    monkeypatch.setattr(
        regression,
        "validate_patch_materialization_authorization",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(ValueError, match="result-content SHA-256 mismatch"):
        regression.materialize_patch(
            repo,
            patch,
            request,
            authorization,
            SimpleNamespace(),
            SimpleNamespace(),
        )
    assert target.read_bytes() == before


def test_materialization_rejects_symlink_target(tmp_path, monkeypatch):
    repo, target, _, _, request, patch, authorization = _patch(tmp_path)
    real = repo / "real.py"
    real.write_text("line one\nold value\n", encoding="utf-8")
    target.unlink()
    target.symlink_to(real)
    monkeypatch.setattr(
        regression,
        "validate_patch_materialization_authorization",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(ValueError, match="symlink"):
        regression.materialize_patch(
            repo,
            patch,
            request,
            authorization,
            SimpleNamespace(),
            SimpleNamespace(),
        )


def test_regression_request_binds_patch_materialization_and_goals(monkeypatch):
    monkeypatch.setattr(regression, "validate_patch_materialization", lambda *args, **kwargs: None)
    materialization = SimpleNamespace(materialization_sha256="a" * 64)
    patch = SimpleNamespace(request_sha256="b" * 64, patch_sha256="c" * 64, selected_node_id="node:test")
    patch_request = SimpleNamespace(
        proposal=SimpleNamespace(
            verification_goals=(
                SimpleNamespace(verification_goal_id="goal-b", kind="STATIC_SCAN"),
                SimpleNamespace(verification_goal_id="goal-a", kind="TEST"),
            )
        )
    )
    authorization = SimpleNamespace(authorization_sha256="d" * 64)

    request = regression.build_regression_evidence_request(
        materialization,
        patch,
        patch_request,
        authorization,
        SimpleNamespace(),
        SimpleNamespace(),
    )

    assert [item.verification_goal_id for item in request.verification_goals] == ["goal-a", "goal-b"]
    assert request.patch_sha256 == patch.patch_sha256
    assert request.materialization_sha256 == materialization.materialization_sha256
    assert request.authority == "REGRESSION_EVIDENCE_CONTEXT"
    assert request.gate_effect == "NONE"


def _regression_request():
    materialization = regression.PatchMaterializationResult(
        schema_version=1,
        patch_request_sha256="1" * 64,
        patch_sha256="2" * 64,
        authorization_sha256="3" * 64,
        materialization_sha256="4" * 64,
        selected_node_id="node:test",
        application_status="APPLIED_HASH_VERIFIED",
        review_status="UNREVIEWED",
        files=(),
    )
    return regression.RegressionEvidenceRequest(
        schema_version=1,
        patch_request_sha256="1" * 64,
        patch_sha256="2" * 64,
        authorization_sha256="3" * 64,
        materialization_sha256="4" * 64,
        request_sha256="5" * 64,
        selected_node_id="node:test",
        verification_goals=(
            regression.RegressionVerificationGoal("goal-a", "TEST"),
            regression.RegressionVerificationGoal("goal-b", "STATIC_SCAN"),
        ),
        materialization=materialization,
    )


def test_regression_evidence_is_content_addressed_and_aggregate_is_derived(tmp_path, monkeypatch):
    request = _regression_request()
    monkeypatch.setattr(regression, "validate_regression_evidence_request", lambda *args, **kwargs: None)
    payload = {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"runner": "external-ci", "environment": "linux-py311"},
        "observations": [
            {
                "verification_goal_id": "goal-b",
                "kind": "STATIC_SCAN",
                "status": "PASS",
                "command": ["scanner", "check"],
                "exit_code": 0,
                "duration_ms": 12,
                "stdout_sha256": "a" * 64,
                "stderr_sha256": "b" * 64,
                "statement": "Static scan completed successfully.",
            },
            {
                "verification_goal_id": "goal-a",
                "kind": "TEST",
                "status": "PASS",
                "command": ["pytest", "tests/test_app.py"],
                "exit_code": 0,
                "duration_ms": 25,
                "stdout_sha256": "c" * 64,
                "stderr_sha256": "d" * 64,
                "statement": "Regression test passed.",
            },
        ],
    }
    path = tmp_path / "regression.json"
    path.write_text(dumps(payload), encoding="utf-8")

    result = regression.load_regression_evidence_response(
        path,
        request,
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
    )

    assert result.aggregate_status == "PASS"
    assert result.identity_status == "DECLARED_UNATTESTED"
    assert [item.verification_goal_id for item in result.observations] == ["goal-a", "goal-b"]
    assert all(item.observation_id.startswith("regression-observation:") for item in result.observations)
    assert result.authority == "REGRESSION_EVIDENCE"
    assert result.gate_effect == "NONE"


def test_regression_response_rejects_missing_goal_and_shadow_policy_field(tmp_path, monkeypatch):
    request = _regression_request()
    monkeypatch.setattr(regression, "validate_regression_evidence_request", lambda *args, **kwargs: None)
    observation = {
        "verification_goal_id": "goal-a",
        "kind": "TEST",
        "status": "PASS",
        "command": [],
        "exit_code": None,
        "duration_ms": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "statement": "Passed by declared runner.",
    }
    payload = {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"runner": "external-ci"},
        "observations": [observation],
    }
    path = tmp_path / "invalid.json"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="cover each approved verification goal"):
        regression.load_regression_evidence_response(
            path,
            request,
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
        )

    payload["release_decision"] = "PASS"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported regression evidence response field"):
        regression.load_regression_evidence_response(
            path,
            request,
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
        )


def test_regression_validation_rejects_authority_upgrade(tmp_path, monkeypatch):
    request = _regression_request()
    monkeypatch.setattr(regression, "validate_regression_evidence_request", lambda *args, **kwargs: None)
    payload = {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"runner": "external-ci"},
        "observations": [
            {
                "verification_goal_id": goal.verification_goal_id,
                "kind": goal.kind,
                "status": "PASS",
                "command": [],
                "exit_code": None,
                "duration_ms": None,
                "stdout_sha256": None,
                "stderr_sha256": None,
                "statement": "Passed.",
            }
            for goal in request.verification_goals
        ],
    }
    path = tmp_path / "regression.json"
    path.write_text(dumps(payload), encoding="utf-8")
    result = regression.load_regression_evidence_response(
        path,
        request,
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
    )

    with pytest.raises(ValueError, match="gate-neutral"):
        regression.validate_regression_evidence(
            replace(result, authority="RELEASE_AUTHORITY"),
            request,
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
        )
