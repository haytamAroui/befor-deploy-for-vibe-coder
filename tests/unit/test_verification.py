from __future__ import annotations

from dataclasses import replace
from json import dumps
from types import SimpleNamespace

import pytest

import before_deploy.verification as verification
from before_deploy.regression_evidence import (
    PatchMaterializationAuthorization,
    PatchMaterializationFile,
    PatchMaterializationResult,
    RegressionEvidenceResult,
    RegressionObservation,
    patch_materialization_authorization_to_primitive,
    patch_materialization_to_primitive,
    regression_evidence_to_primitive,
)


def _inputs(statuses=("PASS",)):
    goals = tuple(
        SimpleNamespace(
            verification_goal_id=f"goal-{index}",
            kind="TEST",
            statement=f"Run regression check {index}",
        )
        for index, _ in enumerate(statuses, start=1)
    )
    observations = tuple(
        RegressionObservation(
            observation_id=f"regression-observation:{index}",
            verification_goal_id=goal.verification_goal_id,
            kind=goal.kind,
            status=status,
            command=("pytest",) if status != "NOT_RUN" else (),
            exit_code=0 if status == "PASS" else (1 if status == "FAIL" else None),
            duration_ms=10 if status != "NOT_RUN" else None,
            stdout_sha256=None,
            stderr_sha256=None,
            statement=None,
        )
        for index, (goal, status) in enumerate(zip(goals, statuses, strict=True), start=1)
    )
    patch_request = SimpleNamespace(proposal=SimpleNamespace(verification_goals=goals))
    patch = SimpleNamespace(
        proposal_sha256="1" * 64,
        approval_sha256="2" * 64,
        request_sha256="3" * 64,
        patch_sha256="4" * 64,
        selected_node_id="advisory-finding:test",
        review_status="UNREVIEWED",
    )
    authorization = SimpleNamespace(authorization_sha256="5" * 64)
    materialization = SimpleNamespace(
        materialization_sha256="6" * 64,
        review_status="UNREVIEWED",
    )
    regression_request = SimpleNamespace(materialization=materialization)
    aggregate = "PASS"
    if "ERROR" in statuses:
        aggregate = "ERROR"
    elif "FAIL" in statuses:
        aggregate = "FAIL"
    elif "NOT_RUN" in statuses:
        aggregate = "INCOMPLETE"
    regression = SimpleNamespace(
        materialization_sha256=materialization.materialization_sha256,
        request_sha256="7" * 64,
        regression_evidence_sha256="8" * 64,
        identity_status="DECLARED_UNATTESTED",
        aggregate_status=aggregate,
        observations=observations,
    )
    return regression, regression_request, patch, patch_request, authorization


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (("PASS",), "PASS"),
        (("FAIL",), "FAIL"),
        (("ERROR",), "ERROR"),
        (("NOT_RUN",), "INCOMPLETE"),
        (("PASS", "FAIL"), "FAIL"),
        (("FAIL", "ERROR"), "ERROR"),
        (("PASS", "NOT_RUN"), "INCOMPLETE"),
    ],
)
def test_build_verification_derives_status_without_release_authority(monkeypatch, statuses, expected):
    monkeypatch.setattr(verification, "validate_regression_evidence", lambda *args, **kwargs: None)
    regression, regression_request, patch, patch_request, authorization = _inputs(statuses)

    result = verification.build_verification(
        regression,
        regression_request,
        patch,
        patch_request,
        authorization,
        SimpleNamespace(),
        SimpleNamespace(),
    )

    assert result.overall_status == expected
    assert result.release_status == "NOT_EVALUATED"
    assert result.authority == "VERIFICATION_EVIDENCE"
    assert result.gate_effect == "NONE"
    assert result.evidence_identity_status == "DECLARED_UNATTESTED"
    assert result.patch_review_status == "UNREVIEWED"
    assert len(result.requirements) == len(statuses)
    assert len(result.checks) == len(statuses)


def test_verification_requires_pass_for_each_declared_goal(monkeypatch):
    monkeypatch.setattr(verification, "validate_regression_evidence", lambda *args, **kwargs: None)
    regression, regression_request, patch, patch_request, authorization = _inputs(("PASS", "NOT_RUN"))

    result = verification.build_verification(
        regression,
        regression_request,
        patch,
        patch_request,
        authorization,
        SimpleNamespace(),
        SimpleNamespace(),
    )

    assert [item.required_observation_status for item in result.requirements] == ["PASS", "PASS"]
    assert [item.status for item in result.checks] == ["SATISFIED", "INCOMPLETE"]
    assert result.overall_status == "INCOMPLETE"


def test_verification_rejects_authority_upgrade_and_release_claim(monkeypatch):
    monkeypatch.setattr(verification, "validate_regression_evidence", lambda *args, **kwargs: None)
    regression, regression_request, patch, patch_request, authorization = _inputs()
    result = verification.build_verification(
        regression,
        regression_request,
        patch,
        patch_request,
        authorization,
        SimpleNamespace(),
        SimpleNamespace(),
    )

    with pytest.raises(ValueError, match="gate-neutral"):
        verification.validate_verification(
            replace(result, authority="RELEASE_AUTHORITY", gate_effect="BLOCK"),
            regression,
            regression_request,
            patch,
            patch_request,
            authorization,
            SimpleNamespace(),
            SimpleNamespace(),
        )

    with pytest.raises(ValueError, match="release disposition"):
        verification.validate_verification(
            replace(result, release_status="READY"),
            regression,
            regression_request,
            patch,
            patch_request,
            authorization,
            SimpleNamespace(),
            SimpleNamespace(),
        )


def test_verification_digest_changes_with_observation_status(monkeypatch):
    monkeypatch.setattr(verification, "validate_regression_evidence", lambda *args, **kwargs: None)
    pass_inputs = _inputs(("PASS",))
    fail_inputs = _inputs(("FAIL",))

    passed = verification.build_verification(
        *pass_inputs,
        SimpleNamespace(),
        SimpleNamespace(),
    )
    failed = verification.build_verification(
        *fail_inputs,
        SimpleNamespace(),
        SimpleNamespace(),
    )

    assert passed.verification_sha256 != failed.verification_sha256


def test_authorization_loader_rejects_noncanonical_authority_contract(tmp_path, monkeypatch):
    monkeypatch.setattr(
        verification,
        "validate_patch_materialization_authorization",
        lambda *args, **kwargs: None,
    )
    artifact = PatchMaterializationAuthorization(
        schema_version=1,
        patch_request_sha256="1" * 64,
        patch_sha256="2" * 64,
        authorization_sha256="3" * 64,
        selected_node_id="node:test",
        operator="human@example.test",
        identity_status="DECLARED_UNATTESTED",
        scope="APPLY_EXACT_PATCH_FOR_REGRESSION_ONLY",
    )
    payload = patch_materialization_authorization_to_primitive(artifact)
    payload["authority_contract"]["release_authority"] = "forged"
    path = tmp_path / "authorization.json"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="not canonical"):
        verification.load_patch_materialization_authorization_artifact(
            path,
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
        )


def test_materialization_loader_round_trips_canonical_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(verification, "validate_patch_materialization", lambda *args, **kwargs: None)
    artifact = PatchMaterializationResult(
        schema_version=1,
        patch_request_sha256="1" * 64,
        patch_sha256="2" * 64,
        authorization_sha256="3" * 64,
        materialization_sha256="4" * 64,
        selected_node_id="node:test",
        application_status="APPLIED_HASH_VERIFIED",
        review_status="UNREVIEWED",
        files=(
            PatchMaterializationFile(
                patch_file_id="patch-file:test",
                target_path="app.py",
                before_content_sha256="5" * 64,
                after_content_sha256="6" * 64,
            ),
        ),
    )
    path = tmp_path / "materialization.json"
    path.write_text(dumps(patch_materialization_to_primitive(artifact)), encoding="utf-8")

    loaded = verification.load_patch_materialization_artifact(
        path,
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
    )
    assert loaded == artifact


def test_regression_loader_rejects_shadow_field(tmp_path, monkeypatch):
    monkeypatch.setattr(verification, "validate_regression_evidence", lambda *args, **kwargs: None)
    artifact = RegressionEvidenceResult(
        schema_version=1,
        patch_request_sha256="1" * 64,
        patch_sha256="2" * 64,
        authorization_sha256="3" * 64,
        materialization_sha256="4" * 64,
        request_sha256="5" * 64,
        regression_evidence_sha256="6" * 64,
        selected_node_id="node:test",
        source_runner="ci",
        source_environment="linux",
        identity_status="DECLARED_UNATTESTED",
        source_format="before-deploy-regression-evidence-v1",
        raw_input_sha256="7" * 64,
        raw_input_size_bytes=10,
        normalized_output_sha256="8" * 64,
        aggregate_status="PASS",
        observations=(
            RegressionObservation(
                observation_id="regression-observation:test",
                verification_goal_id="goal-1",
                kind="TEST",
                status="PASS",
                command=("pytest",),
                exit_code=0,
                duration_ms=10,
                stdout_sha256=None,
                stderr_sha256=None,
                statement=None,
            ),
        ),
    )
    payload = regression_evidence_to_primitive(artifact)
    payload["release_decision"] = "READY"
    path = tmp_path / "regression.json"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported regression evidence field"):
        verification.load_regression_evidence_artifact(
            path,
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
        )


def test_verification_rendering_keeps_release_unassessed(monkeypatch):
    monkeypatch.setattr(verification, "validate_regression_evidence", lambda *args, **kwargs: None)
    regression, regression_request, patch, patch_request, authorization = _inputs()
    result = verification.build_verification(
        regression,
        regression_request,
        patch,
        patch_request,
        authorization,
        SimpleNamespace(),
        SimpleNamespace(),
    )

    rendered = verification.render_verification_json(result)
    assert '"release_status": "NOT_EVALUATED"' in rendered
    assert '"gate_effect": "NONE"' in rendered
    assert '"evidence_identity_status": "DECLARED_UNATTESTED"' in rendered
