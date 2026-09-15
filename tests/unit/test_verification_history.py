from __future__ import annotations

from dataclasses import replace
from json import dumps, loads

import pytest

import before_deploy.verification_history as history
from before_deploy.verification import VerificationCheck, VerificationRequirement, VerificationResult


def _verification(*, status: str = "PASS", node: str = "advisory-finding:test", patch: str = "2" * 64):
    observed = {
        "PASS": "PASS",
        "FAIL": "FAIL",
        "ERROR": "ERROR",
        "INCOMPLETE": "NOT_RUN",
    }[status]
    check_status = {
        "PASS": "SATISFIED",
        "FAIL": "FAILED",
        "ERROR": "ERROR",
        "INCOMPLETE": "INCOMPLETE",
    }[status]
    requirement_semantic = {
        "verification_goal_id": "remediation-verification:test",
        "kind": "TEST",
        "statement": "Run the focused regression test",
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
        patch_request_sha256="c" * 64,
        patch_sha256=patch,
        materialization_authorization_sha256="d" * 64,
        materialization_sha256="e" * 64,
        regression_request_sha256="f" * 64,
        regression_evidence_sha256=(status[0].lower() if status != "INCOMPLETE" else "9") * 64,
        verification_sha256="",
        selected_node_id=node,
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


def test_history_root_entry_is_content_addressed_and_gate_neutral():
    verification = _verification()
    result = history.append_verification_history(verification)

    assert result.entry_count == 1
    assert result.current_verification_sha256 == verification.verification_sha256
    assert result.current_status == "PASS"
    assert result.entries[0].sequence == 1
    assert result.entries[0].supersedes_verification_sha256 is None
    assert result.authority == "VERIFICATION_HISTORY"
    assert result.gate_effect == "NONE"
    assert result.release_status == "NOT_EVALUATED"
    history.validate_verification_history(result)


def test_later_fail_explicitly_supersedes_earlier_pass_without_status_ranking():
    first = history.append_verification_history(_verification(status="PASS"))
    later = _verification(status="FAIL", patch="3" * 64)
    result = history.append_verification_history(later, first)

    assert result.current_status == "FAIL"
    assert result.current_verification_sha256 == later.verification_sha256
    assert result.entries[1].supersedes_verification_sha256 == first.current_verification_sha256
    assert result.entries[:-1] == first.entries
    assert result.entries[0].overall_status == "PASS"


def test_history_rejects_duplicate_verification_sha():
    verification = _verification()
    existing = history.append_verification_history(verification)

    with pytest.raises(ValueError, match="duplicate verification"):
        history.append_verification_history(verification, existing)


def test_history_rejects_cross_node_append():
    existing = history.append_verification_history(_verification())

    with pytest.raises(ValueError, match="different selected node"):
        history.append_verification_history(_verification(node="advisory-finding:other"), existing)


def test_history_rejects_broken_supersession_chain():
    first = history.append_verification_history(_verification())
    result = history.append_verification_history(_verification(status="FAIL", patch="3" * 64), first)
    broken_entry = replace(result.entries[1], supersedes_verification_sha256="0" * 64)
    broken = replace(result, entries=(result.entries[0], broken_entry))

    with pytest.raises(ValueError, match="supersession chain"):
        history.validate_verification_history(broken)


def test_verification_artifact_round_trip_and_shadow_field_rejection(tmp_path):
    verification = _verification()
    payload = history.verification_to_primitive(verification)
    artifact = tmp_path / "verification.json"
    artifact.write_text(dumps(payload), encoding="utf-8")

    assert history.load_verification_artifact(artifact) == verification

    payload["release_decision"] = "READY"
    artifact.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported verification field"):
        history.load_verification_artifact(artifact)


def test_history_artifact_round_trip_is_canonical(tmp_path):
    first = history.append_verification_history(_verification())
    result = history.append_verification_history(_verification(status="ERROR", patch="4" * 64), first)
    artifact = tmp_path / "verification-history.json"
    artifact.write_text(history.render_verification_history_json(result), encoding="utf-8")

    assert history.load_verification_history(artifact) == result

    payload = loads(artifact.read_text(encoding="utf-8"))
    payload["authority_contract"]["release_authority"] = "history"
    artifact.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="not canonical"):
        history.load_verification_history(artifact)


def test_history_cannot_claim_release_disposition():
    result = history.append_verification_history(_verification())
    forged = replace(result, release_status="READY")

    with pytest.raises(ValueError, match="cannot claim release"):
        history.validate_verification_history(forged)
