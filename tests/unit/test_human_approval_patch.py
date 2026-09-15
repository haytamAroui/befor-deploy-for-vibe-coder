from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from json import dumps

import pytest

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, build_unified_review
from before_deploy.advisory_execution import (
    AdvisoryExecutionProvenance,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
)
from before_deploy.entrypoint import main
from before_deploy.evidence_artifact import load_review_evidence
from before_deploy.evidence_explanation import (
    build_evidence_explanation_request,
    load_evidence_explanation_response,
)
from before_deploy.evidence_inspect import build_evidence_inspection
from before_deploy.evidence_investigation import build_evidence_investigation_request
from before_deploy.human_approval_patch import (
    build_human_approval,
    build_patch_request,
    load_human_approval_artifact,
    load_patch_response,
    render_human_approval_json,
    render_patch_json,
    render_patch_request_json,
    validate_human_approval,
    validate_patch_result,
)
from before_deploy.models import (
    Confidence,
    Finding,
    GateOutcome,
    Location,
    PolicyDecision,
    ScanManifest,
    ScanResult,
    Severity,
)
from before_deploy.remediation_proposal import (
    build_remediation_proposal_request,
    load_remediation_proposal_response,
)
from before_deploy.reports.review_report import render_review_json

NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _scan() -> ScanResult:
    finding = Finding(
        rule_id="SEC-TEST-001",
        rule_version="1.0.0",
        title="Deterministic issue",
        message="Deterministic evidence.",
        remediation="Fix it.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint="deterministic-fingerprint",
        location=Location(path="app.py", start_line=5, end_line=5),
    )
    return ScanResult(
        manifest=ScanManifest(
            scan_id="scan-1",
            repository_path="/private/repository/must-not-leak",
            repository_digest="repo-digest",
            policy_digest="policy-digest",
            policy_name="strict",
            started_at=NOW,
            completed_at=NOW,
        ),
        executions=(),
        findings=(finding,),
        waivers=(),
        decision=PolicyDecision(
            outcome=GateOutcome.BLOCK,
            reason_codes=("BLOCKING_FINDINGS",),
            blocking_fingerprints=(finding.fingerprint,),
        ),
    )


def _source() -> AdvisoryImport:
    finding = AdvisoryFinding(
        finding_id="ADV-1",
        source="reviewer",
        title="Possible issue",
        message="Advisory claim.",
        category="security",
        severity="high",
        confidence="0.8",
        fingerprint="same-advisory-fingerprint",
        location=Location(path="app.py", start_line=5, end_line=5),
    )
    raw = AdvisoryRawArtifact(
        sha256="a" * 64,
        size_bytes=100,
        media_type="application/json",
        schema="review-json-v1",
    )
    execution = AdvisoryExecutionProvenance(
        schema_version=1,
        provider_id="provider-a",
        implementation="provider-a-adapter",
        implementation_version="1",
        model=AdvisoryModelIdentity(status="ATTESTED", provider="provider-a", model="model-a"),
        configuration=(),
        configuration_sha256="c" * 64,
        budgets=(),
        context_sha256="e" * 64,
        context_selected_files=1,
        context_selected_bytes=20,
        started_at=NOW,
        completed_at=NOW,
        duration_ms=5,
        raw_output=raw,
        normalized_output_sha256="9" * 64,
        result_status="COMPLETED",
    )
    return AdvisoryImport(
        input_name="provider.json",
        source="reviewer",
        source_format="review-json-v1",
        findings=(finding,),
        raw_artifact=raw,
        execution=execution,
    )


def _review_path(tmp_path):
    path = tmp_path / "review.json"
    path.write_text(render_review_json(build_unified_review(_scan(), (_source(),))), encoding="utf-8")
    return path


def _explanation_payload(request):
    return {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"provider": "external-explainer", "model": "declared-model"},
        "summary": {
            "text": "The selected advisory overlaps deterministic evidence at the recorded location.",
            "evidence_node_ids": [request.selected_node_id],
            "investigation_item_ids": [],
        },
        "details": [
            {
                "text": "The policy relationship remains separate from advisory authority.",
                "evidence_node_ids": [request.selected_node_id],
                "investigation_item_ids": [],
            }
        ],
        "limitations": [
            {
                "text": "Location overlap alone does not establish semantic equivalence.",
                "evidence_node_ids": [request.selected_node_id],
                "investigation_item_ids": [],
            }
        ],
    }


def _proposal_payload(request):
    citation = request.allowed_explanation_statement_ids[0]
    return {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"provider": "external-proposer", "model": "declared-model"},
        "objective": {
            "text": "Reduce the bounded risk described by the explanation.",
            "explanation_statement_ids": [citation],
        },
        "changes": [
            {
                "target_path": "app.py",
                "intent": "Adjust the affected implementation so the unsafe condition is not reachable.",
                "rationale": "The change follows the approved remediation objective.",
                "explanation_statement_ids": [citation],
            }
        ],
        "verification_goals": [
            {
                "kind": "TEST",
                "statement": "Run regression coverage for the described condition.",
                "explanation_statement_ids": [citation],
            }
        ],
        "risks": [],
    }


def _lineage(tmp_path):
    review_path = _review_path(tmp_path)
    artifact = load_review_evidence(review_path)
    inspection = build_evidence_inspection(artifact, "ADV-1")
    investigation_request = build_evidence_investigation_request(inspection)
    explanation_request = build_evidence_explanation_request(
        inspection,
        investigation_request,
        None,
    )
    explanation_path = tmp_path / "explanation-response.json"
    explanation_path.write_text(dumps(_explanation_payload(explanation_request)), encoding="utf-8")
    explanation = load_evidence_explanation_response(
        explanation_path,
        explanation_request,
        investigation_request,
    )
    proposal_request = build_remediation_proposal_request(
        explanation_request,
        explanation,
        investigation_request,
    )
    proposal_path = tmp_path / "proposal-response.json"
    proposal_path.write_text(dumps(_proposal_payload(proposal_request)), encoding="utf-8")
    proposal = load_remediation_proposal_response(
        proposal_path,
        proposal_request,
        investigation_request,
    )
    return (
        review_path,
        investigation_request,
        explanation_path,
        proposal_request,
        proposal_path,
        proposal,
    )


def _approval(proposal, proposal_request, investigation_request, *, decision="APPROVE"):
    return build_human_approval(
        proposal,
        proposal_request,
        investigation_request,
        decision=decision,
        approver="human@example.test",
        confirmed_proposal_sha256=proposal.proposal_sha256,
        rationale="I reviewed the bounded proposal and authorize patch generation only.",
    )


def _patch_payload(request, *, target_path="app.py"):
    diff = (
        f"diff --git a/{target_path} b/{target_path}\n"
        f"--- a/{target_path}\n"
        f"+++ b/{target_path}\n"
        "@@ -1 +1 @@\n"
        "-unsafe_call()\n"
        "+safe_call()\n"
    )
    return {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"provider": "external-patcher", "model": "declared-model"},
        "files": [
            {
                "target_path": target_path,
                "base_content_sha256": "b" * 64,
                "patched_content_sha256": "c" * 64,
                "unified_diff": diff,
            }
        ],
    }


def test_approval_requires_exact_confirmed_proposal_digest(tmp_path):
    _, investigation_request, _, proposal_request, _, proposal = _lineage(tmp_path)

    approval = _approval(proposal, proposal_request, investigation_request)
    rendered = render_human_approval_json(approval)
    assert approval.decision == "APPROVE"
    assert approval.proposal_sha256 == proposal.proposal_sha256
    assert approval.authority == "HUMAN_APPROVAL_WORKFLOW"
    assert approval.gate_effect == "NONE"
    assert approval.identity_status == "DECLARED_UNATTESTED"
    assert '"patch_application": "not_authorized_by_this_artifact"' in rendered
    assert '"release_authority": "persisted_policy_decision_only"' in rendered

    with pytest.raises(ValueError, match="Confirmed proposal SHA-256"):
        build_human_approval(
            proposal,
            proposal_request,
            investigation_request,
            decision="APPROVE",
            approver="human@example.test",
            confirmed_proposal_sha256="0" * 64,
        )


def test_rejection_is_recorded_but_cannot_unlock_patch_generation(tmp_path):
    _, investigation_request, _, proposal_request, _, proposal = _lineage(tmp_path)
    rejection = _approval(
        proposal,
        proposal_request,
        investigation_request,
        decision="REJECT",
    )
    assert rejection.decision == "REJECT"
    with pytest.raises(ValueError, match="requires an APPROVE"):
        build_patch_request(
            proposal,
            proposal_request,
            rejection,
            investigation_request,
        )


def test_approval_validation_rejects_release_authority_upgrade(tmp_path):
    _, investigation_request, _, proposal_request, _, proposal = _lineage(tmp_path)
    approval = _approval(proposal, proposal_request, investigation_request)
    with pytest.raises(ValueError, match="workflow-only and gate-neutral"):
        validate_human_approval(
            replace(approval, authority="RELEASE_AUTHORITY"),
            proposal,
            proposal_request,
            investigation_request,
        )


def test_patch_request_is_bound_to_approval_and_exact_proposal_targets(tmp_path):
    _, investigation_request, _, proposal_request, _, proposal = _lineage(tmp_path)
    approval = _approval(proposal, proposal_request, investigation_request)
    request = build_patch_request(
        proposal,
        proposal_request,
        approval,
        investigation_request,
    )
    rendered = render_patch_request_json(request)
    assert request.proposal_sha256 == proposal.proposal_sha256
    assert request.approval_sha256 == approval.approval_sha256
    assert request.allowed_target_paths == ("app.py",)
    assert request.verification_goal_ids == (proposal.verification_goals[0].verification_goal_id,)
    assert request.authority == "PATCH_CONTEXT"
    assert request.gate_effect == "NONE"
    assert '"patch_application": "forbidden"' in rendered
    assert '"patch_review": "not_implied"' in rendered


def test_valid_patch_is_content_addressed_not_applied_and_unreviewed(tmp_path):
    _, investigation_request, _, proposal_request, _, proposal = _lineage(tmp_path)
    approval = _approval(proposal, proposal_request, investigation_request)
    request = build_patch_request(proposal, proposal_request, approval, investigation_request)
    path = tmp_path / "patch-response.json"
    path.write_text(dumps(_patch_payload(request)), encoding="utf-8")

    result = load_patch_response(path, request, proposal_request, investigation_request)
    rendered = render_patch_json(result)
    assert result.authority == "PATCH_ARTIFACT"
    assert result.gate_effect == "NONE"
    assert result.application_status == "NOT_APPLIED"
    assert result.review_status == "UNREVIEWED"
    assert result.files[0].patch_file_id.startswith("patch-file:")
    assert result.files[0].diff_sha256
    assert '"patch_application": "not_performed"' in rendered
    assert '"release_authority": "persisted_policy_decision_only"' in rendered


def test_patch_rejects_scope_widening_shadow_policy_and_invalid_headers(tmp_path):
    _, investigation_request, _, proposal_request, _, proposal = _lineage(tmp_path)
    approval = _approval(proposal, proposal_request, investigation_request)
    request = build_patch_request(proposal, proposal_request, approval, investigation_request)
    path = tmp_path / "invalid-patch.json"

    payload = _patch_payload(request, target_path="other.py")
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="escapes approved proposal scope"):
        load_patch_response(path, request, proposal_request, investigation_request)

    payload = _patch_payload(request)
    payload["release_decision"] = "PASS"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported patch response field"):
        load_patch_response(path, request, proposal_request, investigation_request)

    payload = _patch_payload(request)
    payload["files"][0]["unified_diff"] = (
        "--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-old\n+new\n"
    )
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="headers do not match"):
        load_patch_response(path, request, proposal_request, investigation_request)


def test_patch_validation_rejects_application_or_review_claims(tmp_path):
    _, investigation_request, _, proposal_request, _, proposal = _lineage(tmp_path)
    approval = _approval(proposal, proposal_request, investigation_request)
    request = build_patch_request(proposal, proposal_request, approval, investigation_request)
    path = tmp_path / "patch.json"
    path.write_text(dumps(_patch_payload(request)), encoding="utf-8")
    result = load_patch_response(path, request, proposal_request, investigation_request)

    with pytest.raises(ValueError, match="cannot claim application"):
        validate_patch_result(
            replace(result, application_status="APPLIED"),
            request,
            proposal_request,
            investigation_request,
        )
    with pytest.raises(ValueError, match="cannot claim human review"):
        validate_patch_result(
            replace(result, review_status="APPROVED"),
            request,
            proposal_request,
            investigation_request,
        )


def test_cli_approve_then_fix_writes_only_workflow_artifacts(tmp_path, capsys):
    review_path, investigation_request, explanation_path, proposal_request, proposal_path, proposal = _lineage(tmp_path)
    approve_dir = tmp_path / "approve-output"

    approve_exit = main(
        [
            "approve",
            str(review_path),
            "ADV-1",
            "--explanation-response-file",
            str(explanation_path),
            "--proposal-response-file",
            str(proposal_path),
            "--decision",
            "APPROVE",
            "--approver",
            "human@example.test",
            "--confirm-proposal-sha256",
            proposal.proposal_sha256,
            "--output-dir",
            str(approve_dir),
            "--format",
            "json",
        ]
    )
    first = capsys.readouterr()
    assert approve_exit == 0
    assert first.err == ""
    assert '"decision": "APPROVE"' in first.out
    approval_path = approve_dir / "human-approval.json"
    assert approval_path.is_file()
    assert (approve_dir / "human-approval.md").is_file()

    approval = load_human_approval_artifact(
        approval_path,
        proposal,
        proposal_request,
        investigation_request,
    )
    patch_request = build_patch_request(
        proposal,
        proposal_request,
        approval,
        investigation_request,
    )
    patch_response = tmp_path / "patch-response.json"
    patch_response.write_text(dumps(_patch_payload(patch_request)), encoding="utf-8")
    fix_dir = tmp_path / "fix-output"

    fix_exit = main(
        [
            "fix",
            str(review_path),
            "ADV-1",
            "--explanation-response-file",
            str(explanation_path),
            "--proposal-response-file",
            str(proposal_path),
            "--approval-file",
            str(approval_path),
            "--patch-response-file",
            str(patch_response),
            "--output-dir",
            str(fix_dir),
            "--format",
            "json",
        ]
    )
    second = capsys.readouterr()
    assert fix_exit == 0
    assert second.err == ""
    assert '"application_status": "NOT_APPLIED"' in second.out
    assert '"review_status": "UNREVIEWED"' in second.out
    assert (fix_dir / "patch-request.json").is_file()
    assert (fix_dir / "patch-request.md").is_file()
    assert (fix_dir / "patch.json").is_file()
    assert (fix_dir / "patch.md").is_file()
    assert not (fix_dir / "report.json").exists()
    assert not (fix_dir / "review.json").exists()
