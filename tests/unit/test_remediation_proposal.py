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
    render_remediation_proposal_json,
    render_remediation_proposal_request_json,
    validate_remediation_proposal,
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


def _advisory() -> AdvisoryFinding:
    return AdvisoryFinding(
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


def _source() -> AdvisoryImport:
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
        findings=(_advisory(),),
        raw_artifact=raw,
        execution=execution,
    )


def _review_path(tmp_path):
    review = build_unified_review(_scan(), (_source(),))
    path = tmp_path / "review.json"
    path.write_text(render_review_json(review), encoding="utf-8")
    return path


def _lineage(tmp_path):
    artifact = load_review_evidence(_review_path(tmp_path))
    inspection = build_evidence_inspection(artifact, "ADV-1")
    investigation_request = build_evidence_investigation_request(inspection)
    explanation_request = build_evidence_explanation_request(
        inspection,
        investigation_request,
        None,
    )
    explanation_payload = {
        "schema_version": 1,
        "request_sha256": explanation_request.request_sha256,
        "source": {"provider": "external-explainer", "model": "declared-model"},
        "summary": {
            "text": "The selected advisory overlaps deterministic evidence at the recorded location.",
            "evidence_node_ids": [inspection.selected_node_id],
            "investigation_item_ids": [],
        },
        "details": [
            {
                "text": "The deterministic policy relationship remains separate from advisory authority.",
                "evidence_node_ids": [inspection.selected_node_id],
                "investigation_item_ids": [],
            }
        ],
        "limitations": [
            {
                "text": "Location overlap alone does not establish semantic equivalence.",
                "evidence_node_ids": [inspection.selected_node_id],
                "investigation_item_ids": [],
            }
        ],
    }
    explanation_path = tmp_path / "explanation-response.json"
    explanation_path.write_text(dumps(explanation_payload), encoding="utf-8")
    explanation = load_evidence_explanation_response(
        explanation_path,
        explanation_request,
        investigation_request,
    )
    request = build_remediation_proposal_request(
        explanation_request,
        explanation,
        investigation_request,
    )
    return investigation_request, explanation_request, explanation_path, explanation, request


def _proposal_payload(request, *, target_path: str = "app.py"):
    citation = request.allowed_explanation_statement_ids[0]
    return {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"provider": "external-proposer", "model": "declared-model"},
        "objective": {
            "text": "Reduce the risk described by the validated explanation without changing release authority.",
            "explanation_statement_ids": [citation],
        },
        "changes": [
            {
                "target_path": target_path,
                "intent": "Adjust the affected implementation so the unsafe condition is no longer reachable.",
                "rationale": "The proposal follows the cited explanation and remains non-executable.",
                "explanation_statement_ids": [citation],
            }
        ],
        "verification_goals": [
            {
                "kind": "TEST",
                "statement": "Add or update regression coverage for the described unsafe condition.",
                "explanation_statement_ids": [citation],
            }
        ],
        "risks": [
            {
                "statement": "Behavioral changes may require compatibility review.",
                "explanation_statement_ids": [citation],
            }
        ],
    }


def test_request_is_stable_bounded_and_non_executable(tmp_path):
    investigation_request, explanation_request, _, explanation, first = _lineage(tmp_path)
    second = build_remediation_proposal_request(
        explanation_request,
        explanation,
        investigation_request,
    )

    rendered = render_remediation_proposal_request_json(first)
    assert first.request_sha256 == second.request_sha256
    assert first.authority == "REMEDIATION_CONTEXT"
    assert first.gate_effect == "NONE"
    assert first.explanation_sha256 == explanation.explanation_sha256
    assert first.allowed_explanation_statement_ids
    assert "/private/repository/must-not-leak" not in rendered
    assert '"patch_generation": "forbidden"' in rendered
    assert '"self_approval": "forbidden"' in rendered


def test_valid_proposal_is_content_addressed_advisory_and_not_approved(tmp_path):
    investigation_request, _, _, _, request = _lineage(tmp_path)
    path = tmp_path / "proposal-response.json"
    path.write_text(dumps(_proposal_payload(request)), encoding="utf-8")

    result = load_remediation_proposal_response(path, request, investigation_request)
    rendered = render_remediation_proposal_json(result)

    assert result.authority == "REMEDIATION_PROPOSAL_ADVISORY"
    assert result.gate_effect == "NONE"
    assert result.execution_status == "NON_EXECUTABLE"
    assert result.approval_status == "NOT_APPROVED"
    assert result.identity_status == "DECLARED_UNATTESTED"
    assert result.objective.objective_id.startswith("remediation-objective:")
    assert result.changes[0].change_id.startswith("remediation-change:")
    assert result.verification_goals[0].verification_goal_id.startswith("remediation-verification:")
    assert result.risks[0].risk_id.startswith("remediation-risk:")
    assert '"human_approval_required_before_patch": true' in rendered
    assert '"BLOCK"' not in rendered


def test_response_rejects_patch_approval_and_shadow_policy_fields(tmp_path):
    investigation_request, _, _, _, request = _lineage(tmp_path)
    path = tmp_path / "invalid.json"

    payload = _proposal_payload(request)
    payload["approved"] = True
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported remediation proposal response field"):
        load_remediation_proposal_response(path, request, investigation_request)

    payload = _proposal_payload(request)
    payload["changes"][0]["patch"] = "@@"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported remediation change field"):
        load_remediation_proposal_response(path, request, investigation_request)

    payload = _proposal_payload(request)
    payload["release_decision"] = "PASS"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported remediation proposal response field"):
        load_remediation_proposal_response(path, request, investigation_request)


def test_response_rejects_noncanonical_or_escaping_target_paths(tmp_path):
    investigation_request, _, _, _, request = _lineage(tmp_path)
    path = tmp_path / "path.json"

    for target in ("../app.py", "/tmp/app.py", "src\\app.py", "src//app.py"):
        path.write_text(dumps(_proposal_payload(request, target_path=target)), encoding="utf-8")
        with pytest.raises(ValueError, match="target path"):
            load_remediation_proposal_response(path, request, investigation_request)


def test_response_rejects_out_of_context_citations(tmp_path):
    investigation_request, _, _, _, request = _lineage(tmp_path)
    payload = _proposal_payload(request)
    payload["objective"]["explanation_statement_ids"] = ["explanation-summary:not-in-context"]
    path = tmp_path / "citation.json"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="escapes bounded context"):
        load_remediation_proposal_response(path, request, investigation_request)


def test_validation_rejects_authority_or_approval_upgrade(tmp_path):
    investigation_request, _, _, _, request = _lineage(tmp_path)
    path = tmp_path / "proposal.json"
    path.write_text(dumps(_proposal_payload(request)), encoding="utf-8")
    result = load_remediation_proposal_response(path, request, investigation_request)

    with pytest.raises(ValueError, match="advisory and gate-neutral"):
        validate_remediation_proposal(
            replace(result, authority="RELEASE_AUTHORITY"),
            request,
            investigation_request,
        )
    with pytest.raises(ValueError, match="cannot self-assert approval"):
        validate_remediation_proposal(
            replace(result, approval_status="APPROVED"),
            request,
            investigation_request,
        )


def test_raw_formatting_changes_raw_digest_but_not_normalized_output(tmp_path):
    investigation_request, _, _, _, request = _lineage(tmp_path)
    payload = _proposal_payload(request)
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first_path.write_text(dumps(payload, separators=(",", ":")), encoding="utf-8")
    second_path.write_text(dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    first = load_remediation_proposal_response(first_path, request, investigation_request)
    second = load_remediation_proposal_response(second_path, request, investigation_request)

    assert first.raw_input_sha256 != second.raw_input_sha256
    assert first.normalized_output_sha256 == second.normalized_output_sha256
    assert first.objective == second.objective
    assert first.changes == second.changes


def test_installed_propose_writes_request_and_result_without_gate_artifacts(tmp_path, capsys):
    _, _, explanation_path, _, request = _lineage(tmp_path)
    proposal_path = tmp_path / "proposal-response.json"
    proposal_path.write_text(dumps(_proposal_payload(request)), encoding="utf-8")
    output_dir = tmp_path / "propose-output"

    exit_code = main(
        [
            "propose",
            str(_review_path(tmp_path)),
            "ADV-1",
            "--explanation-response-file",
            str(explanation_path),
            "--response-file",
            str(proposal_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert '"execution_status": "NON_EXECUTABLE"' in captured.out
    assert '"approval_status": "NOT_APPROVED"' in captured.out
    assert (output_dir / "remediation-proposal-request.json").is_file()
    assert (output_dir / "remediation-proposal-request.md").is_file()
    assert (output_dir / "remediation-proposal.json").is_file()
    assert (output_dir / "remediation-proposal.md").is_file()
    assert not (output_dir / "report.json").exists()
    assert not (output_dir / "review.json").exists()
