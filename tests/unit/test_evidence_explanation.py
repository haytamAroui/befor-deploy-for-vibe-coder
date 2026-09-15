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
    render_evidence_explanation_json,
    render_evidence_explanation_request_json,
    validate_evidence_explanation,
)
from before_deploy.evidence_inspect import build_evidence_inspection
from before_deploy.evidence_investigation import (
    build_evidence_investigation_request,
    load_evidence_investigation_response,
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
    review = build_unified_review(_scan(), (_source(),))
    path = tmp_path / "review.json"
    path.write_text(render_review_json(review), encoding="utf-8")
    return path


def _contexts(tmp_path, *, with_investigation: bool = True):
    artifact = load_review_evidence(_review_path(tmp_path))
    inspection = build_evidence_inspection(artifact, "ADV-1")
    investigation_request = build_evidence_investigation_request(inspection)
    investigation = None
    investigation_path = tmp_path / "investigation-response.json"
    if with_investigation:
        evidence_id = investigation_request.selected_node_id
        payload = {
            "schema_version": 1,
            "inspection_sha256": investigation_request.inspection_sha256,
            "request_sha256": investigation_request.request_sha256,
            "source": {"provider": "investigator", "model": "declared-model"},
            "hypotheses": [
                {
                    "statement": "The advisory may describe the same code path.",
                    "evidence_node_ids": [evidence_id],
                }
            ],
            "observations": [
                {
                    "statement": "The advisory and deterministic finding are colocated.",
                    "evidence_node_ids": [evidence_id],
                }
            ],
            "questions": [],
        }
        investigation_path.write_text(dumps(payload), encoding="utf-8")
        investigation = load_evidence_investigation_response(
            investigation_path, investigation_request
        )
    explanation_request = build_evidence_explanation_request(
        inspection, investigation_request, investigation
    )
    return (
        inspection,
        investigation_request,
        investigation,
        explanation_request,
        investigation_path,
    )


def _explanation_payload(request):
    evidence_id = request.selected_node_id
    investigation_id = (
        request.allowed_investigation_item_ids[0]
        if request.allowed_investigation_item_ids
        else None
    )
    return {
        "schema_version": 1,
        "request_sha256": request.request_sha256,
        "source": {"provider": "external-explainer", "model": "declared-explainer"},
        "summary": {
            "text": "The selected advisory claim overlaps a deterministic finding, but remains advisory.",
            "evidence_node_ids": [evidence_id],
            "investigation_item_ids": [],
        },
        "details": [
            {
                "text": "The bounded investigation records a possible relationship without changing policy authority.",
                "evidence_node_ids": [],
                "investigation_item_ids": [investigation_id] if investigation_id else [],
            }
        ],
        "limitations": [
            {
                "text": "Location overlap alone does not establish semantic equivalence.",
                "evidence_node_ids": [evidence_id],
                "investigation_item_ids": [],
            }
        ],
    }


def test_explanation_request_is_stable_cited_and_gate_neutral(tmp_path):
    _, investigation_request, investigation, first, _ = _contexts(tmp_path)
    second = build_evidence_explanation_request(
        first.inspection, investigation_request, investigation
    )

    rendered = render_evidence_explanation_request_json(first)
    assert first.request_sha256 == second.request_sha256
    assert first.authority == "EXPLANATION_CONTEXT"
    assert first.gate_effect == "NONE"
    assert first.investigation_sha256 == investigation.investigation_sha256
    assert first.allowed_investigation_item_ids
    assert "/private/repository/must-not-leak" not in rendered
    assert '"citations_required": true' in rendered
    assert '"new_evidence_creation": "forbidden"' in rendered


def test_explanation_request_can_operate_without_investigation(tmp_path):
    _, investigation_request, _, request, _ = _contexts(tmp_path, with_investigation=False)

    assert request.investigation_sha256 is None
    assert request.allowed_investigation_item_ids == ()
    assert request.investigation is None
    assert request.investigation_request_sha256 == investigation_request.request_sha256


def test_valid_explanation_is_content_addressed_cited_and_advisory_only(tmp_path):
    _, investigation_request, _, request, _ = _contexts(tmp_path)
    response = tmp_path / "explanation-response.json"
    response.write_text(dumps(_explanation_payload(request)), encoding="utf-8")

    result = load_evidence_explanation_response(response, request, investigation_request)
    rendered = render_evidence_explanation_json(result)

    assert result.source_provider == "external-explainer"
    assert result.identity_status == "DECLARED_UNATTESTED"
    assert result.authority == "EXPLANATION_ADVISORY"
    assert result.gate_effect == "NONE"
    assert result.summary.statement_id.startswith("explanation-summary:")
    assert result.details[0].statement_id.startswith("explanation-detail:")
    assert result.limitations[0].statement_id.startswith("explanation-limitation:")
    assert result.summary.evidence_node_ids == (request.selected_node_id,)
    assert result.details[0].investigation_item_ids
    assert '"policy_mutation": "forbidden"' in rendered
    assert '"confidence_or_severity_promotion": "forbidden"' in rendered


def test_explanation_rejects_uncited_or_out_of_context_statements(tmp_path):
    _, investigation_request, _, request, _ = _contexts(tmp_path)
    payload = _explanation_payload(request)
    payload["summary"]["evidence_node_ids"] = []
    path = tmp_path / "uncited.json"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="must cite at least one bounded source"):
        load_evidence_explanation_response(path, request, investigation_request)

    payload = _explanation_payload(request)
    payload["summary"]["evidence_node_ids"] = ["deterministic-finding:not-in-trace"]
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="escapes bounded request context"):
        load_evidence_explanation_response(path, request, investigation_request)


def test_explanation_rejects_shadow_policy_fields_and_binding_drift(tmp_path):
    _, investigation_request, _, request, _ = _contexts(tmp_path)
    payload = _explanation_payload(request)
    payload["summary"]["severity"] = "critical"
    path = tmp_path / "shadow.json"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported explanation summary field"):
        load_evidence_explanation_response(path, request, investigation_request)

    payload = _explanation_payload(request)
    payload["release_decision"] = "PASS"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported explanation response field"):
        load_evidence_explanation_response(path, request, investigation_request)

    payload = _explanation_payload(request)
    payload["request_sha256"] = "0" * 64
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="different request"):
        load_evidence_explanation_response(path, request, investigation_request)


def test_explanation_raw_format_changes_do_not_change_normalized_semantics(tmp_path):
    _, investigation_request, _, request, _ = _contexts(tmp_path)
    payload = _explanation_payload(request)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(dumps(payload, separators=(",", ":")), encoding="utf-8")
    second.write_text(dumps(payload, indent=4, sort_keys=True), encoding="utf-8")

    first_result = load_evidence_explanation_response(first, request, investigation_request)
    second_result = load_evidence_explanation_response(second, request, investigation_request)

    assert first_result.raw_input_sha256 != second_result.raw_input_sha256
    assert first_result.normalized_output_sha256 == second_result.normalized_output_sha256
    assert first_result.summary == second_result.summary


def test_validation_rejects_explanation_authority_upgrade(tmp_path):
    _, investigation_request, _, request, _ = _contexts(tmp_path)
    path = tmp_path / "response.json"
    path.write_text(dumps(_explanation_payload(request)), encoding="utf-8")
    result = load_evidence_explanation_response(path, request, investigation_request)

    with pytest.raises(ValueError, match="advisory and gate-neutral"):
        validate_evidence_explanation(
            replace(result, authority="RELEASE_AUTHORITY"),
            request,
            investigation_request,
        )


def test_explain_cli_writes_request_and_result_without_gate_artifacts(tmp_path, capsys):
    review_path = _review_path(tmp_path)
    _, investigation_request, _, request, investigation_path = _contexts(tmp_path)
    explanation_path = tmp_path / "explanation-response.json"
    explanation_path.write_text(dumps(_explanation_payload(request)), encoding="utf-8")
    output_dir = tmp_path / "explain-output"

    exit_code = main(
        [
            "explain",
            str(review_path),
            "ADV-1",
            "--investigation-response-file",
            str(investigation_path),
            "--response-file",
            str(explanation_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert '"authority": "EXPLANATION_ADVISORY"' in captured.out
    assert (output_dir / "explanation-request.json").is_file()
    assert (output_dir / "explanation-request.md").is_file()
    assert (output_dir / "explanation.json").is_file()
    assert (output_dir / "explanation.md").is_file()
    assert not (output_dir / "report.json").exists()
    assert not (output_dir / "review.json").exists()
