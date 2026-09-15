from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from json import dumps, loads

import pytest

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, build_unified_review
from before_deploy.advisory_execution import (
    AdvisoryExecutionProvenance,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
)
from before_deploy.entrypoint import main
from before_deploy.evidence_artifact import load_review_evidence
from before_deploy.evidence_inspect import build_evidence_inspection
from before_deploy.evidence_investigation import (
    build_evidence_investigation_request,
    load_evidence_investigation_response,
    render_evidence_investigation_json,
    render_evidence_investigation_request_json,
    validate_evidence_investigation,
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


def _request(tmp_path):
    artifact = load_review_evidence(_review_path(tmp_path))
    inspection = build_evidence_inspection(artifact, "ADV-1")
    return build_evidence_investigation_request(inspection)


def _response_payload(request, *, evidence_node_id: str | None = None):
    evidence_id = evidence_node_id or request.selected_node_id
    return {
        "schema_version": 1,
        "inspection_sha256": request.inspection_sha256,
        "request_sha256": request.request_sha256,
        "source": {"provider": "external-investigator", "model": "declared-model"},
        "hypotheses": [
            {
                "statement": "The advisory claim may describe the same code path as the deterministic issue.",
                "rationale": "Both references are present in the bounded inspection trace.",
                "evidence_node_ids": [evidence_id],
            }
        ],
        "observations": [
            {
                "statement": "A deterministic finding is colocated with the selected advisory claim.",
                "evidence_node_ids": [evidence_id],
            }
        ],
        "questions": [
            {
                "question": "Does the runtime path make the advisory condition reachable?",
                "evidence_node_ids": [evidence_id],
            }
        ],
    }


def test_investigation_request_is_stable_bounded_and_gate_neutral(tmp_path):
    first = _request(tmp_path)
    artifact = load_review_evidence(_review_path(tmp_path))
    inspection = build_evidence_inspection(artifact, "ADV-1")
    second = build_evidence_investigation_request(inspection)

    rendered = render_evidence_investigation_request_json(first)
    assert first.request_sha256 == second.request_sha256
    assert first.allowed_evidence_node_ids == tuple(
        sorted(record.node.node_id for record in first.inspection.nodes)
    )
    assert first.authority == "INVESTIGATION_CONTEXT"
    assert first.gate_effect == "NONE"
    assert "/private/repository/must-not-leak" not in rendered
    assert '"evidence_references": "inspection_node_ids_only"' in rendered
    assert '"release_authority": "persisted_policy_decision_only"' in rendered


def test_valid_response_is_content_addressed_and_advisory_only(tmp_path):
    request = _request(tmp_path)
    response_path = tmp_path / "investigation-response.json"
    response_path.write_text(dumps(_response_payload(request)), encoding="utf-8")

    result = load_evidence_investigation_response(response_path, request)
    rendered = render_evidence_investigation_json(result)

    assert result.source_provider == "external-investigator"
    assert result.declared_model == "declared-model"
    assert result.identity_status == "DECLARED_UNATTESTED"
    assert result.authority == "INVESTIGATION_ADVISORY"
    assert result.gate_effect == "NONE"
    assert len(result.hypotheses) == 1
    assert len(result.observations) == 1
    assert len(result.questions) == 1
    assert result.hypotheses[0].hypothesis_id.startswith("investigation-hypothesis:")
    assert result.observations[0].observation_id.startswith("investigation-observation:")
    assert result.questions[0].question_id.startswith("investigation-question:")
    assert '"policy_mutation": "forbidden"' in rendered
    assert '"confidence_promotion": "forbidden"' in rendered
    assert '"gate_effect": "NONE"' in rendered
    assert '"BLOCK"' not in rendered


def test_response_rejects_evidence_reference_outside_inspection_context(tmp_path):
    request = _request(tmp_path)
    payload = _response_payload(request, evidence_node_id="deterministic-finding:not-in-trace")
    path = tmp_path / "outside.json"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="escapes bounded inspection context"):
        load_evidence_investigation_response(path, request)


def test_response_rejects_authority_or_confidence_fields_in_strict_schema(tmp_path):
    request = _request(tmp_path)
    payload = _response_payload(request)
    payload["hypotheses"][0]["confidence"] = 1.0
    path = tmp_path / "confidence.json"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported hypothesis field"):
        load_evidence_investigation_response(path, request)

    payload = _response_payload(request)
    payload["release_decision"] = "PASS"
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported investigation response field"):
        load_evidence_investigation_response(path, request)


def test_response_rejects_binding_drift_and_size_overflow(tmp_path):
    request = _request(tmp_path)
    payload = _response_payload(request)
    payload["inspection_sha256"] = "0" * 64
    path = tmp_path / "drift.json"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="different inspection"):
        load_evidence_investigation_response(path, request)

    payload = _response_payload(request)
    path.write_text(dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds byte limit"):
        load_evidence_investigation_response(path, request, max_bytes=10)


def test_validation_rejects_investigation_authority_upgrade(tmp_path):
    request = _request(tmp_path)
    path = tmp_path / "response.json"
    path.write_text(dumps(_response_payload(request)), encoding="utf-8")
    result = load_evidence_investigation_response(path, request)

    with pytest.raises(ValueError, match="advisory and gate-neutral"):
        validate_evidence_investigation(
            replace(result, authority="RELEASE_AUTHORITY"),
            request,
        )


def test_normalized_digest_ignores_json_whitespace_while_raw_digest_attests_bytes(tmp_path):
    request = _request(tmp_path)
    payload = _response_payload(request)
    compact = tmp_path / "compact.json"
    pretty = tmp_path / "pretty.json"
    compact.write_text(dumps(payload, separators=(",", ":")), encoding="utf-8")
    pretty.write_text(dumps(payload, indent=2), encoding="utf-8")

    first = load_evidence_investigation_response(compact, request)
    second = load_evidence_investigation_response(pretty, request)

    assert first.normalized_output_sha256 == second.normalized_output_sha256
    assert first.raw_input_sha256 != second.raw_input_sha256
    assert first.investigation_sha256 != second.investigation_sha256


def test_cli_request_only_mode_writes_bounded_request_artifacts(tmp_path, capsys):
    review_path = _review_path(tmp_path)
    output_dir = tmp_path / "investigate-request"

    exit_code = main(
        [
            "investigate",
            str(review_path),
            "ADV-1",
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert '"authority": "INVESTIGATION_CONTEXT"' in captured.out
    assert (output_dir / "investigation-request.json").is_file()
    assert (output_dir / "investigation-request.md").is_file()
    assert not (output_dir / "investigation.json").exists()
    assert not (output_dir / "review.json").exists()


def test_cli_response_mode_writes_advisory_investigation_without_gate_artifacts(tmp_path, capsys):
    review_path = _review_path(tmp_path)
    request_output = tmp_path / "request-stage"
    assert main(
        [
            "investigate",
            str(review_path),
            "ADV-1",
            "--output-dir",
            str(request_output),
            "--format",
            "json",
        ]
    ) == 0
    capsys.readouterr()
    request_payload = loads((request_output / "investigation-request.json").read_text(encoding="utf-8"))
    response = {
        "schema_version": 1,
        "inspection_sha256": request_payload["inspection_sha256"],
        "request_sha256": request_payload["request_sha256"],
        "source": {"provider": "external-investigator"},
        "hypotheses": [
            {
                "statement": "Inspect the correlated deterministic path.",
                "evidence_node_ids": [request_payload["selected_node_id"]],
            }
        ],
        "observations": [],
        "questions": [],
    }
    response_path = tmp_path / "response.json"
    response_path.write_text(dumps(response), encoding="utf-8")
    output_dir = tmp_path / "investigate-result"

    exit_code = main(
        [
            "investigate",
            str(review_path),
            "ADV-1",
            "--response-file",
            str(response_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert '"authority": "INVESTIGATION_ADVISORY"' in captured.out
    assert (output_dir / "investigation-request.json").is_file()
    assert (output_dir / "investigation.json").is_file()
    assert (output_dir / "investigation.md").is_file()
    assert not (output_dir / "report.json").exists()
    assert not (output_dir / "review.json").exists()


def test_cli_rejects_response_bound_to_another_request(tmp_path, capsys):
    review_path = _review_path(tmp_path)
    response_path = tmp_path / "wrong.json"
    response_path.write_text(
        dumps(
            {
                "schema_version": 1,
                "inspection_sha256": "0" * 64,
                "request_sha256": "0" * 64,
                "source": {"provider": "external-investigator"},
                "hypotheses": [],
                "observations": [],
                "questions": [
                    {
                        "question": "What happened?",
                        "evidence_node_ids": ["not-a-real-node"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "investigate",
            str(review_path),
            "ADV-1",
            "--response-file",
            str(response_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "different inspection" in captured.err
