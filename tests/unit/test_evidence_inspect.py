from __future__ import annotations

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
from before_deploy.evidence_inspect import (
    build_evidence_inspection,
    render_evidence_inspection_json,
    resolve_inspection_selector,
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


def _advisory(*, finding_id: str = "ADV-1", title: str = "Possible issue") -> AdvisoryFinding:
    return AdvisoryFinding(
        finding_id=finding_id,
        source="reviewer",
        title=title,
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


def _write_review(tmp_path, sources: tuple[AdvisoryImport, ...] | None = None):
    review = build_unified_review(_scan(), sources or (_source(),))
    path = tmp_path / "review.json"
    path.write_text(render_review_json(review), encoding="utf-8")
    return path


def test_persisted_review_evidence_round_trips_through_existing_validators(tmp_path):
    path = _write_review(tmp_path)
    original = loads(path.read_text(encoding="utf-8"))

    artifact = load_review_evidence(path)

    assert artifact.graph.graph_sha256 == original["evidence_graph"]["graph_sha256"]
    assert artifact.correlation.correlation_sha256 == original["evidence_correlation"]["correlation_sha256"]
    assert artifact.corroboration.corroboration_sha256 == original["evidence_corroboration"]["corroboration_sha256"]
    assert len(artifact.graph.nodes) > 0


def test_loader_rejects_gate_authority_tampering_before_inspection(tmp_path):
    path = _write_review(tmp_path)
    payload = loads(path.read_text(encoding="utf-8"))
    payload["evidence_graph"]["gate_effect"] = "BLOCK"
    path.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="gate-neutral"):
        load_review_evidence(path)


def test_advisory_inspection_exposes_full_recorded_lineage_without_authority_promotion(tmp_path):
    artifact = load_review_evidence(_write_review(tmp_path))

    result = build_evidence_inspection(artifact, "ADV-1")
    rendered = render_evidence_inspection_json(result)
    node_types = {record.node.node_type for record in result.nodes}

    assert {
        "ADVISORY_FINDING",
        "NORMALIZED_ADVISORY_OUTPUT",
        "RAW_ADVISORY_ARTIFACT",
        "ADVISORY_EXECUTION",
        "ADVISORY_CONTEXT",
        "DETERMINISTIC_FINDING",
        "REPOSITORY_SNAPSHOT",
        "POLICY_DECISION",
        "POLICY_INPUT",
    }.issubset(node_types)
    assert result.authority == "INSPECTION_DIAGNOSTIC"
    assert result.gate_effect == "NONE"
    assert len(result.correlations) == 1
    assert result.corroboration_assessments[0].status == "NONE"
    assert result.corroboration_assessments[0].signals == ("DETERMINISTIC_COLOCATION",)
    assert result.policy_relationships[0].policy_role == "BLOCKING"
    assert result.policy_relationships[0].outcome == "BLOCK"
    assert "/private/repository/must-not-leak" not in rendered
    assert '"advisory_authority_promotion": "forbidden"' in rendered


def test_deterministic_inspection_can_follow_correlation_to_advisory_provenance(tmp_path):
    artifact = load_review_evidence(_write_review(tmp_path))

    result = build_evidence_inspection(artifact, "deterministic-fingerprint")

    selected = next(record.node for record in result.nodes if record.node.node_id == result.selected_node_id)
    assert selected.node_type == "DETERMINISTIC_FINDING"
    assert any(record.node.node_type == "ADVISORY_EXECUTION" for record in result.nodes)
    assert len(result.correlations) == 1
    assert result.policy_relationships[0].policy_role == "BLOCKING"


def test_selector_fails_closed_when_fingerprint_alias_is_ambiguous(tmp_path):
    first = _advisory(finding_id="ADV-1", title="First wording")
    second = _advisory(finding_id="ADV-2", title="Second wording")
    sources = (
        AdvisoryImport("one", "reviewer", "json", (first,)),
        AdvisoryImport("two", "reviewer", "json", (second,)),
    )
    artifact = load_review_evidence(_write_review(tmp_path, sources))

    with pytest.raises(ValueError, match="ambiguous"):
        resolve_inspection_selector(artifact, "same-advisory-fingerprint")

    assert resolve_inspection_selector(artifact, "ADV-1").finding_id == "ADV-1"
    assert resolve_inspection_selector(artifact, "ADV-2").finding_id == "ADV-2"


def test_installed_entrypoint_inspect_writes_diagnostic_artifacts(tmp_path, capsys):
    review_path = _write_review(tmp_path)
    output_dir = tmp_path / "inspect-output"

    exit_code = main(
        [
            "inspect",
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
    assert '"authority": "INSPECTION_DIAGNOSTIC"' in captured.out
    assert (output_dir / "inspection.json").is_file()
    assert (output_dir / "inspection.md").is_file()
    assert not (output_dir / "report.json").exists()
    assert not (output_dir / "review.json").exists()


def test_installed_entrypoint_inspect_returns_input_error_for_unknown_selector(tmp_path, capsys):
    review_path = _write_review(tmp_path)

    exit_code = main(["inspect", str(review_path), "does-not-exist"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "did not match" in captured.err
