from datetime import datetime, timezone
from json import loads

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, build_unified_review
from before_deploy.advisory_execution import (
    AdvisoryExecutionProvenance,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
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
from before_deploy.reports.review_report import render_review_json, render_review_markdown

NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _source(name: str, provider: str, model: str, digest_char: str, finding: AdvisoryFinding):
    raw = AdvisoryRawArtifact(
        sha256=digest_char * 64,
        size_bytes=120,
        media_type="application/json",
        schema="review-json-v1",
    )
    execution = AdvisoryExecutionProvenance(
        schema_version=1,
        provider_id=provider,
        implementation=f"{provider}-adapter",
        implementation_version="1",
        model=AdvisoryModelIdentity(status="ATTESTED", provider=provider, model=model),
        configuration=(),
        configuration_sha256=("c" if digest_char != "c" else "d") * 64,
        budgets=(),
        context_sha256=("e" if digest_char != "e" else "f") * 64,
        context_selected_files=1,
        context_selected_bytes=10,
        started_at=NOW,
        completed_at=NOW,
        duration_ms=3,
        raw_output=raw,
        normalized_output_sha256=("8" if digest_char != "8" else "7") * 64,
        result_status="COMPLETED",
    )
    return AdvisoryImport(
        input_name=name,
        source="reviewer",
        source_format="review-json-v1",
        findings=(finding,),
        raw_artifact=raw,
        execution=execution,
    )


def test_review_reports_expose_gate_neutral_corroboration_without_confidence_promotion():
    deterministic = Finding(
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
    scan = ScanResult(
        manifest=ScanManifest(
            scan_id="scan-1",
            repository_path="/legacy/report/path",
            repository_digest="repo-digest",
            policy_digest="policy-digest",
            policy_name="strict",
            started_at=NOW,
            completed_at=NOW,
        ),
        executions=(),
        findings=(deterministic,),
        waivers=(),
        decision=PolicyDecision(
            outcome=GateOutcome.BLOCK,
            reason_codes=("BLOCKING_FINDINGS",),
            blocking_fingerprints=(deterministic.fingerprint,),
        ),
    )
    advisory = AdvisoryFinding(
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
    review = build_unified_review(
        scan,
        (
            _source("one", "provider-a", "model-a", "a", advisory),
            _source("two", "provider-b", "model-b", "b", advisory),
        ),
    )

    payload = loads(render_review_json(review))
    corroboration = payload["evidence_corroboration"]
    item = corroboration["assessments"][0]

    assert payload["deterministic_scan"]["decision"]["outcome"] == "BLOCK"
    assert payload["authority_contract"]["corroboration_authority"] == "diagnostic_only"
    assert payload["authority_contract"]["corroboration_semantics"] == (
        "exact_claim_provenance_only"
    )
    assert payload["authority_contract"]["deterministic_colocation_semantics"] == (
        "context_not_semantic_agreement"
    )
    assert corroboration["authority"] == "CORROBORATION_DIAGNOSTIC"
    assert corroboration["gate_effect"] == "NONE"
    assert corroboration["graph_sha256"] == payload["evidence_graph"]["graph_sha256"]
    assert corroboration["correlation_sha256"] == payload["evidence_correlation"][
        "correlation_sha256"
    ]
    assert item["status"] == "MULTI_EXECUTION_EXACT_CLAIM"
    assert item["provider_ids"] == ["provider-a", "provider-b"]
    assert item["attested_model_identities"] == ["provider-a/model-a", "provider-b/model-b"]
    assert "DETERMINISTIC_COLOCATION" in item["signals"]
    assert item["authority"] == "CORROBORATION_DIAGNOSTIC"
    assert item["gate_effect"] == "NONE"
    assert "confidence" not in item
    assert payload["advisory_findings"][0]["confidence"] == "0.8"

    graph_section = str(payload["evidence_graph"])
    correlation_section = str(payload["evidence_correlation"])
    corroboration_section = str(corroboration)
    assert "/legacy/report/path" not in graph_section
    assert "/legacy/report/path" not in correlation_section
    assert "/legacy/report/path" not in corroboration_section

    markdown = render_review_markdown(review)
    assert "MULTI_EXECUTION_EXACT_CLAIM" in markdown
    assert "provider-a/model-a" in markdown
    assert "provider-b/model-b" in markdown
    assert "does not alter provider confidence" in markdown
