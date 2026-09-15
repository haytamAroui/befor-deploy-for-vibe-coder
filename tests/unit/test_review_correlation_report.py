from datetime import datetime, timezone
from json import dumps, loads

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, build_unified_review
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


def test_review_json_exposes_graph_bound_gate_neutral_correlation_and_exact_dedup():
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
            repository_path="/must/not/leak",
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
    sources = (
        AdvisoryImport("one", "reviewer", "json", (advisory,)),
        AdvisoryImport("two", "reviewer", "json", (advisory,)),
    )
    review = build_unified_review(scan, sources)

    payload = loads(render_review_json(review))
    correlation = payload["evidence_correlation"]

    assert payload["deterministic_scan"]["decision"]["outcome"] == "BLOCK"
    assert payload["authority_contract"]["correlation_authority"] == "diagnostic_only"
    assert payload["authority_contract"]["deduplication_semantics"] == (
        "exact_advisory_fingerprint_only"
    )
    assert correlation["authority"] == "CORRELATION_DIAGNOSTIC"
    assert correlation["gate_effect"] == "NONE"
    assert correlation["graph_sha256"] == payload["evidence_graph"]["graph_sha256"]
    assert len(correlation["correlations"]) == 1
    assert correlation["correlations"][0]["relation"] == "CORRELATES_WITH"
    assert len(correlation["unique_advisory_node_ids"]) == 1
    assert correlation["duplicate_groups"][0]["occurrence_count"] == 2

    graph_backed_diagnostics = dumps(
        {
            "evidence_graph": payload["evidence_graph"],
            "evidence_correlation": correlation,
        },
        sort_keys=True,
    )
    assert "/must/not/leak" not in graph_backed_diagnostics
