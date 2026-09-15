from datetime import datetime, timezone
from json import loads

import pytest

from before_deploy.advisory import build_unified_review, load_advisory_file
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


def _scan_result() -> ScanResult:
    deterministic = Finding(
        rule_id="SEC-TEST-001",
        rule_version="1.0.0",
        title="Deterministic test finding",
        message="Bounded deterministic evidence.",
        remediation="Fix it.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint="deterministic-fingerprint",
        location=Location(path="src/app.py", start_line=10, end_line=10),
    )
    manifest = ScanManifest(
        scan_id="scan-1",
        repository_path=".",
        repository_digest="repo-digest",
        policy_digest="policy-digest",
        policy_name="test",
        started_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
        completed_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )
    decision = PolicyDecision(
        outcome=GateOutcome.BLOCK,
        reason_codes=("BLOCKING_FINDINGS",),
        blocking_fingerprints=(deterministic.fingerprint,),
    )
    return ScanResult(
        manifest=manifest,
        executions=(),
        findings=(deterministic,),
        waivers=(),
        decision=decision,
    )


def test_loads_ocr_json_as_non_authoritative_advisory(tmp_path):
    result_path = tmp_path / "ocr.json"
    result_path.write_text(
        """[
          {
            "path": "src/app.py",
            "content": "Possible authorization bug.",
            "start_line": 10,
            "end_line": 11,
            "category": "security",
            "severity": "high",
            "thinking": "must never be imported",
            "existing_code": "secret = value",
            "suggestion_code": "replacement"
          }
        ]""",
        encoding="utf-8",
    )

    imported = load_advisory_file(result_path)

    assert imported.source == "open-code-review"
    assert imported.source_format == "ocr-json"
    assert len(imported.findings) == 1
    finding = imported.findings[0]
    assert finding.authority == "ADVISORY"
    assert finding.gate_effect == "NONE"
    assert finding.location == Location(path="src/app.py", start_line=10, end_line=11)
    assert not hasattr(finding, "thinking")
    assert not hasattr(finding, "existing_code")
    assert not hasattr(finding, "suggestion_code")


def test_location_correlation_does_not_change_policy_decision(tmp_path):
    result_path = tmp_path / "advisory.json"
    result_path.write_text(
        """{
          "source": {"provider": "test-reviewer"},
          "findings": [
            {
              "title": "Possible bug",
              "message": "Review this line.",
              "category": "bug",
              "severity": "medium",
              "location": {"path": "src/app.py", "start_line": 10, "end_line": 12}
            }
          ]
        }""",
        encoding="utf-8",
    )
    scan = _scan_result()

    review = build_unified_review(scan, (load_advisory_file(result_path),))

    assert review.scan.decision is scan.decision
    assert review.scan.decision.outcome == GateOutcome.BLOCK
    assert len(review.correlations) == 1
    assert review.correlations[0].deterministic_fingerprints == (
        "deterministic-fingerprint",
    )
    assert review.correlations[0].gate_effect == "NONE"


def test_review_json_states_authority_contract_and_omits_raw_ocr_code(tmp_path):
    result_path = tmp_path / "ocr.json"
    result_path.write_text(
        """{
          "comments": [
            {
              "path": "src/app.py",
              "content": "Potential bug.",
              "start_line": 10,
              "severity": "high",
              "category": "bug",
              "thinking": "private chain",
              "existing_code": "password = hardcoded",
              "suggestion_code": "password = getenv()"
            }
          ]
        }""",
        encoding="utf-8",
    )
    review = build_unified_review(_scan_result(), (load_advisory_file(result_path),))

    rendered = render_review_json(review)
    payload = loads(rendered)

    assert payload["authority_contract"]["release_authority"] == (
        "deterministic_policy_decision"
    )
    assert payload["authority_contract"]["advisory_gate_effect"] == "NONE"
    assert payload["authority_contract"]["evidence_graph"] == "diagnostic_lineage_only"
    assert payload["deterministic_scan"]["decision"]["outcome"] == "BLOCK"

    graph = payload["evidence_graph"]
    assert graph["authority"] == "EVIDENCE_GRAPH"
    assert graph["gate_effect"] == "NONE"
    assert len(graph["graph_sha256"]) == 64
    release_nodes = [node for node in graph["nodes"] if node["authority"] == "RELEASE_AUTHORITY"]
    assert len(release_nodes) == 1
    assert release_nodes[0]["node_type"] == "POLICY_DECISION"

    assert "private chain" not in rendered
    assert "password = hardcoded" not in rendered
    assert "password = getenv()" not in rendered


def test_rejects_absolute_or_parent_traversal_paths(tmp_path):
    result_path = tmp_path / "bad.json"
    result_path.write_text(
        '[{"path": "../outside.py", "content": "bad"}]',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="repository-relative"):
        load_advisory_file(result_path)
