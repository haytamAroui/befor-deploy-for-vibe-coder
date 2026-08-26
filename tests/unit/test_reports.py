import json

from before_deploy.models import (
    Confidence,
    ControlExecution,
    ExecutionStatus,
    Finding,
    GateOutcome,
    PolicyDecision,
    ScanManifest,
    ScanResult,
    Severity,
    utc_now,
)
from before_deploy.reports import render_json, render_markdown, render_sarif


def _result() -> ScanResult:
    now = utc_now()
    finding = Finding(
        rule_id="SEC-SECRET-001",
        rule_version="0.1.0",
        title="Likely committed secret",
        message="A high-confidence credential pattern was detected.",
        remediation="Rotate the credential.",
        severity=Severity.BLOCKER,
        confidence=Confidence.HIGH,
        fingerprint="secret-fingerprint",
        evidence={"pattern": "private_key", "match_digest": "abc123"},
    )
    return ScanResult(
        manifest=ScanManifest(
            scan_id="scan-1",
            repository_path="/repo",
            repository_digest="repo-digest",
            policy_digest="policy-digest",
            policy_name="test",
            started_at=now,
            completed_at=now,
        ),
        executions=(
            ControlExecution(
                control_id="SEC-SECRET-001",
                control_version="0.1.0",
                status=ExecutionStatus.COMPLETED,
                started_at=now,
                completed_at=now,
            ),
        ),
        findings=(finding,),
        waivers=(),
        decision=PolicyDecision(
            outcome=GateOutcome.BLOCK,
            reason_codes=("BLOCKING_FINDING:SEC-SECRET-001",),
            blocking_fingerprints=("secret-fingerprint",),
        ),
    )


def test_reports_preserve_redacted_finding_content():
    result = _result()
    raw_secret = "-----BEGIN " + "PRIVATE KEY-----"

    assert raw_secret not in render_json(result)
    assert raw_secret not in render_markdown(result)
    assert raw_secret not in render_sarif(result)


def test_sarif_has_required_top_level_contract():
    sarif = json.loads(render_sarif(_result()))

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SEC-SECRET-001"
