from datetime import timedelta

from before_deploy.models import (
    Confidence,
    ControlExecution,
    Disposition,
    ExecutionStatus,
    Finding,
    GateOutcome,
    ScanManifest,
    Severity,
    Waiver,
    utc_now,
)
from before_deploy.policy import ControlPolicy, PolicyProfile, evaluate


def _manifest() -> ScanManifest:
    now = utc_now()
    return ScanManifest(
        scan_id="scan-1",
        repository_path="/repo",
        repository_digest="repo-digest",
        policy_digest="policy-digest",
        policy_name="test",
        started_at=now,
    )


def _profile() -> PolicyProfile:
    return PolicyProfile(
        schema_version=1,
        name="test",
        controls={"SEC-TEST-001": ControlPolicy(required=True, disposition=Disposition.BLOCK)},
        public_fastapi_routes=frozenset(),
    )


def _execution(status: ExecutionStatus = ExecutionStatus.COMPLETED) -> ControlExecution:
    now = utc_now()
    return ControlExecution(
        control_id="SEC-TEST-001",
        control_version="1",
        status=status,
        started_at=now,
        completed_at=now,
    )


def _finding() -> Finding:
    return Finding(
        rule_id="SEC-TEST-001",
        rule_version="1",
        title="test",
        message="test finding",
        remediation="fix it",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint="finding-1",
    )


def test_required_control_error_has_priority_over_other_outcomes():
    findings, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(ExecutionStatus.ERROR),),
        findings=(_finding(),),
        waivers=(),
        profile=_profile(),
    )

    assert findings[0].disposition == Disposition.BLOCK
    assert decision.outcome == GateOutcome.ERROR
    assert decision.error_control_ids == ("SEC-TEST-001",)


def test_exact_unexpired_waiver_prevents_only_matching_block():
    manifest = _manifest()
    waiver = Waiver(
        waiver_id="waiver-1",
        finding_fingerprint="finding-1",
        rule_id="SEC-TEST-001",
        repository_digest=manifest.repository_digest,
        approved_by="security@example.test",
        justification="temporary compensating control",
        compensating_controls="network isolation",
        expires_at=utc_now() + timedelta(days=1),
    )

    _, decision = evaluate(
        manifest=manifest,
        executions=(_execution(),),
        findings=(_finding(),),
        waivers=(waiver,),
        profile=_profile(),
    )

    assert decision.outcome == GateOutcome.PASS
    assert decision.waived_fingerprints == ("finding-1",)


def test_expired_waiver_does_not_change_decision():
    manifest = _manifest()
    waiver = Waiver(
        waiver_id="waiver-1",
        finding_fingerprint="finding-1",
        rule_id="SEC-TEST-001",
        repository_digest=manifest.repository_digest,
        approved_by="security@example.test",
        justification="temporary compensating control",
        compensating_controls="network isolation",
        expires_at=utc_now() - timedelta(seconds=1),
    )

    _, decision = evaluate(
        manifest=manifest,
        executions=(_execution(),),
        findings=(_finding(),),
        waivers=(waiver,),
        profile=_profile(),
    )

    assert decision.outcome == GateOutcome.BLOCK
