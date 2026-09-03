from pathlib import Path

import pytest

from before_deploy.models import (
    ControlExecution,
    CoverageAssessment,
    CoverageAudit,
    CoverageStatus,
    Disposition,
    ExecutionStatus,
    GateOutcome,
    ScanManifest,
    utc_now,
)
from before_deploy.policy import (
    AssurancePolicy,
    ControlPolicy,
    PolicyProfile,
    evaluate,
    load_policy,
)


def _manifest() -> ScanManifest:
    now = utc_now()
    return ScanManifest(
        scan_id="scan-assurance",
        repository_path="/repo",
        repository_digest="repo-digest",
        policy_digest="policy-digest",
        policy_name="assurance-test",
        started_at=now,
    )


def _execution() -> ControlExecution:
    now = utc_now()
    return ControlExecution(
        control_id="SEC-TEST-001",
        control_version="1",
        status=ExecutionStatus.COMPLETED,
        started_at=now,
        completed_at=now,
    )


def _profile(minimum: CoverageStatus) -> PolicyProfile:
    return PolicyProfile(
        schema_version=1,
        name="assurance-test",
        controls={
            "SEC-TEST-001": ControlPolicy(
                required=True,
                disposition=Disposition.BLOCK,
            )
        },
        public_fastapi_routes=frozenset(),
        assurance=AssurancePolicy(
            minimum_domain_coverage={"DOMAIN-INJECTION-001": minimum}
        ),
    )


def _audit(status: CoverageStatus) -> CoverageAudit:
    return CoverageAudit(
        audit_version="0.4.0",
        assessments=(
            CoverageAssessment(
                domain="Injection",
                domain_id="DOMAIN-INJECTION-001",
                status=status,
                rationale="test",
            ),
        ),
    )


def test_covered_satisfies_covered_minimum():
    _, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(),),
        findings=(),
        waivers=(),
        profile=_profile(CoverageStatus.COVERED),
        coverage_audit=_audit(CoverageStatus.COVERED),
    )

    assert decision.outcome == GateOutcome.PASS
    assert (
        "ASSURANCE_COVERAGE_SATISFIED:DOMAIN-INJECTION-001:COVERED"
        in decision.reason_codes
    )


def test_covered_satisfies_partial_minimum():
    _, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(),),
        findings=(),
        waivers=(),
        profile=_profile(CoverageStatus.PARTIAL),
        coverage_audit=_audit(CoverageStatus.COVERED),
    )

    assert decision.outcome == GateOutcome.PASS


def test_partial_fails_covered_minimum():
    _, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(),),
        findings=(),
        waivers=(),
        profile=_profile(CoverageStatus.COVERED),
        coverage_audit=_audit(CoverageStatus.PARTIAL),
    )

    assert decision.outcome == GateOutcome.ERROR
    assert decision.error_control_ids == ("ASSURANCE:DOMAIN-INJECTION-001",)
    assert (
        "ASSURANCE_COVERAGE_INSUFFICIENT:DOMAIN-INJECTION-001:"
        "PARTIAL:REQUIRES_COVERED"
        in decision.reason_codes
    )


@pytest.mark.parametrize(
    "status",
    [
        CoverageStatus.UNAVAILABLE,
        CoverageStatus.NOT_SELECTED,
        CoverageStatus.NOT_APPLICABLE,
        CoverageStatus.DECLARED_REVIEW_REQUIRED,
        CoverageStatus.ERROR,
    ],
)
def test_non_assurance_states_fail_partial_minimum(status: CoverageStatus):
    _, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(),),
        findings=(),
        waivers=(),
        profile=_profile(CoverageStatus.PARTIAL),
        coverage_audit=_audit(status),
    )

    assert decision.outcome == GateOutcome.ERROR
    assert decision.error_control_ids == ("ASSURANCE:DOMAIN-INJECTION-001",)


def test_missing_required_domain_is_policy_error():
    empty_audit = CoverageAudit(audit_version="0.4.0", assessments=())

    _, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(),),
        findings=(),
        waivers=(),
        profile=_profile(CoverageStatus.PARTIAL),
        coverage_audit=empty_audit,
    )

    assert decision.outcome == GateOutcome.ERROR
    assert "ASSURANCE_DOMAIN_MISSING:DOMAIN-INJECTION-001" in decision.reason_codes


def test_missing_coverage_audit_is_policy_error_when_assurance_is_configured():
    _, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(),),
        findings=(),
        waivers=(),
        profile=_profile(CoverageStatus.PARTIAL),
    )

    assert decision.outcome == GateOutcome.ERROR
    assert "ASSURANCE_COVERAGE_AUDIT_MISSING" in decision.reason_codes


def test_no_assurance_configuration_preserves_existing_policy_behavior():
    profile = PolicyProfile(
        schema_version=1,
        name="legacy",
        controls={
            "SEC-TEST-001": ControlPolicy(
                required=True,
                disposition=Disposition.BLOCK,
            )
        },
        public_fastapi_routes=frozenset(),
    )

    _, decision = evaluate(
        manifest=_manifest(),
        executions=(_execution(),),
        findings=(),
        waivers=(),
        profile=profile,
    )

    assert decision.outcome == GateOutcome.PASS


def test_policy_loader_accepts_domain_assurance(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
schema_version: 1
profile: assurance
controls:
  SEC-TEST-001:
    required: true
    disposition: BLOCK
assurance:
  minimum_domain_coverage:
    DOMAIN-INJECTION-001: COVERED
    DOMAIN-SECRETS-001: PARTIAL
""".strip(),
        encoding="utf-8",
    )

    loaded = load_policy(policy)

    assert loaded.assurance.minimum_domain_coverage == {
        "DOMAIN-INJECTION-001": CoverageStatus.COVERED,
        "DOMAIN-SECRETS-001": CoverageStatus.PARTIAL,
    }


@pytest.mark.parametrize(
    "domain_id,status",
    [
        ("INJECTION", "COVERED"),
        ("DOMAIN-INJECTION-001", "UNAVAILABLE"),
        ("DOMAIN-INJECTION-001", "NOT_SELECTED"),
    ],
)
def test_policy_loader_rejects_invalid_assurance_minimums(
    tmp_path: Path, domain_id: str, status: str
):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        f"""
schema_version: 1
profile: assurance
controls:
  SEC-TEST-001:
    required: true
    disposition: BLOCK
assurance:
  minimum_domain_coverage:
    {domain_id}: {status}
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_policy(policy)
