from pathlib import Path

from before_deploy.controls import native_controls
from before_deploy.models import GateOutcome
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "rules" / "default-policy.yaml"


def _scan(fixture_name: str):
    profile = load_policy(POLICY_PATH)
    controls = configured_controls(profile, native_controls())
    return ScanOrchestrator(controls).scan(ROOT / "fixtures" / fixture_name, POLICY_PATH)


def test_vulnerable_fixture_blocks_for_expected_controls():
    result = _scan("vulnerable_fastapi_nextjs")
    rule_ids = {finding.rule_id for finding in result.findings}

    assert result.decision.outcome == GateOutcome.BLOCK
    assert {
        "SEC-SECRET-001",
        "SEC-SAST-001",
        "SEC-API-001",
        "SEC-CONFIG-001",
        "SEC-CONFIG-002",
        "SEC-CICD-001",
        "SEC-DEP-001",
    }.issubset(rule_ids)
    assert all("demo-secret-value" not in finding.message for finding in result.findings)


def test_local_python_sql_flow_fixture_blocks_only_on_the_bounded_assignment_pattern():
    result = _scan("vulnerable_python_local_sql_flow")

    assert result.decision.outcome == GateOutcome.BLOCK
    assert {finding.rule_id for finding in result.findings} == {"SEC-SAST-001"}
    assert result.findings[0].evidence == {
        "construction": "f_string",
        "sink": "execute",
        "flow": "local_straight_line_assignment",
    }
    assert result.security_analysis_plan is not None
    capability = next(
        selection
        for selection in result.security_analysis_plan.control_selections
        if selection.implementation_id == "SEC-SAST-001"
    )
    assert capability.capability_version == "0.2.0"
    contract = next(
        selection
        for selection in result.security_analysis_plan.control_contract_selections
        if selection.implementation_id == "SEC-SAST-001"
    )
    assert contract.control_id == "CONTROL-INJECTION-PYTHON-001"
    assert contract.control_version == "0.2.0"


def test_local_python_sql_flow_reassignment_and_branch_cases_do_not_infer_dataflow():
    reassigned = _scan("secure_python_local_sql_flow")
    conditional = _scan("python_local_sql_flow_ambiguous")

    assert reassigned.decision.outcome == GateOutcome.PASS
    assert conditional.decision.outcome == GateOutcome.PASS
    assert not reassigned.findings
    assert not conditional.findings


def test_secure_fixture_passes_default_profile():
    result = _scan("secure_fastapi_nextjs")

    assert result.decision.outcome == GateOutcome.PASS
    assert result.decision.blocking_fingerprints == ()
