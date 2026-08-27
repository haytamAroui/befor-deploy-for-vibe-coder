from pathlib import Path

from before_deploy.controls import native_controls
from before_deploy.models import GateOutcome
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy
from before_deploy.reports import render_json, render_markdown, render_sarif

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "rules" / "default-policy.yaml"
SQL_SINGLE_ALIAS_POLICY_PATH = ROOT / "rules" / "python-sql-single-alias-policy.yaml"


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


def test_fastapi_dynamic_routes_emit_review_state_without_a_finding_or_gate_change():
    result = _scan("fastapi_dynamic_route_review")

    assert result.decision.outcome == GateOutcome.PASS
    assert not result.findings
    execution = next(item for item in result.executions if item.control_id == "SEC-API-001")
    assert execution.metadata == {
        "dynamic_route_review_status": "REVIEW_REQUIRED",
        "dynamic_route_review_count": "2",
        "dynamic_route_review_locations": "app.py:8:DYNAMIC_PATH,app.py:13:DYNAMIC_METHODS",
    }
    for report in (render_json(result), render_markdown(result), render_sarif(result)):
        assert "dynamic_route_review_status" in report
        assert "REVIEW_REQUIRED" in report
    markdown_report = render_markdown(result)
    assert "`SEC-API-001` | COMPLETED" in markdown_report
    assert "dynamic_route_review_locations=app.py:8:DYNAMIC_PATH,app.py:13:DYNAMIC_METHODS" in markdown_report


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


def test_sql_single_alias_policy_blocks_only_on_the_new_bounded_alias_contract():
    profile = load_policy(SQL_SINGLE_ALIAS_POLICY_PATH)
    controls = configured_controls(profile, native_controls())
    result = ScanOrchestrator(controls).scan(
        ROOT / "fixtures" / "vulnerable_python_sql_single_alias", SQL_SINGLE_ALIAS_POLICY_PATH
    )

    assert result.decision.outcome == GateOutcome.BLOCK
    assert {finding.rule_id for finding in result.findings} == {"SEC-SAST-SQL-ALIAS-001"}
    assert result.findings[0].evidence == {
        "construction": "f_string",
        "sink": "execute",
        "flow": "single_local_name_alias",
    }
    assert result.security_analysis_plan is not None
    contract = next(
        selection
        for selection in result.security_analysis_plan.control_contract_selections
        if selection.implementation_id == "SEC-SAST-SQL-ALIAS-001"
    )
    assert contract.control_id == "CONTROL-INJECTION-PYTHON-SQL-SINGLE-ALIAS-001"
    assert contract.security_domain_ids == ("DOMAIN-INJECTION-001",)
    for report in (render_json(result), render_markdown(result), render_sarif(result)):
        assert "account_id" not in report
        assert "SELECT * FROM accounts" not in report


def test_sql_single_alias_policy_does_not_infer_safe_or_excluded_flow():
    profile = load_policy(SQL_SINGLE_ALIAS_POLICY_PATH)
    controls = configured_controls(profile, native_controls())
    for fixture_name in (
        "secure_python_sql_single_alias",
        "python_sql_single_alias_reassigned",
        "python_sql_single_alias_false_positive",
    ):
        result = ScanOrchestrator(controls).scan(
            ROOT / "fixtures" / fixture_name, SQL_SINGLE_ALIAS_POLICY_PATH
        )
        assert result.decision.outcome == GateOutcome.PASS
        assert not result.findings


def test_default_policy_does_not_implicitly_select_sql_single_alias_control():
    result = _scan("vulnerable_python_sql_single_alias")

    assert result.decision.outcome == GateOutcome.PASS
    assert "SEC-SAST-SQL-ALIAS-001" not in {execution.control_id for execution in result.executions}
    assert result.security_analysis_plan is not None
    assert "SEC-SAST-SQL-ALIAS-001" not in {
        selection.implementation_id
        for selection in result.security_analysis_plan.control_contract_selections
    }


def test_secure_fixture_passes_default_profile():
    result = _scan("secure_fastapi_nextjs")

    assert result.decision.outcome == GateOutcome.PASS
    assert result.decision.blocking_fingerprints == ()
