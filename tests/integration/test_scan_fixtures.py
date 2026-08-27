from pathlib import Path

from before_deploy.controls import native_controls
from before_deploy.models import GateOutcome
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy
from before_deploy.reports import render_json, render_markdown, render_sarif

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "rules" / "default-policy.yaml"
SQL_SINGLE_ALIAS_POLICY_PATH = ROOT / "rules" / "python-sql-single-alias-policy.yaml"
PHP_LARAVEL_COMPOSER_LOCK_POLICY_PATH = ROOT / "rules" / "php-laravel-composer-lock-policy.yaml"
RUST_CARGO_LOCK_POLICY_PATH = ROOT / "rules" / "rust-cargo-lock-policy.yaml"


def _scan(fixture_name: str):
    profile = load_policy(POLICY_PATH)
    controls = configured_controls(profile, native_controls())
    return ScanOrchestrator(controls).scan(ROOT / "fixtures" / fixture_name, POLICY_PATH)


def _scan_php_laravel_composer_lock(fixture_name: str):
    profile = load_policy(PHP_LARAVEL_COMPOSER_LOCK_POLICY_PATH)
    controls = configured_controls(profile, native_controls())
    return ScanOrchestrator(controls).scan(
        ROOT / "fixtures" / fixture_name, PHP_LARAVEL_COMPOSER_LOCK_POLICY_PATH
    )


def _scan_rust_cargo_lock(fixture_name: str):
    profile = load_policy(RUST_CARGO_LOCK_POLICY_PATH)
    controls = configured_controls(profile, native_controls())
    return ScanOrchestrator(controls).scan(
        ROOT / "fixtures" / fixture_name, RUST_CARGO_LOCK_POLICY_PATH
    )


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


def test_fastapi_dynamic_router_prefix_emits_review_metadata_without_a_finding_or_gate_change():
    result = _scan("fastapi_dynamic_router_prefix_review")

    assert result.decision.outcome == GateOutcome.PASS
    assert not result.findings
    assert result.waivers == ()
    assert not result.decision.blocking_fingerprints
    assert not result.decision.waiver_required_fingerprints
    assert not any("DYNAMIC_ROUTER_PREFIX" in code for code in result.decision.reason_codes)
    assert result.coverage_audit is not None
    assert not any(
        "DYNAMIC_ROUTER_PREFIX" in assessment.rationale
        for assessment in result.coverage_audit.assessments
    )
    execution = next(item for item in result.executions if item.control_id == "SEC-API-001")
    assert execution.control_version == "0.3.0"
    assert execution.metadata == {
        "dynamic_route_review_status": "REVIEW_REQUIRED",
        "dynamic_route_review_count": "1",
        "dynamic_route_review_locations": "app.py:7:DYNAMIC_ROUTER_PREFIX",
    }
    for report in (render_json(result), render_markdown(result), render_sarif(result)):
        assert "DYNAMIC_ROUTER_PREFIX" in report
        assert "REVIEW_REQUIRED" in report
        assert "api_prefix" not in report
        assert "/api/v1" not in report
        assert "create_account" not in report


def test_php_laravel_composer_lock_policy_blocks_only_on_the_bounded_missing_lockfile():
    result = _scan_php_laravel_composer_lock("vulnerable_php_laravel_composer_lock")

    assert result.decision.outcome == GateOutcome.BLOCK
    assert {finding.rule_id for finding in result.findings} == {
        "SEC-PHP-LARAVEL-COMPOSER-LOCK-001"
    }
    assert result.project_profile is not None
    assert result.project_profile.languages == ("PHP",)
    assert result.project_profile.frameworks == ("Laravel",)
    execution = next(
        item
        for item in result.executions
        if item.control_id == "SEC-PHP-LARAVEL-COMPOSER-LOCK-001"
    )
    assert execution.status.value == "COMPLETED"
    assert result.security_analysis_plan is not None
    contract = next(
        item
        for item in result.security_analysis_plan.control_contract_selections
        if item.implementation_id == "SEC-PHP-LARAVEL-COMPOSER-LOCK-001"
    )
    assert contract.control_id == "CONTROL-SUPPLY-PHP-LARAVEL-COMPOSER-LOCK-001"
    assert contract.security_domain_ids == ("DOMAIN-SUPPLY-CHAIN-001",)
    for report in (render_json(result), render_markdown(result), render_sarif(result)):
        assert "SEC-PHP-LARAVEL-COMPOSER-LOCK-001" in report
        assert "^12.0" not in report
        assert "do-not-report-composer-value" not in report


def test_php_laravel_composer_lock_policy_handles_secure_incomplete_and_invalid_fixtures():
    secure = _scan_php_laravel_composer_lock("secure_php_laravel_composer_lock")
    incomplete = _scan_php_laravel_composer_lock("php_laravel_composer_lock_without_artisan")
    malformed = _scan_php_laravel_composer_lock("php_laravel_composer_lock_malformed_manifest")

    assert secure.decision.outcome == GateOutcome.PASS
    assert not secure.findings
    assert incomplete.decision.outcome == GateOutcome.PASS
    incomplete_execution = next(
        item
        for item in incomplete.executions
        if item.control_id == "SEC-PHP-LARAVEL-COMPOSER-LOCK-001"
    )
    assert incomplete_execution.status.value == "NOT_APPLICABLE"
    assert malformed.decision.outcome == GateOutcome.ERROR
    assert not malformed.findings
    malformed_execution = next(
        item
        for item in malformed.executions
        if item.control_id == "SEC-PHP-LARAVEL-COMPOSER-LOCK-001"
    )
    assert malformed_execution.status.value == "ERROR"
    assert malformed_execution.metadata == {"error_kind": "COMPOSER_MANIFEST_INVALID"}
    for report in (render_json(malformed), render_markdown(malformed), render_sarif(malformed)):
        assert "unterminated-value" not in report


def test_default_policy_does_not_implicitly_select_php_laravel_composer_lock_control():
    result = _scan("vulnerable_php_laravel_composer_lock")

    assert result.decision.outcome == GateOutcome.PASS
    assert "SEC-PHP-LARAVEL-COMPOSER-LOCK-001" not in {
        item.control_id for item in result.executions
    }
    assert result.security_analysis_plan is not None
    assert "SEC-PHP-LARAVEL-COMPOSER-LOCK-001" not in {
        item.implementation_id for item in result.security_analysis_plan.control_contract_selections
    }


def test_rust_cargo_lock_policy_blocks_only_on_the_bounded_missing_lockfile():
    result = _scan_rust_cargo_lock("vulnerable_rust_cargo_lock")

    assert result.decision.outcome == GateOutcome.BLOCK
    assert {finding.rule_id for finding in result.findings} == {"SEC-RUST-CARGO-LOCK-001"}
    assert result.project_profile is not None
    assert result.project_profile.languages == ("Rust",)
    execution = next(
        item for item in result.executions if item.control_id == "SEC-RUST-CARGO-LOCK-001"
    )
    assert execution.status.value == "COMPLETED"
    assert result.security_analysis_plan is not None
    contract = next(
        item
        for item in result.security_analysis_plan.control_contract_selections
        if item.implementation_id == "SEC-RUST-CARGO-LOCK-001"
    )
    assert contract.control_id == "CONTROL-SUPPLY-RUST-CARGO-LOCK-001"
    assert contract.security_domain_ids == ("DOMAIN-SUPPLY-CHAIN-001",)
    for report in (render_json(result), render_markdown(result), render_sarif(result)):
        assert "SEC-RUST-CARGO-LOCK-001" in report
        assert "tokio" not in report
        assert "do-not-report-cargo-value" not in report


def test_rust_cargo_lock_policy_handles_secure_library_and_invalid_fixtures():
    secure = _scan_rust_cargo_lock("secure_rust_cargo_lock")
    library = _scan_rust_cargo_lock("rust_cargo_lock_library_only")
    malformed = _scan_rust_cargo_lock("rust_cargo_lock_malformed_manifest")

    assert secure.decision.outcome == GateOutcome.PASS
    assert not secure.findings
    assert library.decision.outcome == GateOutcome.PASS
    library_execution = next(
        item for item in library.executions if item.control_id == "SEC-RUST-CARGO-LOCK-001"
    )
    assert library_execution.status.value == "NOT_APPLICABLE"
    assert malformed.decision.outcome == GateOutcome.ERROR
    assert not malformed.findings
    malformed_execution = next(
        item for item in malformed.executions if item.control_id == "SEC-RUST-CARGO-LOCK-001"
    )
    assert malformed_execution.status.value == "ERROR"
    assert malformed_execution.metadata == {"error_kind": "CARGO_MANIFEST_INVALID"}
    for report in (render_json(malformed), render_markdown(malformed), render_sarif(malformed)):
        assert "source_only_invalid" not in report


def test_default_policy_does_not_implicitly_select_rust_cargo_lock_control():
    result = _scan("vulnerable_rust_cargo_lock")

    assert result.decision.outcome == GateOutcome.PASS
    assert "SEC-RUST-CARGO-LOCK-001" not in {item.control_id for item in result.executions}
    assert result.security_analysis_plan is not None
    assert "SEC-RUST-CARGO-LOCK-001" not in {
        item.implementation_id for item in result.security_analysis_plan.control_contract_selections
    }


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
