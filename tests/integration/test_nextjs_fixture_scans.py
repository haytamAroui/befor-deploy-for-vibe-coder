from pathlib import Path

from before_deploy.cli import _controls_for_profile
from before_deploy.controls import native_controls
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy
from before_deploy.reports import render_json, render_markdown, render_sarif


REPOSITORY = Path(__file__).parents[2]
POLICY_PATH = REPOSITORY / "rules" / "default-policy.yaml"
GO_VULNERABILITY_POLICY_PATH = REPOSITORY / "rules" / "go-vulnerability-snapshot-policy.yaml"
NEXT_INLINE_ACTION_POLICY_PATH = REPOSITORY / "rules" / "nextjs-inline-server-actions-policy.yaml"
FIXTURES = REPOSITORY / "fixtures"


def _scan(name: str):
    profile = load_policy(POLICY_PATH)
    controls = configured_controls(profile, native_controls())
    return ScanOrchestrator(controls).scan(FIXTURES / name, POLICY_PATH)


def test_vulnerable_nextjs_fixture_blocks_on_new_nextjs_controls():
    result = _scan("vulnerable_nextjs_security")

    assert result.decision.outcome.value == "BLOCK"
    assert {finding.rule_id for finding in result.findings} >= {
        "SEC-NEXT-ENV-001",
        "SEC-NEXT-COOKIE-001",
        "SEC-NEXT-CORS-001",
    }


def test_secure_nextjs_fixture_passes_and_reports_nextjs_profile():
    result = _scan("secure_nextjs_security")

    assert result.decision.outcome.value == "PASS"
    assert result.project_profile is not None
    assert "Next.js" in result.project_profile.frameworks
    assert not {
        finding.rule_id
        for finding in result.findings
        if finding.rule_id.startswith("SEC-NEXT-")
    }


def test_adaptive_planning_fixture_exposes_evidence_plan_and_diagnostic_coverage():
    result = _scan("adaptive_planning_evidence")

    assert result.decision.outcome.value == "PASS"
    assert result.security_analysis_plan is not None
    assert result.coverage_audit is not None

    plan = result.security_analysis_plan
    evidence_ids = {item.signal_id for item in plan.evidence}
    assert {
        "REPOSITORY-API-OPENAPI",
        "REPOSITORY-CI-GITHUB-ACTIONS",
        "REPOSITORY-CONTAINER-DOCKERFILE",
        "REPOSITORY-IAC-TERRAFORM",
        "REQUIREMENT-AUTHENTICATION",
        "REQUIREMENT-FILE-UPLOAD",
        "REQUIREMENT-PAYMENT",
        "REQUIREMENT-PERSONAL-DATA",
    } <= evidence_ids
    assert {selection.implementation_id for selection in plan.control_selections} >= {
        "SEC-NEXT-ENV-001",
        "SEC-NEXT-COOKIE-001",
        "SEC-NEXT-CORS-001",
        "SEC-CICD-001",
        "SEC-DEP-001",
    }
    assert all(selection.catalog_digest == plan.catalog_digest for selection in plan.control_selections)
    assert all(selection.policy_digest == plan.policy_digest for selection in plan.control_selections)
    assert plan.plan_version == "0.4.0"
    selected_implementation_ids = {
        selection.implementation_id
        for selection in (*plan.control_selections, *plan.adapter_selections)
    }
    contract_by_implementation = {
        selection.implementation_id: selection for selection in plan.control_contract_selections
    }
    assert set(contract_by_implementation) == selected_implementation_ids
    assert contract_by_implementation["SEC-NEXT-COOKIE-001"].control_id == (
        "CONTROL-NEXTJS-SESSION-COOKIE-001"
    )
    assert contract_by_implementation["SEC-NEXT-COOKIE-001"].security_domain_ids == (
        "DOMAIN-SESSION-SECURITY-001",
    )
    assert all(selection.detection_scope for selection in plan.control_contract_selections)
    assert all(selection.exclusions for selection in plan.control_contract_selections)
    assert plan.security_domain_catalog_version == "0.29.0"
    assert plan.security_domain_catalog_digest
    assert not plan.adapter_selections
    assert not plan.skill_selections

    coverage = {item.domain: item.status.value for item in result.coverage_audit.assessments}
    coverage_by_id = {item.domain_id: item.status.value for item in result.coverage_audit.assessments}
    assert result.coverage_audit.security_domain_catalog_digest == plan.security_domain_catalog_digest
    assert coverage["Framework: Next.js"] == "COVERED"
    assert coverage["CI/CD"] == "COVERED"
    assert coverage["Container"] == "NOT_SELECTED"
    assert coverage["Infrastructure as code"] == "NOT_SELECTED"
    assert coverage["Declared requirement: Authentication"] == "DECLARED_REVIEW_REQUIRED"
    assert coverage["Declared requirement: File upload"] == "DECLARED_REVIEW_REQUIRED"
    assert coverage_by_id["DOMAIN-SESSION-SECURITY-001"] == "COVERED"
    assert coverage_by_id["DOMAIN-FILE-UPLOAD-001"] == "NOT_APPLICABLE"
    assert coverage_by_id["DOMAIN-PAYMENT-INTEGRATION-001"] == "UNAVAILABLE"
    assert coverage_by_id["DOMAIN-CONTAINER-SECURITY-001"] == "NOT_SELECTED"
    assert coverage_by_id["DOMAIN-IAC-SECURITY-001"] == "NOT_SELECTED"

    json_report = render_json(result)
    markdown_report = render_markdown(result)
    sarif_report = render_sarif(result)
    assert "security_analysis_plan" in json_report
    assert "control_contract_selections" in json_report
    assert "security_domain_catalog_digest" in json_report
    assert "Security domain catalog" in markdown_report
    assert "Selected control contracts" in markdown_report
    assert "CONTROL-NEXTJS-SESSION-COOKIE-001" in markdown_report
    assert "DOMAIN-SESSION-SECURITY-001" in markdown_report
    assert "beforeDeploySecurityAnalysisPlan" in sarif_report
    assert "control_contract_selections" in sarif_report
    assert "beforeDeploySecurityDomainCatalog" in sarif_report
    assert "JWT-backed login sessions" not in json_report
    assert "JWT-backed login sessions" not in markdown_report
    assert "JWT-backed login sessions" not in sarif_report


def test_vulnerable_nextjs_server_action_fixture_blocks_on_the_local_guard_contract():
    result = _scan("vulnerable_nextjs_server_action")

    assert result.decision.outcome.value == "BLOCK"
    assert {finding.rule_id for finding in result.findings} == {"SEC-NEXT-ACTION-001"}
    assert result.security_analysis_plan is not None
    contract = next(
        selection
        for selection in result.security_analysis_plan.control_contract_selections
        if selection.implementation_id == "SEC-NEXT-ACTION-001"
    )
    assert contract.control_id == "CONTROL-AUTHORIZATION-NEXT-SERVER-ACTION-001"
    assert contract.security_domain_ids == ("DOMAIN-AUTHORIZATION-001",)
    execution = next(item for item in result.executions if item.control_id == "SEC-NEXT-ACTION-001")
    assert execution.metadata["next_proxy_convention"] == "absent"


def test_nextjs_inline_action_policy_selects_only_the_new_inline_contract():
    profile = load_policy(NEXT_INLINE_ACTION_POLICY_PATH)
    controls = configured_controls(profile, _controls_for_profile(profile, NEXT_INLINE_ACTION_POLICY_PATH))
    result = ScanOrchestrator(controls).scan(
        FIXTURES / "vulnerable_nextjs_inline_server_action", NEXT_INLINE_ACTION_POLICY_PATH
    )

    assert result.decision.outcome.value == "BLOCK"
    assert {finding.rule_id for finding in result.findings} == {"SEC-NEXT-INLINE-ACTION-001"}
    assert result.security_analysis_plan is not None
    contract = next(
        selection
        for selection in result.security_analysis_plan.control_contract_selections
        if selection.implementation_id == "SEC-NEXT-INLINE-ACTION-001"
    )
    assert contract.control_id == "CONTROL-AUTHORIZATION-NEXT-INLINE-SERVER-ACTION-001"
    assert contract.security_domain_ids == ("DOMAIN-AUTHORIZATION-001",)
    reports = (render_json(result), render_markdown(result), render_sarif(result))
    assert all("accountId" not in report for report in reports)
    assert all("@/lib/db" not in report for report in reports)
    assert all("Delete account" not in report for report in reports)


def test_default_policy_does_not_implicitly_select_the_inline_nextjs_action_control():
    result = _scan("vulnerable_nextjs_inline_server_action")

    assert result.decision.outcome.value == "PASS"
    assert "SEC-NEXT-INLINE-ACTION-001" not in {execution.control_id for execution in result.executions}
    assert result.security_analysis_plan is not None
    assert "SEC-NEXT-INLINE-ACTION-001" not in {
        selection.implementation_id
        for selection in result.security_analysis_plan.control_contract_selections
    }


def test_default_policy_does_not_implicitly_select_the_go_vulnerability_snapshot():
    result = _scan("vulnerable_go_vulnerability_snapshot")

    assert result.decision.outcome.value == "PASS"
    assert "SEC-GO-VULN-001" not in {execution.control_id for execution in result.executions}
    assert result.security_analysis_plan is not None
    assert "SEC-GO-VULN-001" not in {
        selection.implementation_id
        for selection in result.security_analysis_plan.control_contract_selections
    }


def test_go_vulnerability_snapshot_policy_blocks_only_on_normalized_offline_evidence():
    profile = load_policy(GO_VULNERABILITY_POLICY_PATH)
    controls = configured_controls(profile, _controls_for_profile(profile, GO_VULNERABILITY_POLICY_PATH))
    result = ScanOrchestrator(controls).scan(
        FIXTURES / "vulnerable_go_vulnerability_snapshot", GO_VULNERABILITY_POLICY_PATH
    )

    assert result.decision.outcome.value == "BLOCK"
    assert {finding.rule_id for finding in result.findings} == {"SEC-GO-VULN-001"}
    assert result.security_analysis_plan is not None
    assert {
        selection.control_id for selection in result.security_analysis_plan.control_contract_selections
    } >= {"CONTROL-SUPPLY-GO-VULNERABILITY-SNAPSHOT-001"}
    execution = next(item for item in result.executions if item.control_id == "SEC-GO-VULN-001")
    assert execution.status.value == "COMPLETED"
    assert execution.metadata["evidence_source"] == "packaged_offline_go_vulnerability_snapshot"


def test_vulnerable_go_fixture_blocks_on_native_module_and_tls_controls():
    result = _scan("vulnerable_go_security")

    assert result.decision.outcome.value == "BLOCK"
    assert {finding.rule_id for finding in result.findings} >= {
        "SEC-GO-MODULE-001",
        "SEC-GO-TLS-001",
    }
    assert result.project_profile is not None
    assert result.project_profile.languages == ("Go",)


def test_secure_go_fixture_passes_with_partial_supply_coverage_and_gosec_not_selected():
    result = _scan("secure_go_security")

    assert result.decision.outcome.value == "PASS"
    assert not {finding.rule_id for finding in result.findings if finding.rule_id.startswith("SEC-GO-")}
    assert result.coverage_audit is not None
    coverage = {item.domain_id: item.status.value for item in result.coverage_audit.assessments}
    assert coverage["DOMAIN-SUPPLY-CHAIN-001"] == "PARTIAL"
    assert coverage["DOMAIN-TRANSPORT-SECURITY-001"] == "COVERED"
    assert coverage["DOMAIN-INJECTION-001"] == "NOT_SELECTED"
    assert coverage["DOMAIN-PATH-TRAVERSAL-001"] == "NOT_SELECTED"
    assert coverage["DOMAIN-SSRF-001"] == "NOT_SELECTED"


def test_go_tls_textual_false_positive_fixture_passes_without_tls_finding():
    result = _scan("go_tls_false_positive")

    assert result.decision.outcome.value == "PASS"
    assert "SEC-GO-TLS-001" not in {finding.rule_id for finding in result.findings}


def test_go_without_root_module_keeps_go_controls_explicitly_not_applicable():
    result = _scan("go_without_root_module")

    assert result.decision.outcome.value == "PASS"
    executions = {execution.control_id: execution for execution in result.executions}
    assert executions["SEC-GO-MODULE-001"].status.value == "NOT_APPLICABLE"
    assert executions["SEC-GO-TLS-001"].status.value == "NOT_APPLICABLE"
    assert result.coverage_audit is not None
    coverage = {item.domain_id: item.status.value for item in result.coverage_audit.assessments}
    assert coverage["DOMAIN-SUPPLY-CHAIN-001"] == "NOT_SELECTED"
    assert coverage["DOMAIN-TRANSPORT-SECURITY-001"] == "NOT_APPLICABLE"
