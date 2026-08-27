from pathlib import Path

from before_deploy.controls import native_controls
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy
from before_deploy.reports import render_json, render_markdown, render_sarif


REPOSITORY = Path(__file__).parents[2]
POLICY_PATH = REPOSITORY / "rules" / "default-policy.yaml"
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
    assert plan.security_domain_catalog_version == "0.2.0"
    assert plan.security_domain_catalog_digest
    assert not plan.adapter_selections
    assert not plan.skill_selections

    coverage = {item.domain: item.status.value for item in result.coverage_audit.assessments}
    coverage_by_id = {item.domain_id: item.status.value for item in result.coverage_audit.assessments}
    assert result.coverage_audit.security_domain_catalog_digest == plan.security_domain_catalog_digest
    assert coverage["Framework: Next.js"] == "COVERED"
    assert coverage["CI/CD"] == "COVERED"
    assert coverage["Container"] == "UNAVAILABLE"
    assert coverage["Infrastructure as code"] == "UNAVAILABLE"
    assert coverage["Declared requirement: Authentication"] == "DECLARED_REVIEW_REQUIRED"
    assert coverage["Declared requirement: File upload"] == "DECLARED_REVIEW_REQUIRED"
    assert coverage_by_id["DOMAIN-SESSION-SECURITY-001"] == "COVERED"
    assert coverage_by_id["DOMAIN-FILE-UPLOAD-001"] == "UNAVAILABLE"
    assert coverage_by_id["DOMAIN-PAYMENT-INTEGRATION-001"] == "UNAVAILABLE"
    assert coverage_by_id["DOMAIN-CONTAINER-SECURITY-001"] == "UNAVAILABLE"

    json_report = render_json(result)
    markdown_report = render_markdown(result)
    sarif_report = render_sarif(result)
    assert "security_analysis_plan" in json_report
    assert "security_domain_catalog_digest" in json_report
    assert "Security domain catalog" in markdown_report
    assert "DOMAIN-SESSION-SECURITY-001" in markdown_report
    assert "beforeDeploySecurityAnalysisPlan" in sarif_report
    assert "beforeDeploySecurityDomainCatalog" in sarif_report
    assert "JWT-backed login sessions" not in json_report
    assert "JWT-backed login sessions" not in markdown_report
    assert "JWT-backed login sessions" not in sarif_report


def test_vulnerable_go_fixture_blocks_on_native_module_and_tls_controls():
    result = _scan("vulnerable_go_security")

    assert result.decision.outcome.value == "BLOCK"
    assert {finding.rule_id for finding in result.findings} >= {
        "SEC-GO-MODULE-001",
        "SEC-GO-TLS-001",
    }
    assert result.project_profile is not None
    assert result.project_profile.languages == ("Go",)


def test_secure_go_fixture_passes_with_native_coverage_and_gosec_not_selected():
    result = _scan("secure_go_security")

    assert result.decision.outcome.value == "PASS"
    assert not {finding.rule_id for finding in result.findings if finding.rule_id.startswith("SEC-GO-")}
    assert result.coverage_audit is not None
    coverage = {item.domain_id: item.status.value for item in result.coverage_audit.assessments}
    assert coverage["DOMAIN-SUPPLY-CHAIN-001"] == "COVERED"
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
