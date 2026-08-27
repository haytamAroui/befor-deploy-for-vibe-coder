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
    assert {selection.capability_id for selection in plan.control_selections} >= {
        "SEC-NEXT-ENV-001",
        "SEC-NEXT-COOKIE-001",
        "SEC-NEXT-CORS-001",
        "SEC-CICD-001",
        "SEC-DEP-001",
    }
    assert not plan.adapter_selections
    assert not plan.skill_selections

    coverage = {item.domain: item.status.value for item in result.coverage_audit.assessments}
    assert coverage["Framework: Next.js"] == "COVERED"
    assert coverage["CI/CD"] == "COVERED"
    assert coverage["Container"] == "UNAVAILABLE"
    assert coverage["Infrastructure as code"] == "UNAVAILABLE"
    assert coverage["Declared requirement: Authentication"] == "DECLARED_REVIEW_REQUIRED"
    assert coverage["Declared requirement: File upload"] == "DECLARED_REVIEW_REQUIRED"

    json_report = render_json(result)
    markdown_report = render_markdown(result)
    sarif_report = render_sarif(result)
    assert "security_analysis_plan" in json_report
    assert "Coverage audit" in markdown_report
    assert "beforeDeploySecurityAnalysisPlan" in sarif_report
    assert "JWT-backed login sessions" not in json_report
    assert "JWT-backed login sessions" not in markdown_report
    assert "JWT-backed login sessions" not in sarif_report
