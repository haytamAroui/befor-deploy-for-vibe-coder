from pathlib import Path

from before_deploy.controls import native_controls
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy


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
