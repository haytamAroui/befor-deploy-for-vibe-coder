from dataclasses import dataclass
from pathlib import Path

from before_deploy.inventory import collect_inventory
from before_deploy.models import ProjectProfile
from before_deploy.project_profile import detect_project_profile, select_compatible_controls


FIXTURES = Path(__file__).parents[2] / "fixtures"


@dataclass(frozen=True)
class _Control:
    control_id: str
    control_version: str = "test"


def test_detects_go_and_reports_language_specific_coverage_gap():
    profile = detect_project_profile(collect_inventory(FIXTURES / "go_service"))

    assert profile.languages == ("Go",)
    assert profile.frameworks == ()
    assert profile.signals["manifest:go.mod"] == "1"
    assert profile.coverage_gaps == (
        "Go coverage is limited to root-module checksum presence, direct tls.Config InsecureSkipVerify literals, "
        "one exact offline dependency-vulnerability snapshot, and an opt-in isolated Gosec adapter; deep "
        "framework, dataflow, live-database, and runtime analysis are not installed.",
    )


def test_detects_nextjs_typescript_and_visible_coverage_gap():
    profile = detect_project_profile(collect_inventory(FIXTURES / "nextjs_service"))

    assert profile.languages == ("JavaScript", "TypeScript")
    assert profile.frameworks == ("Next.js",)
    assert profile.signals["framework:Next.js"] == "1"
    assert profile.coverage_gaps == (
        "Next.js coverage is limited to direct public-env, explicit session-cookie, static CORS, and one "
        "module-level Server Action local-guard-marker check; middleware/proxy coverage, inline actions, "
        "semantic authorization, and client/server data-boundary analysis are not installed.",
    )


def test_detects_multiple_unsupported_languages_with_distinct_gaps():
    profile = detect_project_profile(collect_inventory(FIXTURES / "mixed_service"))

    assert profile.languages == ("Java", "Rust")
    assert profile.coverage_gaps == (
        "No language-specific controls are currently installed for Java.",
        "No language-specific controls are currently installed for Rust.",
    )


def test_python_only_control_is_explicitly_not_applicable_to_go_profile():
    profile = ProjectProfile(
        languages=("Go",),
        frameworks=(),
        package_managers=(),
        signals={"extension:.go": "1"},
        coverage_gaps=("No language-specific controls are currently installed for Go.",),
    )

    runnable, executions = select_compatible_controls(
        (_Control("SEC-SAST-001"), _Control("SEC-SECRET-001")), profile
    )

    assert tuple(control.control_id for control in runnable) == ("SEC-SECRET-001",)
    assert len(executions) == 1
    assert executions[0].control_id == "SEC-SAST-001"
    assert executions[0].status.value == "NOT_APPLICABLE"
    assert executions[0].applicable is False
