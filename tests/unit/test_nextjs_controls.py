from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.nextjs import (
    NextPublicEnvironmentControl,
    NextServerActionLocalGuardControl,
    NextSessionCookieControl,
    NextStaticCorsControl,
)
from before_deploy.inventory import collect_inventory
from before_deploy.project_profile import detect_project_profile


FIXTURES = Path(__file__).parents[2] / "fixtures"


def _context(name: str) -> ControlContext:
    inventory = collect_inventory(FIXTURES / name)
    return ControlContext(
        repository_root=inventory.root,
        inventory=inventory,
        project_profile=detect_project_profile(inventory),
    )


def test_nextjs_controls_find_only_high_confidence_vulnerable_patterns():
    context = _context("vulnerable_nextjs_security")

    environment = NextPublicEnvironmentControl().run(context)
    cookies = NextSessionCookieControl().run(context)
    cors = NextStaticCorsControl().run(context)

    assert environment.execution.status.value == "COMPLETED"
    assert [finding.evidence["variable"] for finding in environment.findings] == [
        "NEXT_PUBLIC_SESSION_SECRET"
    ]
    assert len(cookies.findings) == 1
    assert cookies.findings[0].evidence["cookie"] == "session-token"
    assert "httpOnly" in cookies.findings[0].evidence["unsafe_options"]
    assert len(cors.findings) == 1
    assert cors.findings[0].location.path == "next.config.js"


def test_nextjs_controls_accept_explicitly_secure_static_patterns():
    context = _context("secure_nextjs_security")

    results = [
        NextPublicEnvironmentControl().run(context),
        NextSessionCookieControl().run(context),
        NextStaticCorsControl().run(context),
    ]

    assert all(result.execution.status.value == "COMPLETED" for result in results)
    assert all(not result.findings for result in results)


def test_nextjs_server_action_control_reports_only_the_bounded_unguarded_mutation_pattern():
    vulnerable = NextServerActionLocalGuardControl().run(_context("vulnerable_nextjs_server_action"))
    locally_guarded = NextServerActionLocalGuardControl().run(_context("secure_nextjs_server_action"))
    proxy_only = NextServerActionLocalGuardControl().run(_context("nextjs_server_action_proxy_only"))
    ambiguous = NextServerActionLocalGuardControl().run(_context("nextjs_server_action_false_positive"))

    assert vulnerable.execution.status.value == "COMPLETED"
    assert [finding.evidence for finding in vulnerable.findings] == [
        {
            "action": "deleteAccount",
            "mutation_operation": "delete",
            "pattern": "module_use_server_exported_async_direct_mutation_no_local_guard_marker",
        }
    ]
    assert "accountId" not in vulnerable.findings[0].message
    assert "@/lib/db" not in vulnerable.findings[0].message
    assert locally_guarded.execution.metadata["next_proxy_convention"] == "middleware"
    assert not locally_guarded.findings
    assert proxy_only.execution.metadata["next_proxy_convention"] == "proxy"
    assert len(proxy_only.findings) == 1
    assert not ambiguous.findings


def test_nextjs_controls_are_not_applicable_to_non_next_repository():
    context = _context("go_service")

    results = [
        NextPublicEnvironmentControl().run(context),
        NextSessionCookieControl().run(context),
        NextStaticCorsControl().run(context),
        NextServerActionLocalGuardControl().run(context),
    ]

    assert all(result.execution.status.value == "NOT_APPLICABLE" for result in results)
    assert all(result.execution.applicable is False for result in results)
