from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.go import GoModuleIntegrityControl, GoTLSVerificationControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


FIXTURES = Path(__file__).parents[2] / "fixtures"


def _context(name: str) -> ControlContext:
    repository = FIXTURES / name
    return ControlContext(repository_root=repository, inventory=collect_inventory(repository))


def test_go_module_integrity_requires_go_sum_only_for_declared_dependencies():
    secure = GoModuleIntegrityControl().run(_context("secure_go_security"))
    vulnerable = GoModuleIntegrityControl().run(_context("vulnerable_go_security"))
    no_dependencies = GoModuleIntegrityControl().run(_context("go_service"))

    assert secure.execution.status == ExecutionStatus.COMPLETED
    assert not secure.findings
    assert vulnerable.execution.status == ExecutionStatus.COMPLETED
    assert [finding.evidence["issue"] for finding in vulnerable.findings] == ["go_sum_missing"]
    assert no_dependencies.execution.status == ExecutionStatus.COMPLETED
    assert not no_dependencies.findings


def test_go_tls_control_detects_only_direct_explicit_insecure_literals():
    secure = GoTLSVerificationControl().run(_context("secure_go_security"))
    vulnerable = GoTLSVerificationControl().run(_context("vulnerable_go_security"))
    false_positive = GoTLSVerificationControl().run(_context("go_tls_false_positive"))

    assert not secure.findings
    assert len(vulnerable.findings) == 1
    assert vulnerable.findings[0].location is not None
    assert vulnerable.findings[0].location.path == "main.go"
    assert vulnerable.findings[0].location.start_line == 6
    assert vulnerable.findings[0].evidence == {"issue": "tls_insecure_skip_verify_literal"}
    assert not false_positive.findings
