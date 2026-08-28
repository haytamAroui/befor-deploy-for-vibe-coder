"""Bounded Python detection for direct print-based application output."""
from __future__ import annotations
import ast
from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.models import Confidence, ControlExecution, ExecutionStatus, Finding, Location, Severity, fingerprint_for, utc_now
_CONTROL_ID = "SEC-OBSERVABILITY-PYTHON-001"
_CONTROL_VERSION = "0.1.0"
class PythonObservabilityControl:
    """Flag direct print calls; structured logging and indirect output are excluded."""
    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION
    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        findings: list[Finding] = []
        applicable = any(path.suffix == ".py" for path in context.inventory.files)
        for path in context.inventory.files:
            if path.suffix != ".py":
                continue
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "print":
                    continue
                applicable = True
                location = Location(path=relative, start_line=node.lineno)
                evidence = {"artifact": "python", "issue": "direct_print_output"}
                findings.append(Finding(rule_id=self.control_id, rule_version=self.control_version,
                    title="Direct print output is used instead of structured observability",
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    message="A direct print call was detected in Python source.",
                    remediation="Use the approved structured logging or telemetry interface.",
                    location=location, evidence=evidence,
                    fingerprint=fingerprint_for(self.control_id, location, evidence)))
        return ControlResult(execution=ControlExecution(control_id=self.control_id, control_version=self.control_version,
            status=ExecutionStatus.COMPLETED if applicable else ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at, completed_at=utc_now(), applicable=applicable,
            message=None if applicable else "No direct print calls were detected."), findings=tuple(findings))
__all__ = ["PythonObservabilityControl"]
