"""Bounded Python detection for directly swallowed broad exceptions."""
from __future__ import annotations

import ast

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.models import Confidence, ControlExecution, ExecutionStatus, Finding, Location, Severity, fingerprint_for, utc_now

_CONTROL_ID = "SEC-ERROR-HANDLING-PYTHON-001"
_CONTROL_VERSION = "0.1.0"


class PythonErrorHandlingControl:
    """Flag bare or Exception handlers whose complete body is only ``pass``."""

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        findings: list[Finding] = []
        applicable = False
        for path in context.inventory.files:
            if path.suffix != ".py":
                continue
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
                if not _is_broad_handler(handler):
                    continue
                applicable = True
                if not _is_direct_pass(handler):
                    continue
                location = Location(path=relative, start_line=handler.lineno)
                evidence = {"artifact": "python", "issue": "broad_exception_suppressed"}
                findings.append(Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title="Broad exception is suppressed without handling",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    message="A broad exception handler contains only a direct pass statement.",
                    remediation="Handle the failure explicitly, record safe diagnostic context, or re-raise the exception.",
                    location=location,
                    evidence=evidence,
                    fingerprint=fingerprint_for(self.control_id, location, evidence),
                ))
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED if applicable else ExecutionStatus.NOT_APPLICABLE,
                started_at=started_at,
                completed_at=utc_now(),
                applicable=applicable,
                message=None if applicable else "No supported broad exception suppression was detected.",
            ),
            findings=tuple(findings),
        )


def _is_broad_handler(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    return isinstance(handler.type, ast.Name) and handler.type.id == "Exception"


def _is_direct_pass(handler: ast.ExceptHandler) -> bool:
    return len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)


__all__ = ["PythonErrorHandlingControl"]
