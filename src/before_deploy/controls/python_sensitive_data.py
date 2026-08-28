"""Bounded Python detection for direct sensitive values passed to logging calls."""
from __future__ import annotations

import ast

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.models import (
    Confidence,
    ControlExecution,
    ExecutionStatus,
    Finding,
    Location,
    Severity,
    fingerprint_for,
    utc_now,
)

_CONTROL_ID = "SEC-SENSITIVE-DATA-PYTHON-001"
_CONTROL_VERSION = "0.1.0"
_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
_SENSITIVE_PARTS = {
    "access_token",
    "authorization",
    "credit_card",
    "cvv",
    "password",
    "passwd",
    "secret",
    "session_token",
    "ssn",
    "token",
}


class PythonSensitiveDataLoggingControl:
    """Flag direct sensitive-name values passed to explicit logger calls."""

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
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not _is_logger_call(node):
                    continue
                applicable = True
                arguments = node.args[1:] if _is_log_call(node) else node.args
                for argument in arguments:
                    name = _sensitive_name(argument)
                    if name is None:
                        continue
                    location = Location(path=relative, start_line=argument.lineno)
                    evidence = {"artifact": "python", "issue": "sensitive_value_to_logger"}
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="Sensitive value passed directly to a logger",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            message="A directly named sensitive value is passed to an explicit logging call.",
                            remediation="Remove the sensitive value from logs or replace it with an approved redacted identifier.",
                            location=location,
                            evidence=evidence,
                            fingerprint=fingerprint_for(self.control_id, location, evidence),
                        )
                    )
        status = ExecutionStatus.COMPLETED if applicable else ExecutionStatus.NOT_APPLICABLE
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=status,
                started_at=started_at,
                completed_at=utc_now(),
                applicable=applicable,
                message=None if applicable else "No supported explicit Python logger calls were detected.",
            ),
            findings=tuple(findings),
        )


def _is_logger_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr in _LOG_METHODS and (
        isinstance(node.func.value, ast.Name)
        and (node.func.value.id == "logging" or node.func.value.id.lower().endswith("logger"))
    )


def _is_log_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr == "log"


def _sensitive_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        candidate = node.id.lower()
    elif isinstance(node, ast.Attribute):
        candidate = node.attr.lower()
    else:
        return None
    normalized = candidate.replace("-", "_")
    return normalized if normalized in _SENSITIVE_PARTS else None


__all__ = ["PythonSensitiveDataLoggingControl"]
