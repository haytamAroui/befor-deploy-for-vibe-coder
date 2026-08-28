"""Bounded Python data-integrity analysis for destructive SQL without WHERE."""
from __future__ import annotations

import ast
import re

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

_CONTROL_ID = "SEC-DATA-INTEGRITY-001"
_CONTROL_VERSION = "0.1.0"
_SQL_MUTATION_RE = re.compile(r"^\s*(UPDATE|DELETE)\b", re.IGNORECASE)
_WHERE_RE = re.compile(r"\bWHERE\b", re.IGNORECASE)


class PythonDataIntegrityControl:
    """Find direct literal destructive SQL calls without a WHERE clause."""

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_seen = False
        findings: list[Finding] = []
        for path in context.inventory.files:
            if path.suffix != ".py":
                continue
            python_seen = True
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not _is_direct_execute_call(node):
                    continue
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    continue
                sql = node.args[0].value
                if not isinstance(sql, str) or not _SQL_MUTATION_RE.match(sql) or _WHERE_RE.search(sql):
                    continue
                location = Location(path=relative, start_line=node.lineno)
                evidence = {"artifact": "python", "issue": "destructive_sql_without_where"}
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Destructive SQL mutation has no WHERE clause",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        message="Add an explicit WHERE clause or an independently reviewed safeguard.",
                        remediation="Constrain destructive SQL mutations before execution.",
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )
        status = ControlExecution(
            control_id=self.control_id,
            control_version=self.control_version,
            status=ExecutionStatus.COMPLETED if python_seen else ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at,
            completed_at=utc_now(),
            applicable=python_seen,
            message=None if python_seen else "No Python source was detected.",
        )
        return ControlResult(execution=status, findings=tuple(findings))


def _is_direct_execute_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"execute", "executemany"}
        and isinstance(node.func.value, ast.Name)
    )
