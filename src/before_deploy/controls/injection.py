"""AST-based detection of selected Python raw SQL construction patterns."""

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


class SqlInjectionControl:
    """Detect f-string, percent, and format interpolation passed directly to execute calls."""

    control_id = "SEC-SAST-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = [path for path in context.inventory.files if path.suffix == ".py"]
        if not python_files:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No Python source files were in the bounded inventory.",
                )
            )

        findings: list[Finding] = []
        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not _is_execute_call(node) or not node.args:
                    continue
                construction = _unsafe_sql_construction(node.args[0])
                if construction is None:
                    continue
                location = Location(path=relative, start_line=node.lineno)
                evidence = {"construction": construction, "sink": _call_name(node.func)}
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Potential SQL injection through string interpolation",
                        message=(
                            "A SQL execute call receives a query built through string interpolation instead "
                            "of a parameterized statement."
                        ),
                        remediation=(
                            "Use the database driver's parameter binding or ORM query parameters; do not "
                            "interpolate user-controlled values into SQL text."
                        ),
                        severity=Severity.BLOCKER,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Parsed {len(python_files)} Python source files.",
            ),
            findings=tuple(findings),
        )


def _is_execute_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}


def _unsafe_sql_construction(node: ast.AST) -> str | None:
    if isinstance(node, ast.JoinedStr):
        return "f_string"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_string_literal(node.left):
        return "percent_format"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _is_string_literal(node.func.value)
    ):
        return "format_method"
    return None


def _is_string_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return "call"
