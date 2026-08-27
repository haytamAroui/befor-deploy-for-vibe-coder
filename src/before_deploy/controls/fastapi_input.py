"""Bounded FastAPI input-validation analysis for untyped direct body parameters."""
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

_CONTROL_ID = "SEC-API-INPUT-001"
_CONTROL_VERSION = "0.1.0"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ROUTE_METHODS = {"get", "post", "put", "patch", "delete"}
_UNTYPED_BODY_ANNOTATIONS = {"dict", "Any"}


class FastApiInputValidationControl:
    """Flag only direct bare ``dict``/``Any`` parameters on literal mutating routes."""

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        routes_seen = False
        findings: list[Finding] = []
        for path in context.inventory.files:
            if path.suffix != ".py":
                continue
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            if not _imports_fastapi(tree):
                continue
            for function in ast.walk(tree):
                if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for method, path_value in _literal_routes(function):
                    routes_seen = True
                    if method not in _MUTATING_METHODS:
                        continue
                    parameter = _untyped_body_parameter(function)
                    if parameter is None:
                        continue
                    location = Location(path=relative, start_line=parameter.lineno)
                    evidence = {"artifact": "python", "issue": "untyped_fastapi_body"}
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="Mutating FastAPI route accepts an untyped body parameter",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            message="Use an explicit validation model for this direct body parameter.",
                            remediation="Replace the bare body annotation with an approved validation model.",
                            location=location,
                            evidence=evidence,
                            fingerprint=fingerprint_for(self.control_id, location, evidence),
                        )
                    )
        if not routes_seen:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No supported literal FastAPI route decorators were detected.",
                )
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
            ),
            findings=tuple(findings),
        )


def _imports_fastapi(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import) and any(alias.name == "fastapi" for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module == "fastapi":
            return True
    return False


def _literal_routes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[tuple[str, str], ...]:
    routes: list[tuple[str, str]] = []
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr not in _ROUTE_METHODS or not decorator.args:
            continue
        path = decorator.args[0]
        if isinstance(path, ast.Constant) and isinstance(path.value, str) and path.value.startswith("/"):
            routes.append((decorator.func.attr.upper(), path.value))
    return tuple(routes)


def _untyped_body_parameter(function: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.arg | None:
    positional = (*function.args.posonlyargs, *function.args.args)
    for parameter in positional:
        if isinstance(parameter.annotation, ast.Name) and parameter.annotation.id in _UNTYPED_BODY_ANNOTATIONS:
            return parameter
    if function.args.kwonlyargs:
        for parameter in function.args.kwonlyargs:
            if isinstance(parameter.annotation, ast.Name) and parameter.annotation.id in _UNTYPED_BODY_ANNOTATIONS:
                return parameter
    return None
