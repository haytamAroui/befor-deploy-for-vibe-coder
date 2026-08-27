"""Bounded FastAPI upload analysis for direct filename filesystem sinks."""
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

_CONTROL_ID = "SEC-API-UPLOAD-001"
_CONTROL_VERSION = "0.1.0"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ROUTE_METHODS = {"post", "put", "patch", "delete"}


class FastApiUploadFilenameControl:
    """Flag only direct UploadFile.filename values passed to the built-in open sink."""

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        route_seen = False
        upload_route_seen = False
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
                routes = _literal_routes(function)
                if not routes:
                    continue
                route_seen = True
                upload_parameters = _upload_parameters(function)
                if not upload_parameters:
                    continue
                upload_route_seen = True
                for method, _path_value in routes:
                    if method not in _MUTATING_METHODS:
                        continue
                    for call in _direct_open_filename_sinks(function, upload_parameters):
                        location = Location(path=relative, start_line=call.lineno)
                        evidence = {"artifact": "python", "issue": "upload_filename_filesystem_sink"}
                        findings.append(
                            Finding(
                                rule_id=self.control_id,
                                rule_version=self.control_version,
                                title="FastAPI upload filename reaches a direct filesystem sink",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                message="Do not pass an uploaded filename directly to a filesystem sink.",
                                remediation="Sanitize the filename or use an approved storage abstraction before writing files.",
                                location=location,
                                evidence=evidence,
                                fingerprint=fingerprint_for(self.control_id, location, evidence),
                            )
                        )
        if not route_seen or not upload_route_seen:
            status = ExecutionStatus.NOT_APPLICABLE
            applicable = False
        else:
            status = ExecutionStatus.COMPLETED
            applicable = True
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=status,
                started_at=started_at,
                completed_at=utc_now(),
                applicable=applicable,
                message=(
                    "No supported FastAPI upload route was detected."
                    if not applicable
                    else None
                ),
            ),
            findings=tuple(findings),
        )


def _imports_fastapi(tree: ast.Module) -> bool:
    return any(
        (isinstance(node, ast.Import) and any(alias.name == "fastapi" for alias in node.names))
        or (isinstance(node, ast.ImportFrom) and node.module == "fastapi")
        for node in tree.body
    )


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


def _upload_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    parameters = (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)
    return frozenset(
        parameter.arg
        for parameter in parameters
        if isinstance(parameter.annotation, ast.Name) and parameter.annotation.id == "UploadFile"
    )


def _direct_open_filename_sinks(
    function: ast.FunctionDef | ast.AsyncFunctionDef, upload_parameters: frozenset[str]
) -> tuple[ast.Call, ...]:
    sinks: list[ast.Call] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "open":
            continue
        values = (*node.args, *(keyword.value for keyword in node.keywords))
        if any(
            isinstance(value, ast.Attribute)
            and value.attr == "filename"
            and isinstance(value.value, ast.Name)
            and value.value.id in upload_parameters
            for value in values
        ):
            sinks.append(node)
    return tuple(sinks)
