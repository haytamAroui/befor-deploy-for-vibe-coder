"""Bounded FastAPI authorization-declaration analysis."""
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

_CONTROL_ID = "SEC-API-AUTHZ-001"
_CONTROL_VERSION = "0.1.0"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ROUTE_METHODS = {"post", "put", "patch", "delete"}
_FASTAPI_ROUTE_OBJECT_NAMES = {"app", "api", "router"}
_AUTHORIZATION_MARKERS = (
    "require_",
    "authorize_",
    "check_permission",
    "enforce_permission",
    "require_role",
    "require_scope",
)
_AUTHENTICATION_MARKERS = (
    "get_current_user",
    "get_current_subject",
    "authenticate",
    "current_user",
    "current_subject",
    "get_session",
    "get_identity",
)


class FastApiAuthorizationDeclarationControl:
    """Require a narrow lexical authorization marker beyond authentication."""

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        route_seen = False
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
                if not _has_mutating_literal_route(function):
                    continue
                route_seen = True
                dependency_names = _direct_dependency_names(function)
                if not dependency_names:
                    continue
                has_authentication = any(_looks_like_authentication(name) for name in dependency_names)
                has_authorization = any(_looks_like_authorization(name) for name in dependency_names)
                if not has_authentication or has_authorization:
                    continue
                location = Location(path=relative, start_line=function.lineno)
                evidence = {"artifact": "python", "issue": "authentication_without_authorization_marker"}
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="FastAPI route has authentication without an authorization marker",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        message="Add an explicit authorization dependency to this mutating route.",
                        remediation="Use a reviewed role, scope, permission, or ownership dependency.",
                        location=location,
                        evidence=evidence,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                    )
                )
        status = ExecutionStatus.COMPLETED if route_seen else ExecutionStatus.NOT_APPLICABLE
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=status,
                started_at=started_at,
                completed_at=utc_now(),
                applicable=route_seen,
                message=None if route_seen else "No supported mutating FastAPI route was detected.",
            ),
            findings=tuple(findings),
        )


def _imports_fastapi(tree: ast.Module) -> bool:
    return any(
        (isinstance(node, ast.Import) and any(alias.name == "fastapi" for alias in node.names))
        or (isinstance(node, ast.ImportFrom) and node.module == "fastapi")
        for node in tree.body
    )


def _has_mutating_literal_route(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id in _FASTAPI_ROUTE_OBJECT_NAMES
        and decorator.func.attr in _ROUTE_METHODS
        and decorator.args
        and isinstance(decorator.args[0], ast.Constant)
        and isinstance(decorator.args[0].value, str)
        and decorator.args[0].value.startswith("/")
        and decorator.func.attr.upper() in _MUTATING_METHODS
        for decorator in function.decorator_list
    )


def _direct_dependency_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    positional = [*function.args.posonlyargs, *function.args.args]
    positional_defaults = [
        *([None] * (len(positional) - len(function.args.defaults))),
        *function.args.defaults,
    ]
    parameters = [
        *zip(positional, positional_defaults, strict=True),
        *zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True),
    ]
    names: list[str] = []
    for _parameter, default in parameters:
        if not isinstance(default, ast.Call) or not isinstance(default.func, ast.Name):
            continue
        if default.func.id not in {"Depends", "Security"} or not default.args:
            continue
        dependency = default.args[0]
        if isinstance(dependency, ast.Name):
            names.append(dependency.id)
    return tuple(names)


def _looks_like_authentication(name: str) -> bool:
    normalized = name.lower()
    return any(marker in normalized for marker in _AUTHENTICATION_MARKERS)


def _looks_like_authorization(name: str) -> bool:
    normalized = name.lower()
    return any(normalized.startswith(marker) for marker in _AUTHORIZATION_MARKERS)
