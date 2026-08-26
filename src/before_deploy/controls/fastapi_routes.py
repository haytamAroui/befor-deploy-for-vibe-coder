"""Bounded FastAPI route analysis for declared authentication dependencies."""

from __future__ import annotations

import ast
from dataclasses import dataclass

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

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "api_route"}
_DEPENDENCY_NAMES = {"Depends", "Security"}


@dataclass(frozen=True)
class Route:
    path: str
    method: str
    line: int
    authenticated: bool


class FastApiRouteAuthenticationControl:
    """Require a declared FastAPI dependency for mutating routes unless explicitly allowlisted."""

    control_id = "SEC-API-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = [path for path in context.inventory.files if path.suffix == ".py"]
        routes: list[tuple[str, Route]] = []
        fastapi_detected = False

        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            if _imports_fastapi(tree):
                fastapi_detected = True
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for route in _routes_for_function(node):
                    routes.append((relative, route))

        if not fastapi_detected and not routes:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No FastAPI imports or route decorators were detected.",
                )
            )

        findings: list[Finding] = []
        for relative, route in routes:
            allowlisted = (route.path, route.method) in context.public_fastapi_routes
            if route.method not in _MUTATING_METHODS or route.authenticated or allowlisted:
                continue
            location = Location(path=relative, start_line=route.line)
            evidence = {"route_path": route.path, "method": route.method}
            findings.append(
                Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title="Mutating FastAPI route lacks a declared authentication dependency",
                    message=(
                        f"The {route.method} route '{route.path}' does not declare a Depends or Security "
                        "dependency and is not included in the reviewed public-route allowlist."
                    ),
                    remediation=(
                        "Add an appropriate authentication and authorization dependency, or add a narrowly "
                        "scoped reviewed exception to public_fastapi_routes in the policy profile."
                    ),
                    severity=Severity.BLOCKER,
                    confidence=Confidence.MEDIUM,
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
                message=f"Evaluated {len(routes)} FastAPI route-method pairs.",
            ),
            findings=tuple(findings),
        )


def _imports_fastapi(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("fastapi"):
            return True
        if isinstance(node, ast.Import) and any(alias.name.startswith("fastapi") for alias in node.names):
            return True
    return False


def _routes_for_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[Route, ...]:
    authenticated = _function_has_dependency(node)
    routes: list[Route] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        decorator_name = decorator.func.attr
        if decorator_name not in _ROUTE_DECORATORS:
            continue
        path = _literal_path(decorator)
        methods = _route_methods(decorator_name, decorator)
        decorator_auth = _decorator_has_dependency(decorator)
        for method in methods:
            routes.append(
                Route(
                    path=path,
                    method=method,
                    line=decorator.lineno,
                    authenticated=authenticated or decorator_auth,
                )
            )
    return tuple(routes)


def _literal_path(decorator: ast.Call) -> str:
    if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
        raise ValueError("FastAPI route path must be a static string for this control")
    value = decorator.args[0].value
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("FastAPI route path must be a slash-prefixed static string")
    return value


def _route_methods(name: str, decorator: ast.Call) -> tuple[str, ...]:
    if name in {"get", "post", "put", "patch", "delete"}:
        return (name.upper(),)
    for keyword in decorator.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            methods: list[str] = []
            for item in keyword.value.elts:
                if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                    raise ValueError("FastAPI api_route methods must be static strings")
                methods.append(item.value.upper())
            return tuple(methods)
    raise ValueError("FastAPI api_route must declare static methods")


def _function_has_dependency(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    positional = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    defaults = [*node.args.defaults, *node.args.kw_defaults]
    for default in defaults:
        if isinstance(default, ast.Call) and _call_name(default.func) in _DEPENDENCY_NAMES:
            return True
    return any(_annotation_mentions_security(argument.annotation) for argument in positional)


def _decorator_has_dependency(decorator: ast.Call) -> bool:
    for keyword in decorator.keywords:
        if keyword.arg != "dependencies" or not isinstance(keyword.value, (ast.List, ast.Tuple)):
            continue
        if any(isinstance(item, ast.Call) and _call_name(item.func) in _DEPENDENCY_NAMES for item in keyword.value.elts):
            return True
    return False


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _annotation_mentions_security(annotation: ast.AST | None) -> bool:
    if annotation is None:
        return False
    return "Security" in ast.unparse(annotation) or "Depends" in ast.unparse(annotation)
