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
_MAX_DYNAMIC_ROUTE_REVIEW_LOCATIONS = 50


@dataclass(frozen=True)
class Route:
    path: str
    method: str
    line: int
    authenticated: bool


@dataclass(frozen=True)
class DynamicRouteReviewState:
    """A structural FastAPI route condition outside the static authentication contract."""

    line: int
    reason: str


class FastApiRouteAuthenticationControl:
    """Require declared dependencies on static mutating routes and report dynamic review states."""

    control_id = "SEC-API-001"
    control_version = "0.3.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = [path for path in context.inventory.files if path.suffix == ".py"]
        routes: list[tuple[str, Route]] = []
        dynamic_route_reviews: list[tuple[str, DynamicRouteReviewState]] = []
        fastapi_detected = False

        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            if _imports_fastapi(tree):
                fastapi_detected = True
            dynamic_router_prefixes = _dynamic_router_prefixes(tree)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                static_routes, review_states = _routes_for_function(node, dynamic_router_prefixes)
                routes.extend((relative, route) for route in static_routes)
                dynamic_route_reviews.extend((relative, state) for state in review_states)

        if not fastapi_detected and not routes and not dynamic_route_reviews:
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
                message=(
                    f"Evaluated {len(routes)} static FastAPI route-method pairs; "
                    f"recorded {len(dynamic_route_reviews)} dynamic route review states."
                ),
                metadata=_dynamic_route_review_metadata(dynamic_route_reviews),
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


def _routes_for_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    dynamic_router_prefixes: frozenset[str],
) -> tuple[tuple[Route, ...], tuple[DynamicRouteReviewState, ...]]:
    authenticated = _function_has_dependency(node)
    routes: list[Route] = []
    review_states: list[DynamicRouteReviewState] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        decorator_name = decorator.func.attr
        if decorator_name not in _ROUTE_DECORATORS:
            continue
        if _decorator_uses_dynamic_router_prefix(decorator, dynamic_router_prefixes):
            review_states.append(
                DynamicRouteReviewState(line=decorator.lineno, reason="DYNAMIC_ROUTER_PREFIX")
            )
            continue
        path = _literal_path_or_none(decorator)
        if path is None:
            review_states.append(DynamicRouteReviewState(line=decorator.lineno, reason="DYNAMIC_PATH"))
            continue
        methods = _route_methods_or_none(decorator_name, decorator)
        if methods is None:
            review_states.append(DynamicRouteReviewState(line=decorator.lineno, reason="DYNAMIC_METHODS"))
            continue
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
    return tuple(routes), tuple(review_states)


def _dynamic_router_prefixes(tree: ast.Module) -> frozenset[str]:
    """Recognize only direct top-level APIRouter assignments with non-literal prefixes."""
    dynamic_names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            target_names = [target.id for target in statement.targets if isinstance(target, ast.Name)]
            if len(statement.targets) == 1 and len(target_names) == 1 and _has_dynamic_router_prefix(
                statement.value
            ):
                dynamic_names.add(target_names[0])
            else:
                dynamic_names.difference_update(target_names)
        elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)) and isinstance(statement.target, ast.Name):
            dynamic_names.discard(statement.target.id)
    return frozenset(dynamic_names)


def _has_dynamic_router_prefix(value: ast.AST) -> bool:
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "APIRouter"
    ):
        return False
    for keyword in value.keywords:
        if keyword.arg == "prefix":
            return not _is_literal_route_path(keyword.value)
    return False


def _decorator_uses_dynamic_router_prefix(
    decorator: ast.Call, dynamic_router_prefixes: frozenset[str]
) -> bool:
    return isinstance(decorator.func.value, ast.Name) and (
        decorator.func.value.id in dynamic_router_prefixes
    )


def _literal_path_or_none(decorator: ast.Call) -> str | None:
    if not decorator.args:
        return None
    value = decorator.args[0]
    return value.value if _is_literal_route_path(value) else None


def _is_literal_route_path(value: ast.AST) -> bool:
    return isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.startswith("/")


def _route_methods_or_none(name: str, decorator: ast.Call) -> tuple[str, ...] | None:
    if name in {"get", "post", "put", "patch", "delete"}:
        return (name.upper(),)
    for keyword in decorator.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            methods: list[str] = []
            for item in keyword.value.elts:
                if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                    return None
                methods.append(item.value.upper())
            return tuple(methods)
    return None


def _dynamic_route_review_metadata(
    reviews: list[tuple[str, DynamicRouteReviewState]],
) -> dict[str, str]:
    ordered = sorted({(path, state.line, state.reason) for path, state in reviews})
    locations = tuple(
        f"{path}:{line}:{reason}" for path, line, reason in ordered[:_MAX_DYNAMIC_ROUTE_REVIEW_LOCATIONS]
    )
    metadata = {
        "dynamic_route_review_status": "REVIEW_REQUIRED" if ordered else "NOT_REQUIRED",
        "dynamic_route_review_count": str(len(ordered)),
    }
    if locations:
        metadata["dynamic_route_review_locations"] = ",".join(locations)
    if len(ordered) > len(locations):
        metadata["dynamic_route_review_locations_truncated"] = "true"
    return metadata


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
